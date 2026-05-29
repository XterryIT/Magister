import os
import sys
import redis
import json
import time

from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langgraph.graph import StateGraph, START, END
from typing_extensions import TypedDict, Annotated
from langgraph.graph.message import add_messages
from langchain_ollama import ChatOllama
from langgraph.prebuilt import ToolNode, tools_condition
from langchain_core.tools import tool
from neo4j import GraphDatabase
from stix2 import Bundle

# --- Костыль для импортов ---
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from data_pipeline.STIX_conversion import convert_wazuh_to_stix

# ==========================================
# ГЛОБАЛЬНЫЕ НАСТРОЙКИ
# ==========================================
ALERTS_QUEUE = 'wazuh_raw_alerts'
TIME_WINDOW_SEC = 300  
HISTORY_WINDOW_SEC = 900 
ALERT_THRESHOLD = 4    

r_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

class IcedentAgentState(TypedDict):
    incedent: list
    messages: Annotated[list, add_messages]
    report: str
    escalate: bool     
    target_ip: str     

# Используем одну модель для всех ролей (в проде можно разделить L1 на 4b, а L3 на 9b)
llm = ChatOllama(
    model="qwen3.5:9b", 
    validate_model_on_init=True,
    temperature=0,
    num_ctx=8192 
)

# ==========================================
# ИНСТРУМЕНТ NEO4J (ПРОСТРАНСТВЕННЫЙ КОНТЕКСТ)
# ==========================================
@tool
def check_network_topology(ip_address: str) -> str:
    """
    Returns network topology information for a given IP address.
    Always use this tool to determine the blast radius and asset criticality.
    """
    URI = "bolt://localhost:7687"
    AUTH = ("neo4j", "password")
    try:
        with GraphDatabase.driver(URI, auth=AUTH) as driver:
            with driver.session() as session:
                query = """
                MATCH (s:Server {ip: $ip})
                OPTIONAL MATCH (srv:Service)-[:RUNS_ON]->(s)
                OPTIONAL MATCH (s)-[:BELONGS_TO]->(z:Zone)
                RETURN s.name AS Server, z.name AS Zone, collect(srv.name) AS Services
                """
                result = session.run(query, ip=ip_address)
                data = result.single()
                
                if data and data["Server"]:
                    return f"Server: {data['Server']}, Zone: {data['Zone']}, Services running: {', '.join(data['Services'])}"
                else:
                    return f"No topology data found for IP: {ip_address}."
    except Exception as e:
        return f"Neo4j Error: {str(e)}"

tools = [check_network_topology]
llm_with_tools = llm.bind_tools(tools)

# ==========================================
# ЭТАП 1: ИЗВЛЕЧЕНИЕ, BATCHING И ТРИГГЕРЫ
# ==========================================
def check_trigger(ip: str, level: int) -> bool:
    if not ip or ip == "UNKNOWN_IP":
        return False
    if level >= 10:
        print(f"[TRIGGER] CRITICAL: Alert level {level} for IP {ip}!")
        return True

    redis_key = f"alert_history:{ip}"
    current_time = time.time()
    r_client.zadd(redis_key, {str(current_time): current_time})
    r_client.zremrangebyscore(redis_key, 0, current_time - TIME_WINDOW_SEC)
    alert_count = r_client.zcard(redis_key)
    
    if alert_count >= ALERT_THRESHOLD:
        print(f"[TRIGGER] ESCALATION: Accumulated {alert_count}/{ALERT_THRESHOLD} alerts for IP {ip}!")
        r_client.delete(redis_key) 
        return True
    return False

def extrtacting(state: IcedentAgentState):
    try:
        r_client.ping()
    except redis.exceptions.ConnectionError:
        print("[ERROR] Redis connection failed!")
        return {"incedent": [], "messages": [], "escalate": False, "target_ip": ""}

    print("\n[SYSTEM] Waiting for alerts...")
    
    # 1. Ждем первый лог (Блокирующий вызов, система "спит" и не тратит CPU)
    queue_name, first_log_string = r_client.brpop(ALERTS_QUEUE)
    raw_logs = [first_log_string]
    
    # 2. BATCHING: Мгновенно выгребаем всю скопившуюся очередь (не блокирует)
    while True:
        extra_log = r_client.lpop(ALERTS_QUEUE)
        if extra_log:
            raw_logs.append(extra_log)
        else:
            break
            
    print(f"[EXTRACT] Pulled a batch of {len(raw_logs)} alerts from queue.")

    unique_alerts = []
    needs_escalation = False
    escalated_ip = "UNKNOWN_IP"

    # 3. Дедупликация и архивация для всего пакета
    for log_str in raw_logs:
        sample_log = json.loads(log_str)
        log_data = json.loads(sample_log) if isinstance(sample_log, str) else sample_log

        raw_id = log_data.get("rule", {}).get("id", "UNKNOWN_RULE")
        level = int(log_data.get("rule", {}).get("level", 0))
        raw_ip = log_data.get("agent", {}).get("ip", "UNKNOWN_IP")
        
        # Сохраняем в Машину времени для формирования 15-минутного контекста
        if raw_ip != "UNKNOWN_IP":
            history_key = f"logs_archive:{raw_ip}"
            current_time = time.time()
            r_client.zadd(history_key, {json.dumps(log_data): current_time})
            r_client.zremrangebyscore(history_key, 0, current_time - HISTORY_WINDOW_SEC)

        # Жесткая дедупликация: ex=1000 спасет от зацикливания LLM на одном мусоре
        dedup_key = f"dedup:{raw_id}:{raw_ip}"
        is_new_alert = r_client.set(name=dedup_key, value="1", ex=1000, nx=True)

        if is_new_alert:
            unique_alerts.append(log_data)
            # Если хотя бы один лог из пачки требует эскалации, поднимаем флаг
            if check_trigger(raw_ip, level):
                needs_escalation = True
                escalated_ip = raw_ip

    if not unique_alerts:
        print("[EXTRACT] All alerts in batch were duplicates. Dropping.")
        return {"incedent": [], "messages": [], "escalate": False, "target_ip": ""}

    print(f"[EXTRACT] Filtered down to {len(unique_alerts)} UNIQUE alerts.")

    # 4. Формируем запрос для быстрого L1 (передаем всю пачку уникальных логов)
    batch_prompt = "Analyze this batch of alerts and provide a single summary:\n\n"
    for idx, alert in enumerate(unique_alerts):
        desc = alert.get("rule", {}).get("description", "No description")
        level = alert.get("rule", {}).get("level", 0)
        full_log = alert.get("full_log", str(alert.get("data", "")))
        batch_prompt += f"--- Alert {idx+1} ---\nRule: {desc} (Level: {level})\nRaw: {full_log}\n\n"
        
    return {
        "incedent": [], 
        "messages": [HumanMessage(content=batch_prompt)],
        "escalate": needs_escalation,
        "target_ip": escalated_ip
    }

# ==========================================
# ЭТАП 2: L1 (БЫСТРЫЙ ФИЛЬТР)
# ==========================================
def analising(state: IcedentAgentState):
    # Если сработал триггер эскалации, L1 пропускает шаг (экономия Compute ROI)
    if not state.get("messages") or state.get("escalate"):
        return {"report": ""}

    print("[L1] Performing quick noise filtration (Compute ROI check)...")
    base_prompt = (
        "You are an L1 SOC AI Analyst. Your task is instant triage of a batch of alerts.\n"
        "Respond in telegraphic style. DO NOT output thinking process. Output ONLY the final report.\n\n"
        "Format:\n"
        "Verdict: [True Positive / False Positive]\n"
        "Reason: [1 short sentence based on logs]\n"
        "Action: [Short recommendation]"
    )

    sys_message = SystemMessage(content=base_prompt)
    start_time = time.time()
    response = llm.invoke([sys_message] + state["messages"])
    
    print(f"[L1] Report generated in {(time.time()-start_time):.2f} sec.")
    return {"messages": [response], "report": response.content}

# ==========================================
# ЭТАП 3: АГРЕГАТОР (СБОР ВРЕМЕННОГО КОНТЕКСТА)
# ==========================================
def summarize_stix_bundle(bundle_objects):
    summary_lines = []
    for obj in bundle_objects:
        obj_dict = dict(obj)
        obj_type = obj_dict.get("type", "unknown")
        
        if obj_type == "observed-data":
            rule_desc = obj_dict.get("x_wazuh_rule_desc", "Unknown Rule")
            level = obj_dict.get("x_wazuh_rule_level", 0)
            summary_lines.append(f"[EVENT] Lvl: {level} | Desc: {rule_desc}")
        elif obj_type == "indicator":
            name = obj_dict.get("name", "Unknown Indicator")
            summary_lines.append(f"[INDICATOR] {name}")
        elif obj_type == "relationship":
            rel_type = obj_dict.get("relationship_type", "")
            source = obj_dict.get("source_ref", "").split("--")[0] 
            target = obj_dict.get("target_ref", "").split("--")[0]
            summary_lines.append(f"[RELATIONSHIP] {source} -> {rel_type} -> {target}")

    return "\n".join(summary_lines) if summary_lines else "No STIX objects."

def context_aggregator(state: IcedentAgentState):
    print("\n[L2-AGGREGATOR] Building 15-minute historical context...")
    target_ip = state.get("target_ip")
    
    history_key = f"logs_archive:{target_ip}"
    raw_logs = r_client.zrange(history_key, 0, -1)
    
    master_objects = []
    for raw_log_str in raw_logs:
        try:
            log_dict = json.loads(raw_log_str)
            bundle = convert_wazuh_to_stix(log_dict)
            master_objects.extend(bundle.objects)
        except Exception:
            continue
            
    seen_ids = set()
    unique_objects = []
    for obj in master_objects:
        obj_id = obj.get("id")
        if obj_id not in seen_ids:
            seen_ids.add(obj_id)
            unique_objects.append(obj)
    
    compressed_stix = summarize_stix_bundle(unique_objects)
    print(f"[L2-AGGREGATOR] Compressed STIX bundle created ({len(compressed_stix)} chars).")
    
    escalation_prompt = f"MASTER STIX BUNDLE FOR INVESTIGATION:\n{compressed_stix}"
    return {"messages": [HumanMessage(content=escalation_prompt)]}

# ==========================================
# ЭТАП 4: АГЕНТЫ (ДЕТЕКТИВЫ)
# ==========================================
def hunter_agent(state: IcedentAgentState):
    print("[L2-HUNTER] Prosecuting the incident...")
    hunter_prompt = (
        "You are an L2 SOC Threat Hunter. Prove this STIX bundle represents a real attack.\n"
        "Output ONLY the report without thinking steps.\n"
        "Format:\n"
        "Hunter Report:\n"
        "* Attack Vector: [1 sentence]\n"
        "* Evidence: [2 facts]"
    )
    sys_message = SystemMessage(content=hunter_prompt)
    response = llm.invoke([sys_message, state["messages"][-1]])
    return {"messages": [response]}

def skeptic_agent(state: IcedentAgentState):
    print("[L2-SKEPTIC] Defending the incident (False Positive check)...")
    skeptic_prompt = (
        "You are an L2 SOC Validation Analyst. Prove this STIX bundle is benign (False Positive).\n"
        "Output ONLY the report without thinking steps.\n"
        "Format:\n"
        "Skeptic Report:\n"
        "* Benign Explanation: [1 sentence]\n"
        "* Mitigating Factors: [2 facts]"
    )
    sys_message = SystemMessage(content=skeptic_prompt)
    stix_message = next(msg for msg in reversed(state["messages"]) if isinstance(msg, HumanMessage))
    response = llm.invoke([sys_message, stix_message])
    return {"messages": [response]}

# ==========================================
# ЭТАП 5: СУДЬЯ (GRAPHRAG)
# ==========================================
def judge_agent(state: IcedentAgentState):
    print("\n[L3-JUDGE] Analyzing evidence and fetching spatial context (GraphRAG)...")
    target_ip = state.get("target_ip")
    
    tool_responses = [msg.content for msg in state["messages"] if isinstance(msg, ToolMessage)]
    if tool_responses:
        print(f"[NEO4J] Context retrieved: {tool_responses[-1]}")
    
    judge_prompt = (
        "You are the Lead Incident Responder.\n"
        f"1. You MUST call the `check_network_topology` tool for IP: {target_ip}.\n"
        "2. Review the Hunter and Skeptic reports.\n"
        "3. Write the FINAL report in RUSSIAN language.\n\n"
        "Format:\n"
        "Вердикт: [True Positive / False Positive]\n"
        "Контекст Инфраструктуры: [1 предложение на основе Neo4j]\n"
        "Обоснование: [Чьи аргументы победили?]\n"
        "Действие: [Рекомендация]"
    )
    
    sys_message = SystemMessage(content=judge_prompt)
    start_time = time.time()
    response = llm_with_tools.invoke([sys_message] + state["messages"])
    
    if hasattr(response, 'tool_calls') and len(response.tool_calls) > 0:
        print(f"[TOOL] Judge requested topology for {response.tool_calls[0]['args']}")
    else:
        print(f"[L3-JUDGE] Verdict reached in {(time.time()-start_time):.2f} sec.")
        
    return {"messages": [response]}

# ==========================================
# СБОРКА LANGGRAPH
# ==========================================
def route_after_l1(state: IcedentAgentState):
    if state.get("escalate"):
        return "context_aggregator"
    return END

builder = StateGraph(IcedentAgentState)
builder.add_node('extrtacting', extrtacting)
builder.add_node('analising', analising)
builder.add_node('context_aggregator', context_aggregator)
builder.add_node('hunter_agent', hunter_agent)
builder.add_node('skeptic_agent', skeptic_agent)
builder.add_node('judge_agent', judge_agent)
builder.add_node('tools', ToolNode(tools))

builder.add_edge(START, "extrtacting")
builder.add_edge("extrtacting", "analising")
builder.add_conditional_edges("analising", route_after_l1)

builder.add_edge("context_aggregator", "hunter_agent")
builder.add_edge("hunter_agent", "skeptic_agent")
builder.add_edge("skeptic_agent", "judge_agent")
builder.add_conditional_edges("judge_agent", tools_condition)
builder.add_edge("tools", "judge_agent")

graph = builder.compile()

if __name__ == "__main__":
    print("=" * 60)
    print("SOC AI V2: BATCHING + GRAPHRAG (THESIS ARCHITECTURE)")
    print("=" * 60)

    while True:
        try:
            initial_state = {"incedent": [], "messages": [], "report": "", "escalate": False, "target_ip": ""}
            final_state = graph.invoke(initial_state, {"recursion_limit": 15})

            if final_state.get("escalate"):
                print("\n" + "="*50)
                print("INCIDENT ESCALATED: L3 FINAL VERDICT")
                print("="*50)
                print(final_state["messages"][-1].content)
                print("="*50 + "\n")
            
            elif final_state.get("report"):
                print("\n" + "-"*40)
                print("NOISE FILTERED: L1 QUICK REPORT")
                print("-"*40)
                print(final_state["report"])
                print("-"*40 + "\n")
            
        except KeyboardInterrupt:
            print("\n[SYSTEM] Shutdown requested by user.")
            break
        except Exception as e:
            print(f"\n[CRITICAL ERROR] {e}")
            time.sleep(5)