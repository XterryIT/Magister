import os
import sys
import redis
import json
import time

from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from typing_extensions import TypedDict, Annotated
from langgraph.graph.message import add_messages
from langchain_ollama import ChatOllama
from langgraph.prebuilt import ToolNode, tools_condition
from langchain_core.tools import tool
from neo4j import GraphDatabase
from stix2 import Bundle

# Fix for module imports
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from data_pipeline.STIX_conversion import convert_wazuh_to_stix

# ==========================================
# GLOBAL CONFIGURATION
# ==========================================
ALERTS_QUEUE = 'wazuh_raw_alerts'
TIME_WINDOW_SEC = 300  
HISTORY_WINDOW_SEC = 900 
ALERT_THRESHOLD = 4

USE_NEO4J = True

r_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Expanded state to isolate agent reports and prevent ChatML template collisions
class IcedentAgentState(TypedDict):
    incedent: list
    messages: Annotated[list, add_messages]
    report: str
    escalate: bool     
    target_ip: str 
    stix_bundle: str     
    hunter_report: str   
    skeptic_report: str  

llm = ChatOllama(
    model="qwen3.5:4b",
    validate_model_on_init=True,
    temperature=0,
)
# ==========================================
# NEO4J TOOL (SPATIAL CONTEXT)
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

# ==========================================
# STAGE 1: EXTRACT, BATCH AND TRIGGER
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
    
    queue_name, first_log_string = r_client.brpop(ALERTS_QUEUE)
    raw_logs = [first_log_string]
    
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

    # Deduplicate and build time machine archive
    for log_str in raw_logs:
        sample_log = json.loads(log_str)
        log_data = json.loads(sample_log) if isinstance(sample_log, str) else sample_log

        raw_id = log_data.get("rule", {}).get("id", "UNKNOWN_RULE")
        level = int(log_data.get("rule", {}).get("level", 0))
        raw_ip = log_data.get("agent", {}).get("ip", "UNKNOWN_IP")
        
        if raw_ip != "UNKNOWN_IP":
            history_key = f"logs_archive:{raw_ip}"
            current_time = time.time()
            r_client.zadd(history_key, {json.dumps(log_data): current_time})
            r_client.zremrangebyscore(history_key, 0, current_time - HISTORY_WINDOW_SEC)

            # ИСПРАВЛЕНИЕ: Проверяем триггер ДО дедупликации!
            # Считаем КАЖДЫЙ лог, чтобы сработал порог (ALERT_THRESHOLD)
            if check_trigger(raw_ip, level):
                needs_escalation = True
                escalated_ip = raw_ip

        # Дедупликация на 1000 секунд
        dedup_key = f"dedup:{raw_id}:{raw_ip}"
        is_new_alert = r_client.set(name=dedup_key, value="1", ex=300, nx=True)

        if is_new_alert:
            unique_alerts.append(log_data)

    if needs_escalation:
        print(f"[EXTRACT] Incident escalated for IP {escalated_ip}. Bypassing L1.")
        return {
            "incedent": [], 
            "messages": [], 
            "escalate": True,
            "target_ip": escalated_ip
        }

    if not unique_alerts:
        print("[EXTRACT] All alerts in batch were duplicates. Dropping.")
        return {"incedent": [], "messages": [], "escalate": False, "target_ip": ""}

    print(f"[EXTRACT] Filtered down to {len(unique_alerts)} UNIQUE alerts.")

    batch_prompt = "Analyze this batch of alerts and provide a single summary:\n\n"
    for idx, alert in enumerate(unique_alerts):
        desc = alert.get("rule", {}).get("description", "No description")
        level = alert.get("rule", {}).get("level", 0)
        full_log = alert.get("full_log", str(alert.get("data", "")))
        batch_prompt += f"--- Alert {idx+1} ---\nRule: {desc} (Level: {level})\nRaw: {full_log}\n\n"
        
    return {
        "incedent": [], 
        "messages": [HumanMessage(content=batch_prompt)],
        "escalate": False,
        "target_ip": escalated_ip
    }
# ==========================================
# STAGE 2: L1 (QUICK TRIAGE)
# ==========================================
def analising(state: IcedentAgentState):
    # Skip L1 entirely if escalated
    if not state.get("messages") or state.get("escalate"):
        return {"report": ""}

    print("[L1] Performing quick noise filtration (Compute ROI check)...")
    base_prompt = (
        "You are an L1 SOC AI Analyst. Your goal is to triage an alert provided in STIX format.\n"
        "INSTRUCTIONS:\n"
        "1. Analyze the alert objectively.\n"
        "2. Your response MUST STRICTLY follow the Markdown format below without any introductory or conversational text.\n\n"
        "**Verdict:** [Specify: True Positive or False Positive]\n"
        "**Confidence Level:** [Specify in percentage, e.g., 90%]\n"
        "**Incident Summary:** [Write a concise paragraph of 2-3 sentences detailing what happened, the systems involved, and the potential impact.]\n"
        "**MITRE ATT&CK Matrix:** [Specify Tactic and Technique, e.g., Initial Access (T1190)]\n"
        "**Containment Recommendation:** [Provide 1-2 specific actions, e.g., 'Isolate IP 192.168.1.5' or 'Close as benign noise']"
    )

    sys_message = SystemMessage(content=base_prompt)
    start_time = time.time()

    start_time = time.time()

    response = llm.invoke([sys_message] + state["messages"])

    end_time = time.time()
    thinking_time = end_time - start_time

    print("\n" + "-" * 60)
    print(f"  [L1-ANALYST] AI thinking for the: {thinking_time:.2f} sec.".center(60))
    print("  └── [L1-ANALYST] Answer:")
    print(response.content)
    print("-" * 60 + "\n")
    
    return {"report": response.content}

# ==========================================
# STAGE 3: CONTEXT AGGREGATOR
# ==========================================
def summarize_stix_bundle(bundle_objects):
    """
    Преобразует массив объектов STIX в сжатый формат.
    Использует двухпроходный алгоритм для сохранения реальных сущностей (IP, Users) 
    с одновременной группировкой повторяющихся событий (Wazuh Rules).
    """
    event_counter = {}
    rel_counter = {}
    entities = set() # Множество для уникальных участников инцидента

    # ШАГ 1: Построение словаря для расшифровки UUID в реальные значения
    id_resolver = {}
    for obj in bundle_objects:
        obj_dict = dict(obj)
        obj_type = obj_dict.get("type", "unknown")
        obj_id = obj_dict.get("id", "unknown")
        
        # Извлекаем реальные данные в зависимости от типа STIX-объекта
        if obj_type == "ipv4-addr":
            ip_val = obj_dict.get("value", "Unknown IP")
            id_resolver[obj_id] = ip_val
            entities.add(f"[IP ADDRESS] {ip_val}")
            
        elif obj_type == "user-account":
            user_val = obj_dict.get("account_login", "Unknown User")
            id_resolver[obj_id] = user_val
            entities.add(f"[USER ACCOUNT] {user_val}")
            
        elif obj_type == "file":
            file_val = obj_dict.get("name", "Unknown File")
            id_resolver[obj_id] = file_val
            entities.add(f"[FILE COMPROMISED] {file_val}")
            
        elif obj_type == "identity":
            name_val = obj_dict.get("name", "Unknown System")
            id_resolver[obj_id] = name_val

    # ШАГ 2: Обработка событий и связей с подстановкой реальных значений
    for obj in bundle_objects:
        obj_dict = dict(obj)
        obj_type = obj_dict.get("type", "unknown")
        
        if obj_type == "observed-data":
            rule_desc = obj_dict.get("x_wazuh_rule_desc", "Unknown Rule")
            level = obj_dict.get("x_wazuh_rule_level", 0)
            event_key = f"[EVENT] Lvl: {level} | Desc: {rule_desc}"
            event_counter[event_key] = event_counter.get(event_key, 0) + 1
            
        elif obj_type == "relationship":
            rel_type = obj_dict.get("relationship_type", "")
            source_id = obj_dict.get("source_ref", "")
            target_id = obj_dict.get("target_ref", "")
            
            # Подставляем реальное значение. Если его нет в словаре - берем базовый тип
            source_name = id_resolver.get(source_id, source_id.split("--")[0])
            target_name = id_resolver.get(target_id, target_id.split("--")[0])
            
            rel_key = f"[RELATIONSHIP] {source_name} -> {rel_type} -> {target_name}"
            rel_counter[rel_key] = rel_counter.get(rel_key, 0) + 1

    # ШАГ 3: Формирование финального высокоплотного контекста для LLM
    summary_lines = ["--- INVOLVED ENTITIES (THE 'WHO' & 'WHERE') ---"]
    summary_lines.extend(list(entities))
    
    summary_lines.append("\n--- INCIDENT TIMELINE (THE 'WHAT') ---")
    for event_str, count in event_counter.items():
        summary_lines.append(f"{event_str} (Occurred {count} times)" if count > 1 else event_str)
            
    summary_lines.append("\n--- ATTACK GRAPH (HOW THEY CONNECT) ---")
    for rel_str, count in rel_counter.items():
        summary_lines.append(f"{rel_str} (x{count})" if count > 1 else rel_str)
            
    return "\n".join(summary_lines) if len(summary_lines) > 3 else "No meaningful STIX objects extracted."

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
    print("[L2-AGGREGATOR] --- COMPRESSED CONTEXT PREVIEW ---")
    print(compressed_stix)
    print("[L2-AGGREGATOR] ------------------------------------")
    
    return {"stix_bundle": compressed_stix}

# ==========================================
# STAGE 4: AGENTS (HUNTER & SKEPTIC)
# ==========================================

def hunter_agent(state: IcedentAgentState):
    print("  ├── [L2-HUNTER] Prosecuting the incident (Building attack vector)...")
    hunter_prompt = (
        "You are an L2 SOC Threat Hunter. Your goal is to prove this STIX bundle represents a real cyber attack.\n"
        "INSTRUCTIONS:\n"
        "1. Analyze the Kill Chain, focusing on how the attacker moved through the system (Initial Access, Execution, Privilege Escalation, Exfiltration).\n"
        "2. Be analytical and professional. Avoid redundant phrasing.\n"
        "3. Output EXACTLY in the format below.\n\n"
        "**ANALYSIS:**\n"
        "[Write a logical paragraph of 3-4 sentences explaining the sequence of events. Describe how the specific IPs, files, and relationships in the STIX data demonstrate an attack path.]\n\n"
        "**HUNTER REPORT:**\n"
        "* **Attack Vector:** [1-2 sentences summarizing the core attack method]\n"
        "* **Critical Evidence:**\n"
        "  - [Key Fact 1: Mention specific IP, Rule Level, or Compromised File]\n"
        "  - [Key Fact 2: Mention lateral movement or frequency of anomalies]\n"
        "  - [Key Fact 3: Mention data exfiltration or persistence attempts]\n"
        "* **Conclusion:** [A definitive statement confirming the system is compromised]"
    )
    sys_message = SystemMessage(content=hunter_prompt)
    stix_msg = HumanMessage(content=f"STIX BUNDLE:\n{state.get('stix_bundle', '')}")
    
    start_time = time.time()

    response = llm.invoke([sys_message, stix_msg])

    end_time = time.time()
    thinking_time = end_time - start_time

    print("\n" + "-" * 60)
    print(f"   [L2-Hunter] AI thinking for the: {thinking_time:.2f} sec.".center(60))
    print("  └── [L2-HUNTER] Answer:")
    print(response.content)
    print("-" * 60 + "\n")

    return {"hunter_report": response.content}

def skeptic_agent(state: IcedentAgentState):
    print("  └── [L2-SKEPTIC] Defending the incident (Searching for False Positives)...")
    skeptic_prompt = (
        "You are an L2 SOC Validation Analyst. Your goal is to critically examine the STIX bundle and argue why it might be a False Positive, benign administrative activity, or a system glitch.\n"
        "INSTRUCTIONS:\n"
        "1. Look for signs of internal environments (RFC 1918 IPs), routine backups, automated patching (CVE updates), or common misconfigurations.\n"
        "2. Be objective. Do not invent facts, only use the provided STIX data.\n"
        "3. Output EXACTLY in the format below.\n\n"
        "**ANALYSIS:**\n"
        "[Write a logical paragraph of 3-4 sentences explaining the benign context. Explain why the sequence of events could represent normal system behavior or a DevOps process rather than an attack.]\n\n"
        "**SKEPTIC REPORT:**\n"
        "* **Reasonable Explanation:** [1-2 sentences summarizing the benign scenario]\n"
        "* **Mitigating Factors:**\n"
        "  - [Mitigating Fact 1: e.g., Traffic is strictly internal, no external C2]\n"
        "  - [Mitigating Fact 2: e.g., The involved files are standard configuration backups]\n"
        "  - [Mitigating Fact 3: e.g., High-frequency alerts correspond to known automated processes]\n"
        "* **Conclusion:** [A definitive statement classifying the events as benign or false positive]"
    )
    sys_message = SystemMessage(content=skeptic_prompt)
    stix_msg = HumanMessage(content=f"STIX BUNDLE:\n{state.get('stix_bundle', '')}")
    
    start_time = time.time()

    response = llm.invoke([sys_message, stix_msg])

    end_time = time.time()
    thinking_time = end_time - start_time

    print("\n" + "-" * 60)
    print(f"  [L2-Hunter] AI thinking for the: {thinking_time:.2f} sec.".center(60))
    print("  └── [L2-SKEPTIC] Answer:")
    print(response.content)
    print("-" * 60 + "\n")

    return {"skeptic_report": response.content}
# ==========================================
# STAGE 5: JUDGE (GRAPHRAG RESOLUTION)
# ==========================================
def judge_agent(state: IcedentAgentState):
    target_ip = state.get("target_ip")
    
    # Ensure tool interaction history is kept clean
    judge_history = []
    has_tool_message = False
    for msg in state["messages"]:
        if isinstance(msg, ToolMessage):
            judge_history.append(msg)
            has_tool_message = True
        elif isinstance(msg, AIMessage) and hasattr(msg, "tool_calls") and msg.tool_calls:
            judge_history.append(msg)

    # Initial instruction payload for the Judge
    context_prompt = f"""You are the Lead Incident Responder.
    Target IP: {target_ip}

    --- STIX BUNDLE ---
    {state.get('stix_bundle', '')}

    --- HUNTER REPORT ---
    {state.get('hunter_report', '')}

    --- SKEPTIC REPORT ---
    {state.get('skeptic_report', '')}
    """
    messages_to_pass = [SystemMessage(content=context_prompt)] + judge_history

    if not has_tool_message and USE_NEO4J:
        print(f"[L3-JUDGE] Requesting Neo4j context for IP {target_ip}...")
        # FORCE the LLM to call the tool to guarantee spatial context extraction
        llm_forced = llm.bind_tools(tools, tool_choice="check_network_topology")
        response = llm_forced.invoke(messages_to_pass)
        return {"messages": [response]}
    else:
        if not USE_NEO4J:
            print("[L3-JUDGE] Neo4j is DISABLED. Generating verdict without graph context...")
        else:
            print("[L3-JUDGE] Neo4j data received. Generating final verdict...")
    
        # Clean final prompt enforcing Russian language
        final_prompt = (
            "Review the Neo4j context and the agent reports. "
            "You MUST output your response EXACTLY in the format below. "
            "CRITICAL RULES: Do NOT add any preamble or conclusion. Do NOT add markdown headers like '# EXECUTIVE SUMMARY' or tables. "
            "STRICTLY use these exact keys:\n\n"
            "Verdict: [Specify True Positive or False Positive]\n"
            "Confidence: [Enter a percentage, e.g., 95%]\n"
            "MITRE ATT&CK: [Describe the tactics and techniques, e.g., Initial Access - Brute Force]\n"
            "Infrastructure Context: [Provide 1-2 sentences based on Neo4j. If you do not have access, write 'Topology data is unavailable']\n"
            "Justification: [Explain whose arguments prevailed, and why?]\n"
            "Action: [Provide specific containment recommendation]"
        )
        
        messages_to_pass.append(HumanMessage(content=final_prompt))
        
        start_time = time.time()
        # Normal LLM invoke (no tools bound) forces text generation
        response = llm.invoke(messages_to_pass) 

        print(f"[L3-JUDGE] Verdict reached in {(time.time()-start_time):.2f} sec.")
        return {"messages": [response]}

# ==========================================
# МАРШРУТИЗАЦИЯ И СБОРКА ГРАФА
# ==========================================
def route_after_l1(state: IcedentAgentState):
    if state.get("escalate"):
        return "context_aggregator"
    return "end_node"

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

# ИСПРАВЛЕНИЕ 1: Явный словарь маршрутизации для L1
builder.add_conditional_edges(
    "analising", 
    route_after_l1,
    {
        "context_aggregator": "context_aggregator",
        "end_node": END
    }
)

builder.add_edge("context_aggregator", "hunter_agent")
builder.add_edge("hunter_agent", "skeptic_agent")
builder.add_edge("skeptic_agent", "judge_agent")

# ИСПРАВЛЕНИЕ 2: Явный словарь маршрутизации для инструмента Neo4j
builder.add_conditional_edges(
    "judge_agent", 
    tools_condition,
    {
        "tools": "tools",
        "__end__": END
    }
)
builder.add_edge("tools", "judge_agent")

graph = builder.compile()

if __name__ == "__main__":
    print("=" * 60)
    print("SOC AI V2: BATCHING + GRAPHRAG (THESIS ARCHITECTURE)")
    print("=" * 60)


    while True:
        try:
            # Re-initialize all fields to prevent key errors
            initial_state = {
                "incedent": [], 
                "messages": [], 
                "report": "", 
                "escalate": False, 
                "target_ip": "",
                "stix_bundle": "",
                "hunter_report": "",
                "skeptic_report": ""
            }
            final_state = graph.invoke(initial_state, {"recursion_limit": 15})

            if final_state.get("escalate"):
                print("\n" + "="*70)
                print(">>> OFFICIAL INCIDENT REPORT (L3 JUDGE) <<<".center(70))
                print("="*70)
                print(final_state["messages"][-1].content)
                print("="*70)
            
        except KeyboardInterrupt:
            print("\n[SYSTEM] Shutdown requested by user.")
            print("[SYSTEM] Flushing Redis database to clear deduplication keys and archives...")
            try:
                r_client.flushdb()
                print("[SYSTEM] Cleanup successful. Goodbye!")
            except Exception as e:
                print(f"[ERROR] Cleanup failed: {e}")
            break
        except Exception as e:
            print(f"\n[CRITICAL ERROR] {e}")
            time.sleep(5)