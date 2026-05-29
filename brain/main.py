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

llm = ChatOllama(
    model="qwen3.5:4b", 
    validate_model_on_init=True,
    temperature=0,
    num_ctx=8192 # Расширяем окно контекста для предотвращения зависаний
)

# ==========================================
# ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ СЖАТИЯ STIX
# ==========================================
def summarize_stix_bundle(bundle_objects):
    """
    Преобразует массив объектов STIX в сжатый текстовый формат для LLM,
    отсекая UUID и лишнюю JSON-структуру, экономя токены.
    """
    summary = []
    for obj in bundle_objects:
        obj_type = obj.get("type", "unknown")
        if obj_type == "indicator":
            name = obj.get("name", "Unknown Indicator")
            desc = obj.get("description", "No description")
            pattern = obj.get("pattern", "")
            summary.append(f"- Indicator: {name} | Desc: {desc} | Pattern: {pattern}")
        elif obj_type == "observed-data":
            first_observed = obj.get("first_observed", "")
            summary.append(f"- Observation Date: {first_observed}")
        elif obj_type == "attack-pattern":
            name = obj.get("name", "")
            summary.append(f"- Attack Pattern: {name}")
        # Добавь сюда другие типы STIX, если твой генератор их создает
    
    if not summary:
        return "No clear STIX indicators extracted."
    
    return "\n".join(summary)


# ==========================================
# ИНСТРУМЕНТ NEO4J ДЛЯ СУДЬИ
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
# ЭТАП 1: ТРИГГЕР И L1
# ==========================================
def check_trigger(ip: str, level: int) -> bool:
    if not ip or ip == "UNKNOWN_IP":
        return False
    if level >= 10:
        print(f"\n[DEBUG-TRIGGER] 🔥 Критический алерт ({level}) для IP {ip}!")
        return True

    redis_key = f"alert_history:{ip}"
    current_time = time.time()
    r_client.zadd(redis_key, {str(current_time): current_time})
    r_client.zremrangebyscore(redis_key, 0, current_time - TIME_WINDOW_SEC)
    alert_count = r_client.zcard(redis_key)
    
    if alert_count >= ALERT_THRESHOLD:
        print(f"\n[DEBUG-TRIGGER] 🔥 ЭСКАЛАЦИЯ! Накоплено {alert_count}/{ALERT_THRESHOLD} алертов для IP {ip}!")
        r_client.delete(redis_key) 
        return True
    return False

def extrtacting(state: IcedentAgentState):
    try:
        r_client.ping()
    except redis.exceptions.ConnectionError:
        print("[DEBUG-REDIS] ❌ Ошибка подключения к Redis!")
        return {"incedent": [], "messages": [], "escalate": False, "target_ip": ""}

    print("\n[DEBUG-REDIS] 📥 Ожидание лога...")
    queue_name, raw_log_string = r_client.brpop(ALERTS_QUEUE)
    
    sample_log = json.loads(raw_log_string)
    log_data = json.loads(sample_log) if isinstance(sample_log, str) else sample_log

    raw_id = log_data.get("rule", {}).get("id", "UNKNOWN_RULE")
    level = int(log_data.get("rule", {}).get("level", 0))
    raw_ip = log_data.get("agent", {}).get("ip", "UNKNOWN_IP")
    desc = log_data.get("rule", {}).get("description", "No description")

    # Сохраняем в Машину времени (Архив)
    if raw_ip != "UNKNOWN_IP":
        history_key = f"logs_archive:{raw_ip}"
        current_time = time.time()
        r_client.zadd(history_key, {json.dumps(log_data): current_time})
        r_client.zremrangebyscore(history_key, 0, current_time - HISTORY_WINDOW_SEC)

    dedup_key = f"dedup:{raw_id}:{raw_ip}"
    is_new_alert = r_client.set(name=dedup_key, value="1", ex=30, nx=True)

    if is_new_alert:
        needs_escalation = check_trigger(raw_ip, level)
        bundle = convert_wazuh_to_stix(sample_log)

        print()
        
        full_log = log_data.get("full_log", str(log_data.get("data", "")))
        prompt_content = f"Analyze this short log:\nRule: {desc} (Level: {level})\nLog: {full_log}"
            
        return {
            "incedent": [], 
            "messages": [HumanMessage(content=prompt_content)],
            "escalate": needs_escalation,
            "target_ip": raw_ip
        }
    else:
        return {"incedent": [], "messages": [], "escalate": False, "target_ip": ""}

def analising(state: IcedentAgentState):
    """Узел L1 (Быстрый Триаж)"""
    if not state.get("messages") or state.get("escalate"):
        return {"report": ""}

    base_prompt = (
        "You are an L1 SOC AI Analyst. Your task is instant alert triage.\n"
        "Respond in telegraphic style. DO NOT output thinking process. Output ONLY the final report.\n\n"
        "Format:\n"
        "🚨 **Verdict:** [True Positive / False Positive]\n"
        "🔍 **Reason:** [1 short sentence based on log]\n"
        "🛡️ **Action:** [Short recommendation]"
    )

    sys_message = SystemMessage(content=base_prompt)
    response = llm.invoke([sys_message] + state["messages"])
    
    return {"messages": [response], "report": response.content}

# ==========================================
# ЭТАП 2: СБОРЩИК КОНТЕКСТА
# ==========================================

def context_aggregator(state: IcedentAgentState):
    print("\n[DEBUG-AGGREGATOR] Starting 15-minute log history assembly...")
    target_ip = state.get("target_ip")
    
    history_key = f"logs_archive:{target_ip}"
    raw_logs = r_client.zrange(history_key, 0, -1)
    
    master_objects = []
    for raw_log_str in raw_logs:
        log_dict = json.loads(raw_log_str)
        bundle = convert_wazuh_to_stix(log_dict)
        master_objects.extend(bundle.objects)
        
    unique_objects = {obj.id: obj for obj in master_objects}.values()
    master_bundle = Bundle(objects=list(unique_objects), allow_custom=True)
    
    # Сжимаем данные перед отправкой в LLM
    compressed_stix = summarize_stix_bundle(list(unique_objects))

    
    print(f"[DEBUG-AGGREGATOR] MASTER BUNDLE formed. Compressed to {len(compressed_stix)} chars.")

    print("#"*50)
    print("#"*50)
    print(compressed_stix)
    print("#"*50)
    print("#"*50)

    escalation_prompt = f"MASTER STIX BUNDLE SUMMARY FOR L2 INVESTIGATION:\n{compressed_stix}"
    return {"messages": [HumanMessage(content=escalation_prompt)]}

# ==========================================
# ЭТАП 3: ОХОТНИК И СКЕПТИК
# ==========================================
def hunter_agent(state: IcedentAgentState):
    print("\n[DEBUG-L2] Hunter is analyzing STIX summary...")
    hunter_prompt = (
        "You are an L2 SOC Threat Hunter (Prosecutor).\n"
        "Review the MASTER STIX BUNDLE SUMMARY. Your goal is to prove this is a real cyber attack.\n"
        "DO NOT output thinking process. Output ONLY the report.\n\n"
        "Format strictly:\n"
        "Hunter Report:\n"
        "* Attack Vector: [1 sentence]\n"
        "* Evidence: [2-3 facts]\n"
        "* Conclusion: [1 sentence]"
    )
    sys_message = SystemMessage(content=hunter_prompt)
    start_time = time.time()
    response = llm.invoke([sys_message, state["messages"][-1]])
    
    print(f"[DEBUG-L2] ✅ Скептик вынес вердикт за {(time.time()-start_time):.2f} сек:")
    print(f"\n{'='*20} АРГУМЕНТЫ СКЕПТИКА {'='*20}")
    print(response.content)
    print("="*60)
    return {"messages": [response]}

def skeptic_agent(state: IcedentAgentState):
    print("\n[DEBUG-L2] Skeptic is analyzing STIX summary...")
    skeptic_prompt = (
        "You are an L2 SOC Validation Analyst (Defense).\n"
        "Review the MASTER STIX BUNDLE SUMMARY. Prove this is a False Positive (benign activity).\n"
        "DO NOT output thinking process. Output ONLY the report.\n\n"
        "Format strictly:\n"
        "Skeptic Report:\n"
        "* Benign Explanation: [1 sentence]\n"
        "* Mitigating Factors: [2-3 facts]\n"
        "* Conclusion: [1 sentence]"
    )
    sys_message = SystemMessage(content=skeptic_prompt)
    
    stix_message = next(msg for msg in reversed(state["messages"]) if isinstance(msg, HumanMessage))
    
    start_time = time.time()
    response = llm.invoke([sys_message, stix_message])
    
    print(f"[DEBUG-L2] ✅ Скептик вынес вердикт за {(time.time()-start_time):.2f} сек:")
    print(f"\n{'='*20} АРГУМЕНТЫ СКЕПТИКА {'='*20}")
    print(response.content)
    print("="*60)
    return {"messages": [response]}

# ==========================================
# ЭТАП 4: СУДЬЯ + NEO4J
# ==========================================
def judge_agent(state: IcedentAgentState):
    print("\n[DEBUG-L3] ⚖️ Судья принимает дело. Анализ аргументов и графа...")
    target_ip = state.get("target_ip")
    
    # Проверяем, есть ли в памяти ответ от графа (ToolMessage)
    tool_responses = [msg.content for msg in state["messages"] if isinstance(msg, ToolMessage)]
    if tool_responses:
        print(f"\n[DEBUG-NEO4J] 🌐 Данные, полученные из графа: {tool_responses[-1]}")
    
    judge_prompt = (
        "You are the Lead Incident Responder (The Judge).\n"
        "You have the STIX Bundle, Hunter's Report, and Skeptic's Report in the chat history.\n"
        f"1. You MUST call the `check_network_topology` tool using the target IP: {target_ip}.\n"
        "2. Wait for the tool's response to understand the blast radius.\n"
        "3. After evaluating the topology and agent reports, issue a final verdict.\n"
        "4. Write your FINAL report in RUSSIAN language using this Markdown format:\n\n"
        "🚨 **Финальный Вердикт:** [True Positive / False Positive]\n"
        "📊 **Уверенность:** [XX%]\n"
        "🌐 **Контекст Neo4j:** [1 предложение про зону и сервисы сервера]\n"
        "⚖️ **Обоснование:** [2-3 предложения. Чьи аргументы убедительнее?]\n"
        "🛡️ **Резолюция:** [Что делать дальше]"
    )
    
    sys_message = SystemMessage(content=judge_prompt)
    
    print("[DEBUG-L3] ⏳ Судья (Ollama) размышляет...")
    start_time = time.time()
    response = llm_with_tools.invoke([sys_message] + state["messages"])
    end_time = time.time()
    
    if hasattr(response, 'tool_calls') and len(response.tool_calls) > 0:
        print(f"[DEBUG-L3] 🔧 Судья вызывает инструмент: {response.tool_calls[0]['name']} -> {response.tool_calls[0]['args']}")
    else:
        print(f"[DEBUG-L3] ✅ Судья вынес финальный приговор за {(end_time-start_time):.2f} сек.")
        
    return {"messages": [response]}

# ==========================================
# МАРШРУТИЗАЦИЯ И СБОРКА ГРАФА
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
builder.add_node('tools', ToolNode(tools)) # Инструмент для Судьи

builder.add_edge(START, "extrtacting")
builder.add_edge("extrtacting", "analising")
builder.add_conditional_edges("analising", route_after_l1)

# Выстраиваем последовательную цепочку расследования
builder.add_edge("context_aggregator", "hunter_agent")
builder.add_edge("hunter_agent", "skeptic_agent")
builder.add_edge("skeptic_agent", "judge_agent")

# Роутинг инструмента для Судьи
builder.add_conditional_edges("judge_agent", tools_condition)
builder.add_edge("tools", "judge_agent") # После инструмента возвращаемся к Судье

graph = builder.compile()

if __name__ == "__main__":
    print("🤖 Многоагентный SOC AI (L1 + Hunter + Skeptic + Judge) ЗАПУЩЕН!")
    print("=" * 50)

    while True:
        try:
            initial_state = {"incedent": [], "messages": [], "report": "", "escalate": False, "target_ip": ""}
            final_state = graph.invoke(initial_state, {"recursion_limit": 15})

            if final_state.get("escalate"):
                print("\n" + "🔥"*25)
                print("=== ОФИЦИАЛЬНОЕ ЗАКЛЮЧЕНИЕ РАССЛЕДОВАНИЯ ===")
                # Финальный ответ всегда будет последним сообщением от AI
                final_ai_msg = final_state["messages"][-1].content
                print(final_ai_msg)
                print("🔥"*25 + "\n")
            
            elif final_state.get("report"):
                print("\n=== БЫСТРЫЙ ОТЧЕТ L1 ===")
                print(final_state["report"])
                print("=" * 50)
            
            print("⏳ Ожидание алертов...")
        except KeyboardInterrupt:
            print("\n🛑 Остановлено.")
            break
        except Exception as e:
            print(f"\n❌ [CRITICAL ERROR] Произошла ошибка: {e}")
            time.sleep(5)





               