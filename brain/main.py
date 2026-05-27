import os
import sys
import redis
import json
import time

from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from typing_extensions import TypedDict, Annotated
from langgraph.graph.message import add_messages

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from neo4j import GraphDatabase

current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from data_pipeline.STIX_conversion import convert_wazuh_to_stix

ALERTS = 'wazuh_raw_alerts'

# ==========================================
# НАСТРОЙКА: ВКЛ/ВЫКЛ ИНСТРУМЕНТ NEO4J
# ==========================================
USE_NEO4J_TOOL = True
# ==========================================

class IcedentAgentState(TypedDict):
    incedent: list
    messages: Annotated[list, add_messages]
    report: str

llm = ChatOllama(
    model="qwen3.5:4b", 
    validate_model_on_init=True,
    temperature=0, 
)

@tool
def check_network_topology(ip_address: str) -> str:
    """
    Возвращает информацию о топологии сети для заданного IP-адреса.
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
                    return f"Сервер: {data['Server']}, Зона: {data['Zone']}, Услуги: {', '.join(data['Services'])}"
                else:
                    return f"В базе топологии нет данных об IP: {ip_address}."
    except Exception as e:
        return f"Ошибка БД Neo4j: {str(e)}"

tools = [check_network_topology]
llm_with_tools = llm.bind_tools(tools) if USE_NEO4J_TOOL else llm

def extrtacting(state: IcedentAgentState):
    try:
        r = redis.Redis(host='localhost', port=6379, decode_responses=True)
        r.ping()
    except redis.exceptions.ConnectionError:
        return {"incedent": [], "messages": []}

    queue_name, raw_log_string = r.brpop(ALERTS)
    sample_log = json.loads(raw_log_string)
    log_data = json.loads(sample_log) if isinstance(sample_log, str) else sample_log

    raw_id = log_data.get("rule", {}).get("id", None)
    raw_ip = log_data.get("agent", {}).get("ip", None)
        
    dedup_key = f"dedup:{raw_id}:{raw_ip}"
    is_new_alert = r.set(name=dedup_key, value="1", ex=30, nx=True)

    if is_new_alert:
        bundle = convert_wazuh_to_stix(sample_log)
        stix_json = bundle.serialize(indent=4)
        
        prompt_content = f"Проанализируй алерт:\n{stix_json}"
        if USE_NEO4J_TOOL:
            prompt_content += "\nНайди IP-адрес жертвы и используй инструмент check_network_topology."
            
        return {"incedent": [bundle], "messages": [HumanMessage(content=prompt_content)]}
    else:
        return {"incedent": [], "messages": []}

def analising(state: IcedentAgentState):
    # Промпт "Внимательного Скептика" с учетом Kill Chain
    base_prompt = (
        "Ты — старший аналитик SOC. Оцени алерт (True/False Positive). Не доверяй слепо уровню Wazuh.\n"
        "ВАЖНО: Злоумышленники часто используют легитимные команды и рутинные запросы "
        "(например, чтение системных файлов, базовые SQL-запросы) для разведки (Reconnaissance) и продвижения по сети (Lateral Movement).\n"
        "Всегда оценивай контекст! Если легитимная команда исходит от нетипичного IP-адреса, направлена на критическую зону (Internal_zone) "
        "или выглядит как попытка собрать информацию о системе — это часть атаки (True Positive).\n"
    )
    
    tool_prompt = "ОБЯЗАТЕЛЬНО используй ответ от инструмента топологии для принятия решения. " if USE_NEO4J_TOOL else "Анализируй без топологии. "
    
    # Требуем нормальный, развернутый, но структурированный ответ
    format_prompt = (
        "Твой ответ ДОЛЖЕН СТРОГО соответствовать шаблону:\n\n"
        "**Вердикт:** [True Positive или False Positive]\n"
        "**Уверенность:** [XX%]\n"
        "**Резюме инцидента:** [2-3 предложения, описывающие суть произошедшего]\n"
        "**Матрица MITRE ATT&CK:** [Тактика и техника]\n"
        "**Обоснование:** [3-4 предложения. Детально объясни логику: почему лог указывает на атаку или норму? Как это связано с топологией Neo4j? Упомяни конкретные данные из лога.]\n"
        "**Действие:** [Конкретный шаг для реагирования]"
    )

    sys_message = SystemMessage(content=base_prompt + tool_prompt + format_prompt)
    messages_to_send = [sys_message] + state["messages"]
    
    start_time = time.time()
    response = llm_with_tools.invoke(messages_to_send)
    end_time = time.time()
    
    is_tool_call = hasattr(response, 'tool_calls') and len(response.tool_calls) > 0
    
    # Выводим мысли ИИ только при вызове инструмента
    if is_tool_call:
        print("\n🧠 ИИ ищет информацию...")
        if response.content:
            print(f"💭 Логика ИИ: {response.content.strip()}")
        print(f"🔧 Запрос к графу: {response.tool_calls[0]['name']} -> {response.tool_calls[0]['args']}")
        print(f"⏱️ Заняло: {(end_time-start_time):.2f} сек.")
        print("-" * 50)
        return {"messages": [response], "report": ""}
    
    print(f"⏱️ Формирование отчета заняло: {(end_time-start_time):.2f} сек.")
    print("-" * 50)
    
    return {"messages": [response], "report": response.content}
# ==========================================
# ДИНАМИЧЕСКАЯ СБОРКА ГРАФА
# ==========================================
builder = StateGraph(IcedentAgentState)
builder.add_node('extrtacting', extrtacting)
builder.add_node('analising', analising)

builder.add_edge(START, "extrtacting")
builder.add_edge("extrtacting", "analising")

if USE_NEO4J_TOOL:
    builder.add_node('tools', ToolNode(tools))
    builder.add_conditional_edges("analising", tools_condition, {"tools": "tools", END: END})
    builder.add_edge("tools", "analising")
else:
    builder.add_edge("analising", END)

graph = builder.compile()

if __name__ == "__main__":
    print("🤖 ИИ-Аналитик запущен!")
    mode = "ВКЛЮЧЕН" if USE_NEO4J_TOOL else "ВЫКЛЮЧЕН"
    print(f"🌐 Инструмент Neo4j: {mode}")
    print("⏳ Ожидание алертов...")
    print("=" * 50)

    while True:
        try:
            initial_state = {"incedent": [], "messages": [], "report": ""}
            final_state = graph.invoke(initial_state, {"recursion_limit": 5})

            if final_state.get("report"):
                print("\n=== ФИНАЛЬНЫЙ ОТЧЕТ ИИ ===")
                print(final_state["report"])
                print("=" * 50)
            
            print("⏳ Ожидание следующего алерта...")
        except KeyboardInterrupt:
            print("\n🛑 Остановлено.")
            break
        except Exception as e:
            print(f"\n❌ Ошибка: {e}")
            time.sleep(5)