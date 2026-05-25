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

# Модели и инструменты
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from neo4j import GraphDatabase

current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from data_pipeline.STIX_conversion import convert_wazuh_to_stix

ALERTS = 'wazuh_raw_alerts'

# 1. ОБНОВЛЕНИЕ СОСТОЯНИЯ АГЕНТА
# Используем add_messages, чтобы LangGraph накапливал историю общения (память)
class IcedentAgentState(TypedDict):
    incedent: list
    messages: Annotated[list, add_messages]
    report: str

# 2. МОДЕЛЬ
llm = ChatOllama(
    model="qwen3.5:4b", # или твоя актуальная модель
    validate_model_on_init=True,
    temperature=0,
)

# 3. ИНСТРУМЕНТ: ЗАПРОС К NEO4J (TOOL)
@tool
def check_network_topology(ip_address: str) -> str:
    """
    Возвращает информацию о топологии сети для заданного IP-адреса.
    ВСЕГДА используй этот инструмент, если в алерте есть IP-адрес жертвы/хоста,
    чтобы понять, в какой зоне находится сервер и какие сервисы на нем работают.
    """
    URI = "bolt://localhost:7687"
    AUTH = ("neo4j", "magister123")
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
                    return f"Сервер: {data['Server']}, Зона: {data['Zone']}, Работающие сервисы: {', '.join(data['Services'])}"
                else:
                    return f"В базе топологии нет данных об IP: {ip_address}. Вероятно, это внешний адрес атакующего."
    except Exception as e:
        return f"Ошибка подключения к графу Neo4j: {str(e)}"

# Привязываем инструмент к модели, чтобы она знала о его существовании
tools = [check_network_topology]
llm_with_tools = llm.bind_tools(tools)

# 4. УЗЕЛ ИЗВЛЕЧЕНИЯ (EXTRACTING)
def extrtacting(state: IcedentAgentState):
    try:
        r = redis.Redis(host='localhost', port=6379, decode_responses=True)
        r.ping()
    except redis.exceptions.ConnectionError:
        print("Problemy z polaczeniem z Redis")
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
        
        # Формируем первый запрос от "пользователя" к ИИ
        prompt_content = (
            f"Олучен новый инцидент STIX. Проанализируй его.\n"
            f"Найди целевые IP-адреса и ОБЯЗАТЕЛЬНО используй свой инструмент проверки графа сети, "
            f"чтобы получить пространственный контекст перед написанием отчета.\n\n"
            f"Инцидент:\n{stix_json}"
        )
        
        return {
            "incedent": [bundle],
            "messages": [HumanMessage(content=prompt_content)]
        }
    else:
        print("######### DUPLIKAT!!!!!!!!")
        return {"incedent": [], "messages": []}

# 5. УЗЕЛ АНАЛИЗА (AGENT)
def analising(state: IcedentAgentState):
    print("ИИ думает и решает, использовать ли инструменты...")
    sys_message = SystemMessage(
        content=(
            "Ты — выдающийся аналитик SOC уровня L1. "
            "Твоя цель — провести триаж алерта. Ты должен всегда запрашивать контекст "
            "через инструмент проверки топологии Neo4j, если видишь целевой IP-адрес. "
            "Опираясь на данные алерта и ответ от графа сети, напиши четкий, лаконичный отчет."
        )
    )
    
    # Передаем модели системный промпт + всю историю переписки (включая ответы от базы данных)
    messages_to_send = [sys_message] + state["messages"]
    
    start_time = time.time()
    
    # .invoke либо выдаст текст, либо вернет ЗАПРОС на использование инструмента
    response = llm_with_tools.invoke(messages_to_send)
    
    end_time = time.time()
    print(f"⏱️ Шаг ИИ занял: {end_time - start_time:.2f} сек.")
    print("#"*50)

    return {
        "messages": [response], 
        # Отчет сохраняется только тогда, когда модель возвращает текст (а не вызов инструмента)
        "report": response.content if response.content else ""
    }

# 6. СБОРКА ГРАФА (LANGGRAPH ORCHESTRATION)
builder = StateGraph(IcedentAgentState)

builder.add_node('extrtacting', extrtacting)
builder.add_node('analising', analising)
# Специальный узел, который выполняет функции (Python-код) по просьбе ИИ
builder.add_node('tools', ToolNode(tools))

builder.add_edge(START, "extrtacting")
builder.add_edge("extrtacting", "analising")

# Условная логика:
# Если 'analising' захотел вызвать инструмент -> идем в узел 'tools'
# Если 'analising' выдал финальный текст -> идем в END
builder.add_conditional_edges(
    "analising",
    tools_condition,
    {"tools": "tools", END: END}
)
# После того как инструмент сходил в базу, возвращаем результат обратно ИИ для финального ответа
builder.add_edge("tools", "analising")

graph = builder.compile()

if __name__ == "__main__":
    initial_state = {
        "incedent": [],
        "messages": [],
        "report": ""
    }

    final_state = graph.invoke(initial_state)

    print("\n=== ОТЧЕТ ИИ О КИБЕРИНЦИДЕНТЕ ===")
    print(final_state["report"])