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
            f"Получен новый инцидент STIX. Проанализируй его.\n"
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
    print("ИИ анализирует данные и формирует отчет...")
    
    # Жесткий системный промпт с шаблоном ответа
    sys_message = SystemMessage(
        content=(
            "Ты — ведущий AI-аналитик SOC уровня L1. "
            "Твоя цель — провести триаж алерта, представленного в формате STIX. "
            "ПРАВИЛО 1: Всегда запрашивай контекст через инструмент проверки топологии Neo4j, если видишь целевой IP-адрес.\n"
            "ПРАВИЛО 2: Твой финальный ответ ДОЛЖЕН СТРОГО соответствовать следующему формату Markdown, без лишних вступлений:\n\n"
            "**Вердикт:** [Укажи: True Positive (Реальная угроза) или False Positive (Ложное срабатывание)]\n"
            "**Уровень уверенности:** [Укажи в процентах, например: 95%]\n"
            "**Резюме инцидента:** [Опиши суть атаки в 2-3 предложениях простым языком, используя данные из алерта и графа]\n"
            "**Матрица MITRE ATT&CK:** [Укажи тактику и технику, например: Initial Access -> Privilege Escalation]\n"
            "**Обоснование из графа:** [Объясни свое решение, строго опираясь на ответ от базы Neo4j. Укажи зону, сервер и затронутые сервисы]\n"
            "**Рекомендация по сдерживанию:** [Укажи конкретные действия, например: 'Изолировать хост VM1', 'Заблокировать IP' или 'Закрыть как фоновый шум']"
        )
    )
    
    # Передаем модели системный промпт + всю историю переписки
    messages_to_send = [sys_message] + state["messages"]
    
    start_time = time.time()
    
    # Вызов модели
    response = llm_with_tools.invoke(messages_to_send)
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    minutes = int(elapsed_time // 60)
    seconds = elapsed_time % 60

    print(f"⏱️ Шаг ИИ занял: {minutes} мин. и {seconds:.2f} сек.")
    print("#"*50)

    return {
        "messages": [response], 
        # Отчет сохраняется только тогда, когда модель возвращает финальный текст
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
    print("🤖 ИИ-Аналитик (SOC L1) успешно запущен!")
    print("⏳ Ожидание новых алертов из Redis (Очередь: wazuh_raw_alerts)...")
    print("-" * 50)

    # Бесконечный цикл - скрипт будет работать вечно, пока ты его не остановишь
    while True:
        try:
            # 1. Сбрасываем состояние агента для каждого НОВОГО инцидента
            # Важно делать это внутри цикла, чтобы ИИ не тянул контекст старых атак в новые!
            initial_state = {
                "incedent": [],
                "messages": [],
                "report": ""
            }

            # 2. Запускаем граф. 
            # Он зайдет в узел extrtacting, дойдет до команды r.brpop(ALERTS) 
            # и ЗАМРЕТ (заблокируется), ожидая данные. Процессор при этом не грузится!
            final_state = graph.invoke(initial_state)

            # 3. Как только граф отработал (ИИ выдал ответ), выводим его
            if final_state.get("report"):
                print("\n=== ОТЧЕТ ИИ О КИБЕРИНЦИДЕНТЕ ===")
                print(final_state["report"])
            
            print("\n" + "=" * 50)
            print("⏳ ИИ вернулся в режим ожидания следующего алерта...")

        # Если ты нажмешь Ctrl+C в терминале - скрипт красиво остановится
        except KeyboardInterrupt:
            print("\n🛑 Работа ИИ-Аналитика остановлена пользователем.")
            break
            
        # Защита от сбоев: если что-то сломалось (например, Redis упал), 
        # скрипт не вылетит, а напишет ошибку, подождет 5 секунд и попробует снова.
        except Exception as e:
            print(f"\n❌ Произошла критическая ошибка: {e}")
            print("🔄 Перезапуск цикла через 5 секунд...")
            time.sleep(5)