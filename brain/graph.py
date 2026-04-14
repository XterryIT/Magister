# Базовые типы сообщений теперь живут в langchain_core
import os
import sys

from langchain_core.messages import AnyMessage, SystemMessage, HumanMessage, ToolMessage
from IPython.display import Image, display
# TypedDict и Annotated остаются из стандартных библиотек
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from typing_extensions import TypedDict, Annotated
import operator

# Модели и инструменты
from langchain_ollama import ChatOllama
from langchain_core.tools import tool

import redis
import json
import re
import time  
from datetime import datetime



# --- ФИКС ПУТЕЙ ИМПОРТА ---
# 1. Получаем абсолютный путь к текущему файлу (nodes.py)
current_file_path = os.path.abspath(__file__)
# 2. Получаем папку, в которой лежит этот файл (brain/)
current_dir = os.path.dirname(current_file_path)
# 3. Получаем родительскую папку (Magister/)
project_root = os.path.dirname(current_dir)
# 4. Добавляем родительскую папку в системный путь Python
sys.path.append(project_root)

# Теперь Python "видит" папку data_pipeline, и мы можем импортировать из неё
from data_pipeline.STIX_conversion import convert_wazuh_to_stix



ALERTS = 'wazuh_raw_alerts'




class IcedentAgentState(TypedDict):
    incedent: list
    report: str

    

llm = ChatOllama(
    model="qwen3.5:9b",
    validate_model_on_init=True,
    temperature=0,
)

# sys_mesage = SystemMessage(content = "You are the greatest cybersecurity threat analiser.")




   


def extrtacting(state: IcedentAgentState) -> IcedentAgentState:

    try:
        r = redis.Redis(host='localhost', port=6379, decode_responses=True)

        r.ping()

        print("Script is on !")

    except redis.exceptions.ConnectionError:
        print("Problems with connectivity")

    except Exception as e:
        print("something went wrong: {e}")



    queue_name, raw_log_string = r.brpop(ALERTS)

        # Convert json to str
    sample_log = json.loads(raw_log_string)

        # Checks if log converted correctly
    if isinstance(sample_log, str):
        log_data = json.loads(sample_log)
    else:
        log_data = sample_log

        # Extract id alert and victims IP 
    raw_id = log_data.get("rule", {}).get("id", None)
    raw_ip = log_data.get("agent", {}).get("ip", None)
        
        # Foeming a dedup key, this key is need to compare with others keys and deleting duplicats 
    dedup_key = f"dedup:{raw_id}:{raw_ip}"

        # ex sets an expire flag on key name for ex seconds, 
        # f set to True, set the value at key name to value only if it does not exist.
    is_new_alert = r.set(name=dedup_key, value="1", ex=30, nx=True)

    if is_new_alert:
        bundle = convert_wazuh_to_stix(sample_log)

        print("#"*50)
        print("THE STIX OBJECT")
        print("#"*50)
        print(bundle.serialize(indent=4))
        print("#"*50)

        return IcedentAgentState(incedent=[bundle])

    else:
        print("#########duplicate!!!!!!!!")





def analising(state: IcedentAgentState) -> IcedentAgentState:
    """Use LLM to understand what incedent is happaned"""


    sys_mesage = "You are the greatest cybersecurity threat analiser."

    analysing_prompt = f"""
    You will get a STIX object formed from the incident
    
    Style answer:
    1. minimal text editing
    2. Don't insert fragments of the STIX object's text, but convert them into understandable text so that the entire text looks harmonious and readable.

    Your task is:

    1. Analise this Stix object
    2. Understand whats happend
    3. Write a short report where you describe whats happend
    

    Incedent: {state['incedent']}
    
    """
    
    print("AI is thinking")
    print("#"*50)


    start_time = time.time()

    analyze_report = llm.invoke(sys_mesage + analysing_prompt)

    end_time = time.time()

    elapsed_time = end_time - start_time
    minutes = int(elapsed_time // 60)
    seconds = elapsed_time % 60

    # Выводим красивый таймер в консоль
    print(f"⏱️ ИИ думал: {minutes} мин. и {seconds:.2f} сек.")
    print("#"*50)

    return {"report": analyze_report.content}



builder = StateGraph(IcedentAgentState)



#Adding nodes 
builder.add_node('extrtacting', extrtacting)
builder.add_node('analising', analising)


#Adding edges
builder.add_edge(START,"extrtacting")
builder.add_edge("extrtacting","analising")
builder.add_edge("analising",END)


graph = builder.compile()

initial_state = {
    "incedent": [],
    "report": ""
}

final_state = graph.invoke(initial_state)

print("\n=== ОТЧЕТ ИИ О КИБЕРИНЦИДЕНТЕ ===")
print(final_state["report"])




