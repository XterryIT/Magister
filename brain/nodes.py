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




class State(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]

    

llm = ChatOllama(
    model="qwen3.5:9b",
    validate_model_on_init=True,
    temperature=0,
)

sys_mesage = SystemMessage(content = "You are the greatest cybersecurity threat analiser.")




   


def node_a(state: State) -> State:

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

        return State(nlist=[bundle])

    else:
        print("#########duplicate!!!!!!!!")


def node_b(state: State) -> State:
    """LLM decides whether to call a tool or not"""

    return {
        "messages": [
            llm.invoke(
                [sys_mesage] + state["messages"]
            )
        ],
        "llm_calls": state.get('llm_calls', 0) + 1
    }



builder = StateGraph(State)



#Adding nodes 
builder.add_node('a', node_a)
builder.add_node('b', node_b)


#Adding edges
builder.add_edge(START,"a")
builder.add_edge("a","b")
builder.add_edge("b",END)


graph = builder.compile()









# # Базовые типы сообщений теперь живут в langchain_core
# from langchain_core.messages import AnyMessage, SystemMessage, HumanMessage, ToolMessage

# # TypedDict и Annotated остаются из стандартных библиотек
# from langgraph.graph import StateGraph, START, END
# from langgraph.prebuilt import ToolNode, tools_condition
# from typing_extensions import TypedDict, Annotated
# import operator


# # Модели и инструменты
# from langchain_ollama import ChatOllama
# from langchain_core.tools import tool

# @tool
# def add(a: int, b: int) -> int:
#     """Adds two numbers together."""
#     return a + b

# @tool
# def multiply(a: int, b: int) -> int:
#     """Multiplies two numbers together."""
#     return a * b

# @tool
# def divide(a: int, b: int) -> float:
#     """Divides a by b."""
#     return a / b


# tools = [add, multiply, divide]

# llm = ChatOllama(
#     model="qwen3.5:9b",
#     validate_model_on_init=True,
#     temperature=0,
# ).bind_tools(tools)

# sys_mesage = SystemMessage(content = "You a great teacher that can easyly do all math operations")


# # Defining a State
# class MessagesState(TypedDict):
#     messages: Annotated[list[AnyMessage], operator.add]
#     llm_calls: int


# #The model node is used to call the LLM and decide whether to call a tool or not.

# def assistant(state: MessagesState):
#     """LLM decides whether to call a tool or not"""

#     return {
#         "messages": [
#             llm.invoke(
#                 [sys_mesage] + state["messages"]
#             )
#         ],
#         "llm_calls": state.get('llm_calls', 0) + 1
#     }


# # 1. Создаем граф на основе твоего State
# builder = StateGraph(MessagesState)

# # 2. Добавляем узлы (присваиваем функции строковое имя)
# builder.add_node("assistant", assistant)
# builder.add_node("tools", ToolNode(tools)) # Узел с твоими add/multiply

# # 3. Настраиваем связи по ИМЕНАМ (строкам!)
# builder.add_edge(START, "assistant") # Вход в граф

# # Условный переход: если ИИ вызвал инструмент - идем в "tools", иначе в END
# builder.add_conditional_edges(
#     "assistant",
#     tools_condition, # Это стандартная функция из langgraph.prebuilt
# )

# builder.add_edge("tools", "assistant") # После инструментов возвращаемся к ИИ

# # 4. КОМПИЛЯЦИЯ
# graph = builder.compile()
# print("✅ Граф успешно собран!")

# print(graph)











