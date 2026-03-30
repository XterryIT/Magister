# Базовые типы сообщений теперь живут в langchain_core
from langchain_core.messages import AnyMessage, SystemMessage, HumanMessage, ToolMessage

# TypedDict и Annotated остаются из стандартных библиотек
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from typing_extensions import TypedDict, Annotated
import operator


# Модели и инструменты
from langchain_ollama import ChatOllama
from langchain_core.tools import tool


def add(a: int, b: int) -> int:
    """Adds two numbers together."""
    return a + b

def multiply(a: int, b: int) -> int:
    """Multiplies two numbers together."""
    return a * b

def divide(a: int, b: int) -> float:
    """Divides a by b."""
    return a / b


tools = [add, multiply, divide]

llm = ChatOllama(
    model="gemma3:12b",
    validate_model_on_init=True,
    temperature=0,
).bind_tools(tools)

sys_mesage = SystemMessage(content = "You a great teacher that can easyly do all math operations")


# Defining a State
class MessagesState(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]
    llm_calls: int


#The model node is used to call the LLM and decide whether to call a tool or not.

def assistant(state: MessagesState):
    """LLM decides whether to call a tool or not"""

    return {
        "messages": [
            llm.invoke(
                [sys_mesage] + state["messages"]
            )
        ],
        "llm_calls": state.get('llm_calls', 0) + 1
    }


# 1. Создаем граф на основе твоего State
builder = StateGraph(MessagesState)

# 2. Добавляем узлы (присваиваем функции строковое имя)
builder.add_node("assistant", assistant)
builder.add_node("tools", ToolNode) # Узел с твоими add/multiply

# 3. Настраиваем связи по ИМЕНАМ (строкам!)
builder.add_edge(START, "assistant") # Вход в граф

# Условный переход: если ИИ вызвал инструмент - идем в "tools", иначе в END
builder.add_conditional_edges(
    "assistant",
    tools_condition, # Это стандартная функция из langgraph.prebuilt
)

builder.add_edge("tools", "assistant") # После инструментов возвращаемся к ИИ

# 4. КОМПИЛЯЦИЯ
graph = builder.compile()
print("✅ Граф успешно собран!")

print(graph)

