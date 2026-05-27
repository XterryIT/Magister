from typing_extensions import TypedDict, Annotated
from langgraph.graph.message import add_messages

class IcedentAgentState(TypedDict):
    incedent: list
    messages: Annotated[list, add_messages]
    report: str
    escalate: bool # Флаг: если True, L1 молчит и передает дело на L2
    target_ip: str # IP для которого сработал триггер