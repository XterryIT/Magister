"""
Defines the state structure for the LangGraph agent.
"""
from typing_extensions import TypedDict, Annotated
from langgraph.graph.message import add_messages

class IncidentAgentState(TypedDict):
    """
    Expanded state to isolate agent reports and prevent ChatML template collisions.
    """
    incident: list # Fixed typo 'incedent' -> 'incident'
    messages: Annotated[list, add_messages]
    report: str
    escalate: bool     
    target_ip: str 
    stix_bundle: str     
    hunter_report: str   
    skeptic_report: str  
