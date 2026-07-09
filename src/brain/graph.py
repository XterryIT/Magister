"""
Constructs the LangGraph execution flow.
"""
from langgraph.graph import StateGraph, START, END

from src.brain.state import IncidentAgentState
from src.brain.nodes import (
    extracting,
    context_aggregator,
    hunter_agent,
    skeptic_agent,
    judge_agent
)

def route_after_extracting(state: IncidentAgentState):
    """
    Determines if the flow should proceed to aggregation or terminate.
    """
    if state.get("escalate"): 
        return "context_aggregator"
    return "end_node"

def build_graph():
    """
    Builds and compiles the StateGraph for incident response.
    """
    builder = StateGraph(IncidentAgentState)
    
    # Add Nodes
    # Note: Renamed 'extrtacting' typo to 'extracting'
    builder.add_node('extracting', extracting)
    builder.add_node('context_aggregator', context_aggregator)
    builder.add_node('hunter_agent', hunter_agent)
    builder.add_node('skeptic_agent', skeptic_agent)
    builder.add_node('judge_agent', judge_agent)
    
    # Add Edges
    builder.add_edge(START, "extracting")
    
    builder.add_conditional_edges(
        "extracting", 
        route_after_extracting,
        {
            "context_aggregator": "context_aggregator",
            "end_node": END
        }
    )
    
    builder.add_edge("context_aggregator", "hunter_agent")
    builder.add_edge("hunter_agent", "skeptic_agent")
    builder.add_edge("skeptic_agent", "judge_agent")
    builder.add_edge("judge_agent", END)
    
    return builder.compile()
