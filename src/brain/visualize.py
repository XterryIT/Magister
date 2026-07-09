"""
Utility script to visualize the LangGraph node structure and edges.
This will generate a 'graph.png' image file in the current directory,
allowing you to visually inspect the AI agent's reasoning flow.
"""
import sys
import os

# Add the project root to the python path so imports work correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.brain.graph import build_graph

def draw_graph():
    print("=" * 60)
    print("SOC AI: Graph Visualizer")
    print("=" * 60)
    
    print("[SYSTEM] Compiling LangGraph architecture...")
    try:
        graph = build_graph()
        
        # Get the Mermaid representation
        print("[SYSTEM] Requesting PNG generation from Mermaid API...")
        png_bytes = graph.get_graph().draw_mermaid_png()
        
        output_file = "magister_graph.png"
        
        # Write bytes to a PNG file
        with open(output_file, "wb") as f:
            f.write(png_bytes)
            
        print(f"\n[SUCCESS] The graph architecture has been saved to '{output_file}'!")
        print("You can now open this image file to see the nodes and their conditional edges.")
        
    except Exception as e:
        print(f"\n[ERROR] Failed to generate graph visualization: {e}")
        print("Note: This feature requires internet access to render the Mermaid graph via API.")

if __name__ == "__main__":
    draw_graph()
