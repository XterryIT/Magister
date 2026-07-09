"""
Main entry point for running the brain/agent standalone.
"""
import time
from src.brain.graph import build_graph
from src.brain.config import r_client

def run_agent():
    print("=" * 60)
    print("SOC AI:")
    print("=" * 60)

    graph = build_graph()
    total_start_time = time.time()

    try:
        # Initialize empty state
        initial_state = {
            "incident": [], 
            "messages": [], 
            "report": "", 
            "escalate": False, 
            "target_ip": "",
            "stix_bundle": "",
            "hunter_report": "",
            "skeptic_report": ""
        }
        
        # Run graph once
        final_state = graph.invoke(initial_state, {"recursion_limit": 15})
        
        total_end_time = time.time()
        total_duration = total_end_time - total_start_time

        if final_state.get("messages") and len(final_state["messages"]) > 0:
            last_message = final_state["messages"][-1].content
            if "Verdict:" in last_message: 
                print("\n" + "="*70)
                print(">>> OFFICIAL INCIDENT REPORT (L3 JUDGE) <<<".center(70))
                print("="*70)
                print(last_message)
                print("="*70)

                print(f"\n[SYSTEM] TOTAL PROCESSING TIME: {total_duration:.2f} seconds")
        else:
            print("\n[SYSTEM] No critical incidents detected in this batch. Graph completed.")
            
    except KeyboardInterrupt:
        print("\n[SYSTEM] Shutdown requested by user.")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] {e}")
    finally:
        print("\n[SYSTEM] Flushing Redis database to clear deduplication keys and archives...")
        try:
            r_client.flushdb()
            print("[SYSTEM] Cleanup successful. Goodbye!")
        except Exception as e:
            print(f"[ERROR] Cleanup failed: {e}")

if __name__ == "__main__":
    run_agent()