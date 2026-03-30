# main.py
import sys
import os
from deduplication import deduplication

if __name__ == "__main__":
    print("Starting Magister Project: DEDUPLICATION TEST MODE")
    print("-" * 50)
    
    try:
        # This will start the Redis BRPOP loop we wrote earlier
        deduplication() 
    except KeyboardInterrupt:
        print("\nWorker stopped by user.")
    except Exception as e:
        print(f"Critical Error: {e}")