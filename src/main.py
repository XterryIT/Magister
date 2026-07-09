"""
Main Entry Point for the Magister Data Pipeline
This script starts the deduplication worker, which continuously listens to the Redis queue for new Wazuh alerts.
"""
import sys
import os

# Import the core deduplication logic from our pipeline module
from src.data_pipeline.deduplication import deduplication

def main():
    """
    Main function to initialize and start the Magister deduplication service.
    """
    # Print a startup banner to standard output
    print("Starting Magister Project: DEDUPLICATION TEST MODE")
    print("-" * 50)
    
    try:
        # Enter the continuous processing loop.
        # This function connects to Redis and blocks on a BRPOP operation,
        # waiting for new JSON payloads to be pushed into the queue by the Wazuh script.
        deduplication() 
        
    except KeyboardInterrupt:
        # Gracefully handle a manual shutdown (e.g., when the user presses Ctrl+C)
        print("\nWorker stopped by user.")
        
    except Exception as e:
        # Catch any critical, unhandled exceptions that propagate up to the main thread
        # and print them out so the service doesn't die silently.
        print(f"Critical Error: {e}")

# Python boilerplate to ensure the code only runs when executed directly
if __name__ == "__main__":
    main()
