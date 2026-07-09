#!/var/ossec/framework/python/bin/python3
import sys
import json
import redis
import os

# --- CONFIGURATION ---
# It's recommended to set these in environment variables or a config file if possible in Wazuh,
# but for standalone scripts, keep them here or load from an external file.
REDIS_HOST = os.getenv("REDIS_HOST", "192.168.100.39")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "MyAdmin123")
QUEUE_NAME = os.getenv("ALERTS_QUEUE", "wazuh_raw_alerts")

# Custom debug log file (Wazuh must have write permissions here)
DEBUG_LOG_FILE = "/var/ossec/logs/custom_redis_integration.log"

def log_debug(message):
    """Helper function to write logs to a file, since print() output in Wazuh is lost."""
    try:
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(message + "\n")
    except Exception:
        pass # If no write permissions, just ignore

def main():
    if len(sys.argv) < 2:
        log_debug("ERROR: Wazuh did not pass the alert file path (sys.argv[1] is empty).")
        return

    alert_file = sys.argv[1]
    
    try:
        # 1. Read the raw alert from Wazuh
        with open(alert_file, 'r', encoding="utf-8") as f:
            alert_data = json.load(f)

        # Write to our debug log to see what exactly we caught
        log_debug("--- NEW ALERT TRIGGERED ---")
        log_debug(f"Alert file path: {alert_file}")
        
        # 2. Connect to Redis
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
           # password=REDIS_PASSWORD,
            socket_timeout=5,
            decode_responses=True # Automatically decodes bytes into strings
        )

        # 3. Send JSON to the queue
        r.lpush(QUEUE_NAME, json.dumps(alert_data))
        log_debug("SUCCESS: Alert successfully sent to the Redis queue.\n")
        
    except Exception as e:
        # Now any error (no connection, no file) will be recorded in the log
        log_debug(f"INTEGRATION ERROR: {str(e)}\n")

if __name__ == "__main__":
    main()