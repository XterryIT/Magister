import os
import json
import logging
import time
import redis
from src.data_pipeline.STIX_conversion import convert_wazuh_to_stix

# ==========================================
# LOGGING CONFIGURATION
# ==========================================
# Initialize standard Python logging to replace raw print() statements.
# This ensures logs have timestamps, severity levels, and are easily ingestible by monitoring tools.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==========================================
# REDIS CONFIGURATION
# ==========================================
# Load the target queue name where Wazuh dumps raw alerts.
ALERTS_QUEUE = os.getenv('ALERTS_QUEUE', 'wazuh_raw_alerts')
# Load Redis connection credentials.
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)

# ==========================================
# GLOBAL VARIABLES
# ==========================================
# Note: In a production multiprocessing environment, globals should be avoided.
# Here they are used for simple standalone metrics tracking.
stix_bundles = []      # Stores alerts that were successfully converted to STIX format.
all_raw_logs = []      # Stores every single raw log string pulled from the queue.
duplicated_logs = []   # Stores alerts that were flagged as duplicates and skipped.
duration_time = 0.0    # Tracks the total execution time of the script.

def deduplication():
    """
    Core function that connects to the Redis queue, pulls raw Wazuh alerts,
    applies a time-based deduplication filter, and converts unique alerts into STIX objects.
    """
    global duration_time
    
    try:
        # Establish connection to the Redis message broker.
        # decode_responses=True ensures we get Python strings instead of byte strings.
        r = redis.Redis(
            host=REDIS_HOST, 
            port=REDIS_PORT, 
            password=REDIS_PASSWORD,
            decode_responses=True
        )
        # Test the connection immediately.
        r.ping()
        logger.info("Deduplication script is online and connected to Redis!")
    except redis.exceptions.ConnectionError:
        # If Redis is unavailable, log the error and terminate the function gracefully.
        logger.error("Problems with Redis connectivity. Check host and port.")
        return 0.0
    except Exception as e:
        # Catch any other unexpected initialization errors.
        logger.error(f"Something went wrong during Redis connection: {e}")
        return 0.0

    # Start tracking the execution duration for performance metrics.
    start_time = time.time()

    # Continuously process alerts as long as the ALERTS_QUEUE exists in Redis.
    while r.exists(ALERTS_QUEUE):
        # r.brpop removes and returns the last element of the list (queue).
        # It returns a tuple: (queue_name, data_string).
        queue_name, raw_log_string = r.brpop(ALERTS_QUEUE)
        
        # Archive the raw string for metric tracking.
        all_raw_logs.append(raw_log_string)

        # ------------------------------------------
        # STEP 1: JSON PARSING
        # ------------------------------------------
        try:
            # Parse the string retrieved from Redis into a Python dictionary.
            sample_log = json.loads(raw_log_string)
            
            # Defensive programming: Depending on how Wazuh shipped it, the JSON might be double-encoded.
            # If the result of the first parse is STILL a string, parse it again.
            if isinstance(sample_log, str):
                log_data = json.loads(sample_log)
            else:
                log_data = sample_log
        except json.JSONDecodeError as e:
            # If the payload isn't valid JSON, log it and skip to the next item in the queue.
            logger.error(f"Failed to parse JSON log: {e}")
            continue

        # ------------------------------------------
        # STEP 2: METADATA EXTRACTION
        # ------------------------------------------
        # Safely extract the Wazuh rule ID and the Agent IP.
        # Using .get() prevents KeyError if the structure is unexpected.
        raw_id = log_data.get("rule", {}).get("id", None)
        raw_ip = log_data.get("agent", {}).get("ip", None)
        
        # ------------------------------------------
        # STEP 3: DEDUPLICATION LOGIC
        # ------------------------------------------
        # Form a unique deduplication key combining the rule ID and the IP address.
        # This means "Has this specific server triggered this specific rule recently?"
        dedup_key = f"dedup:{raw_id}:{raw_ip}"

        # Try to set this key in Redis.
        # 'ex=30' means the key will automatically delete itself after 30 seconds.
        # 'nx=True' means "Not eXists" - it will ONLY set the key if it isn't already there.
        # If the key was set successfully, is_new_alert is True. If the key already existed, it returns False/None.
        is_new_alert = r.set(name=dedup_key, value="1", ex=30, nx=True)

        if is_new_alert:
            # If it's a new, unique alert, pass it to the STIX conversion pipeline.
            bundle = convert_wazuh_to_stix(sample_log)
            # Store the resulting STIX bundle in our list.
            stix_bundles.append(bundle)
        else:
            # If the key already existed in Redis, this alert is a duplicate occurring within the 30s window.
            # We skip STIX conversion to save processing power and reduce noise.
            duplicated_logs.append(log_data)
            continue
        
    # Calculate the total execution time for the batch.
    end_time = time.time()
    duration_time = end_time - start_time
    return duration_time

# Standard boilerplate to execute the script directly for testing purposes.
if __name__ == "__main__":
    deduplication()

    # Print out the collected metrics using the logger.
    logger.info("===== Deduplication performance =====")
    logger.info(f"Time performance: {duration_time:.4f} s.")
    logger.info(f"All logs: {len(all_raw_logs)} ")
    logger.info(f"All STIX logs: {len(stix_bundles)}")
    logger.info(f"All duplicates: {len(duplicated_logs)}")