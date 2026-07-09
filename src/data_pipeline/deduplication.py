import os
import json
import logging
import time
import redis
from src.data_pipeline.STIX_conversion import convert_wazuh_to_stix

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ALERTS_QUEUE = os.getenv('ALERTS_QUEUE', 'wazuh_raw_alerts')
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)

stix_bundles = []
all_raw_logs = []
duplicated_logs = []
duration_time = 0.0

def deduplication():
    global duration_time
    
    try:
        r = redis.Redis(
            host=REDIS_HOST, 
            port=REDIS_PORT, 
            password=REDIS_PASSWORD,
            decode_responses=True
        )
        r.ping()
        logger.info("Deduplication script is online and connected to Redis!")
    except redis.exceptions.ConnectionError:
        logger.error("Problems with Redis connectivity. Check host and port.")
        return 0.0
    except Exception as e:
        logger.error(f"Something went wrong during Redis connection: {e}")
        return 0.0

    start_time = time.time()

    while r.exists(ALERTS_QUEUE):
        # queue is position of our log in Redis, raw_log_string it is a log data
        queue_name, raw_log_string = r.brpop(ALERTS_QUEUE)
        
        all_raw_logs.append(raw_log_string)

        # Convert json to str
        try:
            sample_log = json.loads(raw_log_string)
            
            # Checks if log converted correctly
            if isinstance(sample_log, str):
                log_data = json.loads(sample_log)
            else:
                log_data = sample_log
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON log: {e}")
            continue

        # Extract id alert and victims IP 
        raw_id = log_data.get("rule", {}).get("id", None)
        raw_ip = log_data.get("agent", {}).get("ip", None)
        
        # Forming a dedup key, this key is needed to compare with others keys and deleting duplicates 
        dedup_key = f"dedup:{raw_id}:{raw_ip}"

        # ex sets an expire flag on key name for ex seconds, 
        # nx set to True, set the value at key name to value only if it does not exist.
        is_new_alert = r.set(name=dedup_key, value="1", ex=30, nx=True)

        if is_new_alert:
            bundle = convert_wazuh_to_stix(sample_log)
            stix_bundles.append(bundle)
        else:
            duplicated_logs.append(log_data)
            continue
        
    end_time = time.time()
    duration_time = end_time - start_time
    return duration_time


if __name__ == "__main__":
    deduplication()

    logger.info("===== Deduplication performance =====")
    logger.info(f"Time performance: {duration_time:.4f} s.")
    logger.info(f"All logs: {len(all_raw_logs)} ")
    logger.info(f"All STIX logs: {len(stix_bundles)}")
    logger.info(f"All duplicates: {len(duplicated_logs)}")