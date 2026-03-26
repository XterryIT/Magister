import redis
import json
import re
from datetime import datetime
from STIX_conversion import convert_wazuh_to_stix

ALERTS = 'wazuh_raw_alerts'

    
    


if __name__ == "__main__":

    try:
        r = redis.Redis(host='localhost', port=6379, decode_responses=True)

        r.ping()


    except redis.exceptions.ConnectionError:
        print("Problems with connectivity")

    except Exception as e:
        print("something went wrong: {e}")


    
    
    while True:
        # queue is position of our log in Redis, raw_log_string it is a log data
        queue_name, raw_log_string = r.brpop(ALERTS)
        
        # Convert json to str
        sample_log = json.loads(raw_log_string)

        # Checks if log converted correctly
        if isinstance(sample_log, str):
            log_data = json.loads(sample_log)
        else:
            log_data = sample_log

        # Extract id alert and victims IP 
        raw_id = log_data.get("rule", {}).get("id", None)
        raw_ip = log_data.get("agent", {}).get("ip", None)
        
        # Foeming a dedup key, this key is need to compare with others keys and deleting duplicats 
        dedup_key = f"dedup:{raw_id}:{raw_ip}"

        # ex sets an expire flag on key name for ex seconds, 
        # f set to True, set the value at key name to value only if it does not exist.
        is_new_alert = r.set(name=dedup_key, value="1", ex=60, nx=True)

        if is_new_alert:
            bundle = convert_wazuh_to_stix(sample_log)

            print(bundle.serialize(indent=4))

        else:
            continue


