import redis
import json
import re
from datetime import datetime
from stix2 import Identity, IPv4Address, URL, Indicator, Relationship, Bundle


ALERTS = 'wazuh_raw_alerts'

def convert_wazuh_to_stix(raw_log_json):
    """
    Converts a raw Wazuh log into a STIX 2.1 Bundle format.
    """
    # 1. Parse the incoming JSON (if it's a string)
    if isinstance(raw_log_json, str):
        log_data = json.loads(raw_log_json)
    else:
        log_data = raw_log_json

    # --- EXTRACTING DATA FROM THE LOG ---
    
    # Extract time (Wazuh uses +0000, STIX expects 'Z' for UTC)
    raw_time = log_data.get("timestamp", "")
    stix_time = raw_time.replace("+0000", "Z") if raw_time else datetime.utcnow()

    # Extract agent (victim) info
    agent_name = log_data.get("agent", {}).get("name", "Unknown Agent")
    agent_ip = log_data.get("agent", {}).get("ip", "0.0.0.0")

    # Extract rule info
    rule_id = log_data.get("rule", {}).get("id", "0")
    rule_desc = log_data.get("rule", {}).get("description", "Unknown Alert")
    rule_level = log_data.get("rule", {}).get("level", 0)

    # Attempt to extract the malicious URL from full_log (using regex)
    # Looking for anything following GET, POST, PUT, DELETE up to a space
    full_log = log_data.get("full_log", "")
    url_match = re.search(r'(?:GET|POST|PUT|DELETE)\s+(/\S+)', full_log)
    malicious_url = url_match.group(1) if url_match else None


    # --- CREATING STIX 2.1 OBJECTS ---
    stix_objects = []

    # 1. Create Identity (Organization or Server)
    target_identity = Identity(
        name=f"Wazuh Agent: {agent_name}",
        identity_class="system",
        description="Server within our infrastructure where the alert was triggered."
    )
    stix_objects.append(target_identity)

    # 2. Create IPv4-Addr (Victim's network address)
    # The stix2 library automatically validates if this is a real IP!
    target_ip = IPv4Address(
        value=agent_ip
    )
    stix_objects.append(target_ip)

    # 3. Create Indicator (IoC - the rule itself)
    alert_indicator = Indicator(
        name=f"Wazuh Rule {rule_id}: {rule_desc}",
        description=f"Wazuh Alert Level {rule_level}. Original log: {full_log}",
        pattern_type="stix",
        # Pattern is a required field in STIX. Here we specify what the indicator detects.
        pattern=f"[ipv4-addr:value = '{agent_ip}']", 
        valid_from=stix_time
    )
    stix_objects.append(alert_indicator)

    # 4. If we found an attack URL, create a URL object
    target_url = None
    if malicious_url:
        target_url = URL(
            value=f"http://{agent_ip}{malicious_url}" # Construct the full URL
        )
        stix_objects.append(target_url)

    # --- CREATING RELATIONSHIPS (FOR NEO4J) ---

    # Relationship 1: Server (Identity) has an address (IPv4)
    rel_identity_ip = Relationship(
        relationship_type="located-at",
        source_ref=target_identity.id,
        target_ref=target_ip.id
    )
    stix_objects.append(rel_identity_ip)

    # Relationship 2: If there is a URL, show that the Indicator points to it
    if target_url:
        rel_indicator_url = Relationship(
            relationship_type="indicates",
            source_ref=alert_indicator.id,
            target_ref=target_url.id
        )
        stix_objects.append(rel_indicator_url)
    else:
        # Otherwise, the indicator just points to the server's IP
        rel_indicator_ip = Relationship(
            relationship_type="indicates",
            source_ref=alert_indicator.id,
            target_ref=target_ip.id
        )
        stix_objects.append(rel_indicator_ip)

    # --- PACKAGING INTO A BUNDLE ---
    # A Bundle is an "envelope" that carries all STIX objects together
    stix_bundle = Bundle(objects=stix_objects)
    
    return stix_bundle

# --- TESTING ---
# if __name__ == "__main__":
#     # Your test log
#     sample_log = None

#     r = redis.Redis(host='localhost', port=6379, decode_responses=True)
#     log = r.rpop(ALERTS)
#     sample_log = json.loads(log)

#     print("#"*50)
#     print("#"*50)
#     print(json.dumps(sample_log, indent=4))
    
#     print("🔄 Starting Wazuh -> STIX 2.1 conversion...\n")
#     bundle = convert_wazuh_to_stix(sample_log)
    
#     # Print pretty JSON. This is exactly what will fly into Neo4j!
#     print(bundle.serialize(indent=4))


# ALERTS = 'wazuh_raw_alerts'

# r = redis.Redis(host='localhost', port=6379, decode_responses=True)

# # True
# log = r.rpop(ALERTS)

# parsed = json.loads(log)
# print('#'*100)
# print('#'*100)

# print(json.dumps(parsed, indent=4))

# print('#'*100)
# print('#'*100)

# print(log)

# print('#'*100)
# print('#'*100)
# # bar




