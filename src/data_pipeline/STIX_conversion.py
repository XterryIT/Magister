import json
from datetime import datetime, timezone
import uuid
import re
from stix2 import (
    Bundle,
    Identity,
    IPv4Address,
    ObservedData,
    Relationship
)

def format_stix_timestamp(raw_time):
    """
    Formats the timestamp extracted from a Wazuh log into a STIX 2.1 compliant timestamp string (UTC).
    
    Args:
        raw_time (str): The raw timestamp string from Wazuh (e.g., '2023-10-27T10:00:00+0000').
        
    Returns:
        str: A STIX-compliant timestamp ending in 'Z' indicating UTC.
    """
    if raw_time:
        # Replace the +0000 timezone offset with the standard 'Z' (Zulu time).
        return raw_time.replace("+0000", "Z")
    # If no timestamp is provided, generate the current UTC time.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def convert_wazuh_to_stix(wazuh_json):
    """
    Converts a raw JSON Wazuh alert into a standardized STIX 2.1 Bundle.
    This creates an interconnected graph of cyber threat intelligence objects 
    (Identity, IPv4Address, ObservedData) linked via Relationships.
    
    Args:
        wazuh_json (dict | str): The raw Wazuh alert data (can be a dict or a JSON string).
        
    Returns:
        Bundle: A stix2 Bundle object containing all the generated STIX entities and relationships.
    """
    
    # ------------------------------------------
    # STEP 1: PARSE AND NORMALIZE INPUT
    # ------------------------------------------
    # Ensure the input is parsed into a Python dictionary.
    if isinstance(wazuh_json, str):
        try:
            log = json.loads(wazuh_json)
        except json.JSONDecodeError as e:
            print(f"JSON Error: {e}")
            return None
    else:
        log = wazuh_json

    # Initialize a list to hold all the STIX objects we generate.
    stix_objects = []

    # Extract the timestamp, defaulting to the current time if missing.
    timestamp = format_stix_timestamp(log.get("timestamp"))

    # ------------------------------------------
    # STEP 2: CREATE IDENTITY (THE TARGET SYSTEM)
    # ------------------------------------------
    # Extract the Wazuh agent's name, ID, and IP address.
    agent_info = log.get("agent", {})
    agent_name = agent_info.get("name", "Unknown-Agent")
    agent_id = agent_info.get("id", "000")
    agent_ip = agent_info.get("ip", "0.0.0.0")

    # Define a STIX Identity object representing the compromised or targeted host.
    # We include custom Wazuh attributes for traceability.
    identity = Identity(
        id=f"identity--{uuid.uuid4()}",
        name=agent_name,
        identity_class="system",
        description=f"Wazuh Agent: {agent_name} (ID: {agent_id}, IP: {agent_ip})",
        custom_properties={
            "x_wazuh_agent_id": agent_id,
            "x_wazuh_agent_ip": agent_ip
        }
    )
    stix_objects.append(identity)

    # ------------------------------------------
    # STEP 3: CREATE OBSERVED DATA (THE EVENT)
    # ------------------------------------------
    # Extract details about the triggered rule.
    rule_info = log.get("rule", {})
    rule_id = rule_info.get("id", "unknown")
    rule_level = rule_info.get("level", 0)
    rule_desc = rule_info.get("description", "No description")

    # Extract file paths if this was a File Integrity Monitoring (Syscheck) alert.
    syscheck_info = log.get("syscheck", {})
    syscheck_path = syscheck_info.get("path", "")
    
    # Extract any raw command outputs or data attached to the alert.
    data_field = log.get("data", "")
    full_log_field = log.get("full_log", "")

    # Define a STIX ObservedData object representing the actual security event.
    # The 'number_observed' is 1 because we process individual Wazuh alerts.
    observed_data = ObservedData(
        id=f"observed-data--{uuid.uuid4()}",
        first_observed=timestamp,
        last_observed=timestamp,
        number_observed=1,
        objects={
            "0": {
                "type": "directory",
                "path": "Unknown" 
            }
        },
        # Inject Wazuh-specific metadata as custom STIX properties.
        custom_properties={
            "x_wazuh_rule_id": rule_id,
            "x_wazuh_rule_level": rule_level,
            "x_wazuh_rule_desc": rule_desc,
            "x_wazuh_syscheck_path": syscheck_path,
            "x_wazuh_data": data_field,
            "x_wazuh_full_log": full_log_field
        }
    )
    stix_objects.append(observed_data)

    # ------------------------------------------
    # STEP 4: LINK EVENT TO SYSTEM
    # ------------------------------------------
    # Create a STIX Relationship linking the security event to the targeted system.
    # This says: "The event 'consists-of' the system identity."
    rel_obs_id = Relationship(
        id=f"relationship--{uuid.uuid4()}",
        relationship_type="consists-of",
        source_ref=observed_data.id,
        target_ref=identity.id
    )
    stix_objects.append(rel_obs_id)

    # ------------------------------------------
    # STEP 5: HANDLE ATTACKER IPs (EXTERNAL ACTORS)
    # ------------------------------------------
    # Some alerts contain the attacker's source IP (e.g., failed SSH logins).
    data_info = log.get("data", {})
    src_ip = data_info.get("srcip")

    # Regular expression to validate standard IPv4 format.
    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

    if src_ip and ipv4_pattern.match(src_ip):
        # Filter out common local and broadcast IPs.
        # We only care about external or potentially rogue internal IPs.
        if src_ip not in ["127.0.0.1", "0.0.0.0", "localhost", "::1", "255.255.255.255"]:
            
            # Create a STIX IPv4Address object representing the source of the attack.
            src_ip_obj = IPv4Address(
                id=f"ipv4-addr--{uuid.uuid4()}",
                value=src_ip
            )
            stix_objects.append(src_ip_obj)

            # Create a STIX Relationship indicating the Source IP targets the System Identity.
            rel_ip_id = Relationship(
                id=f"relationship--{uuid.uuid4()}",
                relationship_type="targets",
                source_ref=src_ip_obj.id,
                target_ref=identity.id
            )
            stix_objects.append(rel_ip_id)
            
            # Create a STIX Relationship indicating the Source IP triggered the security event.
            rel_ip_obs = Relationship(
                id=f"relationship--{uuid.uuid4()}",
                relationship_type="indicates",
                source_ref=src_ip_obj.id,
                target_ref=observed_data.id
            )
            stix_objects.append(rel_ip_obs)

    # ------------------------------------------
    # STEP 6: RETURN THE STIX BUNDLE
    # ------------------------------------------
    # Package all generated STIX objects (Identities, Observables, Relationships) into a single Bundle.
    return Bundle(objects=stix_objects)

# Standard boilerplate for testing the module directly.
if __name__ == "__main__":
    pass 
