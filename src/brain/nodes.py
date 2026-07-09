"""
Contains the execution nodes for the LangGraph agents.
Each function represents a distinct step (or 'node') in the AI reasoning graph.
"""
import json                                         
import time                                        
import redis                                       
from langchain_core.messages import SystemMessage, HumanMessage 

# Import global configurations and clients established in config.py
from src.brain.config import r_client, llm, ALERTS_QUEUE, ALERT_THRESHOLD, HISTORY_WINDOW_SEC, USE_NEO4J
# Import the typed dictionary that defines the state passed between nodes.
from src.brain.state import IncidentAgentState
# Import the Neo4j querying tool for L3 Judge context.
from src.brain.tools import check_network_topology
# Import the module responsible for converting raw Wazuh alerts into standard STIX format.
from src.data_pipeline.STIX_conversion import convert_wazuh_to_stix

def extracting(state: IncidentAgentState):
    """
    Extracts alerts from the Redis queue, performs deduplication, saves them to a time-based archive,
    and determines if the current batch of alerts meets the threshold for escalation.
    """
    try:
        # Check if the Redis server is reachable before proceeding.
        r_client.ping()
    except redis.exceptions.ConnectionError:
        print("[ERROR] Redis connection failed!")
        # If Redis is down, return an empty state to prevent the graph from crashing.
        return {"incident": [], "messages": [], "escalate": False, "target_ip": ""}

    print("\n[SYSTEM] Extracting all available alerts from queue...")
    start_time = time.time() # Start a timer to track extraction performance.

    raw_logs = []
    # Continuously poll the Redis queue until it is empty.
    while True:
        # brpop blocks for up to 3 seconds waiting for a new item.
        item = r_client.brpop(ALERTS_QUEUE, timeout=3)
        if item:
            # item is a tuple: (queue_name, data). We append the raw JSON data to our list.
            raw_logs.append(item[1])
        else:
            # If item is None, the queue is empty, so we break the loop.
            break
            
    # If no logs were found, exit the node early without escalating.
    if not raw_logs:
        print("[EXTRACT] Queue is empty. No alerts to process.")
        return {"incident": [], "messages": [], "escalate": False, "target_ip": "UNKNOWN_IP"}
        
    duration_time = time.time() - start_time
    print(f"[EXTRACT] Pulled a batch of {len(raw_logs)} alerts from queue in {duration_time:.2f} s.")

    unique_alerts = []
    needs_escalation = False
    escalated_ips = set() # A set to track all unique IP addresses involved in this batch.

    # Iterate through every raw log pulled from the queue.
    for log_str in raw_logs:
        # Parse the JSON string into a Python dictionary.
        # Sometimes Wazuh logs are double-encoded, so we handle that with an inline conditional.
        sample_log = json.loads(log_str)
        log_data = json.loads(sample_log) if isinstance(sample_log, str) else sample_log

        # Safely extract key metadata using .get() to prevent KeyError exceptions.
        raw_id = log_data.get("rule", {}).get("id", "UNKNOWN_RULE")
        level = int(log_data.get("rule", {}).get("level", 0))
        raw_ip = log_data.get("agent", {}).get("ip", "UNKNOWN_IP")
        src_ip = log_data.get("data", {}).get("srcip")
        
        # If the alert has a valid agent IP, archive it for the Context Aggregator.
        if raw_ip != "UNKNOWN_IP":
            history_key = f"logs_archive:{raw_ip}"
            current_time = time.time()
            
            # Use Redis Sorted Sets (zadd) to store the log with its timestamp as the score.
            r_client.zadd(history_key, {json.dumps(log_data): current_time})
            # Immediately remove any logs older than the HISTORY_WINDOW_SEC to conserve memory.
            r_client.zremrangebyscore(history_key, 0, current_time - HISTORY_WINDOW_SEC)

            # Add the agent IP to our set of involved IPs.
            escalated_ips.add(raw_ip)
            # If a source IP is provided and is not a local loopback address, add it too.
            if src_ip and src_ip not in ["127.0.0.1", "0.0.0.0", "localhost", "::1"]:
                escalated_ips.add(src_ip)

        # ESCALATION RULE 1: If the Wazuh rule level is 10 or higher, escalate immediately.
        if level >= 10:
            print(f"[TRIGGER] CRITICAL EVENT DETECTED: Level {level} for IP {raw_ip}!")
            needs_escalation = True

        # Create a unique deduplication key based on the rule ID and the agent IP.
        dedup_key = f"dedup:{raw_id}:{raw_ip}"
        
        # Try to set the key in Redis with a 5-minute (300s) expiration.
        # nx=True means it will only set the key if it does NOT already exist.
        is_new_alert = r_client.set(name=dedup_key, value="1", ex=300, nx=True)

        # If the key was successfully set, this is a new, unique alert.
        if is_new_alert:
            unique_alerts.append(log_data)

    # ESCALATION RULE 2: If the number of unique alerts in this batch exceeds the threshold, escalate.
    if len(unique_alerts) >= ALERT_THRESHOLD:
        print(f"[TRIGGER] MASSIVE THREAT: {len(unique_alerts)} unique alerts breached the threshold!")
        needs_escalation = True

    # Prepare the target IP string to pass to the next nodes.
    if needs_escalation:
        # Join all unique IPs into a comma-separated string.
        final_ip_str = ", ".join(list(escalated_ips))
        print(f"[EXTRACT] COMPLEX INCIDENT ESCALATED FOR IPs: {final_ip_str}")
    else:
        # If no escalation, just grab the first IP we saw, or default to UNKNOWN_IP.
        final_ip_str = unique_alerts[0].get("agent", {}).get("ip", "UNKNOWN_IP") if unique_alerts else "UNKNOWN_IP"
        print(f"[EXTRACT] Batch processed. No escalation needed ({len(unique_alerts)} unique alerts).")

    # Return the updated state dictionary.
    return {
        "incident": [], 
        "messages": [HumanMessage(content="Logs collected.")],
        "escalate": needs_escalation,
        "target_ip": final_ip_str
    }

def summarize_stix_bundle(bundle_objects):
    """
    Transforms an array of STIX objects into a compressed summary format.
    This groups similar events together and removes noise (like unique timestamps),
    preventing the LLM's context window from overflowing during severe attacks.
    """
    event_counter = {} # Dictionary to count occurrences of specific events.
    rel_counter = {}   # Dictionary to count occurrences of specific relationships.
    entities = set()   # Set to store unique entities (IPs, users, files).

    # STEP 1: Build a resolution dictionary to map cryptic UUIDs to human-readable values.
    id_resolver = {}
    for obj in bundle_objects:
        obj_dict = dict(obj)
        obj_type = obj_dict.get("type", "unknown")
        obj_id = obj_dict.get("id", "unknown")
        
        # Map IPv4 addresses
        if obj_type == "ipv4-addr":
            ip_val = obj_dict.get("value", "Unknown IP")
            id_resolver[obj_id] = ip_val
            entities.add(f"[IP ADDRESS] {ip_val}")
            
        # Map User Accounts
        elif obj_type == "user-account":
            user_val = obj_dict.get("account_login", "Unknown User")
            id_resolver[obj_id] = user_val
            entities.add(f"[USER ACCOUNT] {user_val}")
            
        # Map Files
        elif obj_type == "file":
            file_val = obj_dict.get("name", "Unknown File")
            id_resolver[obj_id] = file_val
            entities.add(f"[FILE COMPROMISED] {file_val}")
            
        # Map System Identities
        elif obj_type == "identity":
            name_val = obj_dict.get("name", "Unknown System")
            id_resolver[obj_id] = name_val

    # STEP 2: Process the actual events and relationships, substituting UUIDs with resolved names.
    for obj in bundle_objects:
        obj_dict = dict(obj)
        obj_type = obj_dict.get("type", "unknown")
        
        # Process alerts (observed-data)
        if obj_type == "observed-data":
            rule_desc = obj_dict.get("x_wazuh_rule_desc", "Unknown Rule")
            level = obj_dict.get("x_wazuh_rule_level", 0)
            
            context_parts = []
            
            # Extract file paths from syscheck events, if available.
            syscheck_path = obj_dict.get("x_wazuh_syscheck_path", "")
            if syscheck_path:
                context_parts.append(f"File: {syscheck_path}")
                
            # Extract command execution or raw data, if available.
            wazuh_data = obj_dict.get("x_wazuh_data", "")
            if wazuh_data:
                context_parts.append(f"Data: {wazuh_data}")

            # Combine the extracted context parts.
            context_snippet = " | ".join(context_parts)
            
            # Format the event signature for counting.
            if context_snippet:
                event_key = f"[EVENT] Lvl: {level} | Desc: {rule_desc} | Context: {context_snippet}"
            else:
                event_key = f"[EVENT] Lvl: {level} | Desc: {rule_desc}"
                
            # Increment the counter for this specific event signature.
            event_counter[event_key] = event_counter.get(event_key, 0) + 1
            
        # Process relationships between entities and events.
        elif obj_type == "relationship":
            rel_type = obj_dict.get("relationship_type", "")
            source_id = obj_dict.get("source_ref", "")
            target_id = obj_dict.get("target_ref", "")
            
            # Resolve the source and target UUIDs. If they fail to resolve, just take the prefix of the UUID.
            source_name = id_resolver.get(source_id, source_id.split("--")[0])
            target_name = id_resolver.get(target_id, target_id.split("--")[0])
            
            # Format the relationship signature for counting.
            rel_key = f"[RELATIONSHIP] {source_name} -> {rel_type} -> {target_name}"
            rel_counter[rel_key] = rel_counter.get(rel_key, 0) + 1

    # STEP 3: Assemble the final compressed text representation of the incident.
    summary_lines = ["--- INVOLVED ENTITIES (THE 'WHO' & 'WHERE') ---"]
    summary_lines.extend(list(entities))
    
    summary_lines.append("\n--- INCIDENT TIMELINE (THE 'WHAT') ---")
    for event_str, count in event_counter.items():
        # Append the occurrence count if the event happened more than once.
        summary_lines.append(f"{event_str} (Occurred {count} times)" if count > 1 else event_str)
            
    summary_lines.append("\n--- ATTACK GRAPH (HOW THEY CONNECT) ---")
    for rel_str, count in rel_counter.items():
        summary_lines.append(f"{rel_str} (x{count})" if count > 1 else rel_str)
            
    # Join everything into a single string. If it's too short, assume it failed to extract meaningful data.
    final_stix_text = "\n".join(summary_lines) if len(summary_lines) > 3 else "No meaningful STIX objects extracted."
    
    # Implement a hard limit on string length to protect system memory and LLM context limits.
    if len(final_stix_text) > 3500:
        final_stix_text = final_stix_text[:3500] + "\n... [TRUNCATED DUE TO SYSTEM CONSTRAINTS]"
    
    # Print the output for debugging purposes.
    print("#"*50)
    print("#"*50)
    print(final_stix_text)
    print("#"*50)
    print("#"*50)

    return final_stix_text

def context_aggregator(state: IncidentAgentState):
    """
    Builds the historical context for the target IPs by fetching all previous alerts 
    from the Redis archive and converting them into a unified STIX bundle.
    """
    target_ips_str = state.get("target_ip", "")
    print(f"\n[L2-AGGREGATOR] Building historical context for involved hosts: [{target_ips_str}]...")
    
    # Split the target IP string into a list of individual IPs.
    ip_list = [ip.strip() for ip in target_ips_str.split(",") if ip.strip()]
    master_objects = []
    
    # Iterate through each involved IP to pull its historical logs.
    for ip in ip_list:
        history_key = f"logs_archive:{ip}"
        # Retrieve all logs stored in the sorted set for this IP (from index 0 to -1).
        raw_logs = r_client.zrange(history_key, 0, -1)
        
        for raw_log_str in raw_logs:
            try:
                # Parse the log and convert it to STIX objects.
                log_dict = json.loads(raw_log_str)
                bundle = convert_wazuh_to_stix(log_dict)
                # Append the generated STIX objects to our master list.
                master_objects.extend(bundle.objects)
            except Exception:
                # If conversion fails for a specific log, simply skip it.
                continue
            
    seen_ids = set()
    unique_objects = []
    # Maintain a set of all discovered IPs, starting with the original targets.
    all_discovered_ips = set(ip_list) 

    # Deduplicate the STIX objects based on their UUIDs to prevent redundant data.
    for obj in master_objects:
        obj_id = obj.get("id")
        if obj_id not in seen_ids:
            seen_ids.add(obj_id)
            unique_objects.append(obj)
            
        # Actively scan the STIX objects to discover any new IPs that were involved.
        if obj.get("type") == "ipv4-addr":
            ip_value = obj.get("value")
            # If a new IP is found (and is not a localhost address), add it to the set.
            if ip_value and ip_value not in ["127.0.0.1", "0.0.0.0", "localhost", "::1"]:
                all_discovered_ips.add(ip_value)
    
    # Compress the unique STIX objects into a readable text summary.
    compressed_stix = summarize_stix_bundle(unique_objects)
    
    # Update the target IP string to include any newly discovered IPs.
    final_ips_str = ", ".join(list(all_discovered_ips))
    
    print(f"[L2-AGGREGATOR] Multi-Host STIX bundle created ({len(compressed_stix)} chars).")
    
    # Return the generated STIX bundle and the comprehensive list of involved IPs.
    return {"stix_bundle": compressed_stix, "target_ip": final_ips_str}

def hunter_agent(state: IncidentAgentState):
    """
    Acts as the L2 SOC Threat Hunter. Its job is to assume the incident is a real attack,
    analyze the STIX bundle, and attempt to build a coherent attack vector (Kill Chain).
    """
    print("  ├── [L2-HUNTER] Prosecuting the incident (Building attack vector)...")
    
    # Provide the LLM with a highly specific system prompt outlining its persona and required output format.
    hunter_prompt = (
        "You are an L2 SOC Threat Hunter. Your goal is to prove this STIX bundle represents a real cyber attack.\n"
        "INSTRUCTIONS:\n"
        "1. Analyze the Kill Chain, focusing on how the attacker moved through the system (Initial Access, Execution, Privilege Escalation, Exfiltration).\n"
        "2. Be analytical and professional. Avoid redundant phrasing.\n"
        "3. Output EXACTLY in the format below.\n\n"
        "**ANALYSIS:**\n"
        "[Write a logical paragraph of 3-6 sentences explaining the sequence of events. Describe how the specific IPs, files, and relationships in the STIX data demonstrate an attack path.]\n\n"
        "**HUNTER REPORT:**\n"
        "* **Attack Vector:** [1-4 sentences summarizing the core attack method]\n"
        "* **Critical Evidence:**\n"
        "  - [Key Fact 1: Mention specific IP, Rule Level, or Compromised File]\n"
        "  - [Key Fact 2: Mention lateral movement or frequency of anomalies]\n"
        "  - [Key Fact 3: Mention data exfiltration or persistence attempts]\n"
        "* **Conclusion:** [A definitive statement confirming the system is compromised]"
        "Do not generate any extra text after the Conclusion."
    )
    # Wrap the prompts in LangChain message schemas.
    sys_message = SystemMessage(content=hunter_prompt)
    stix_msg = HumanMessage(content=f"STIX BUNDLE:\n{state.get('stix_bundle', '')}")
    
    start_time = time.time()
    # Invoke the LLM with the prompt and the STIX data.
    response = llm.invoke([sys_message, stix_msg])
    thinking_time = time.time() - start_time

    # Print the output for visibility in the console.
    print("\n" + "-" * 60)
    print(f"   [L2-Hunter] AI thinking for: {thinking_time:.2f} sec.".center(60))
    print("  └── [L2-HUNTER] Answer:")
    print(response.content)
    print("-" * 60 + "\n")

    # Store the result in the 'hunter_report' field of the state.
    return {"hunter_report": response.content}

def skeptic_agent(state: IncidentAgentState):
    """
    Acts as the L2 SOC Validation Analyst. Its job is to look for False Positives,
    benign administrative activity, or misconfigurations that might explain the alerts.
    """
    print("  └── [L2-SKEPTIC] Defending the incident (Searching for False Positives)...")
    
    # Provide the LLM with instructions on how to identify benign activity.
    skeptic_prompt = (
        "You are an L2 SOC Validation Analyst. Your goal is to critically examine the STIX bundle and look for benign explanations (False Positives, admin activity, cron jobs).\n"
        "CRITICAL INSTRUCTIONS:\n"
        "1. Identify the Source: Where are the actions originating from? Are they internal (RFC 1918 IPs like 172.16.x.x) or external?\n"
        "2. Evaluate File Activity: Are the files related to 'audit', 'report', 'backup', 'status', or 'docker'? If so, they MIGHT be benign automated scripts, BUT ONLY IF they stay within internal zones.\n"
        "3. The Exfiltration Test: If there is evidence of data (like 'dump.csv' or '.bak') being moved to an External/Unknown IP, or accessed via unauthorized FTP/SSH, you CANNOT claim it is benign. You MUST acknowledge the threat (True Positive).\n"
        "4. Output EXACTLY in the format below:\n\n"
        "**ANALYSIS:**\n"
        "[Write 3-6 sentences. 1. Identify if the IPs are internal or external. 2. Explain if the file names suggest benign activity. 3. Assess if there is any indication of exfiltration or unauthorized access.]\n\n"
        "**SKEPTIC REPORT:**\n"
        "* **Reasonable Explanation:** [Summarize the benign scenario, or state 'No benign explanation found due to external access/exfiltration']\n"
        "* **Mitigating Factors:**\n"
        "  - [Fact 1: e.g., All IPs are internal]\n"
        "  - [Fact 2: e.g., File names indicate routine backups]\n"
        "* **Conclusion:** [State clearly if you think it is a False Positive or a True Positive]"
    )
    # Wrap the prompts in LangChain message schemas.
    sys_message = SystemMessage(content=skeptic_prompt)
    stix_msg = HumanMessage(content=f"STIX BUNDLE:\n{state.get('stix_bundle', '')}")
    
    start_time = time.time()
    # Invoke the LLM with the prompt and the STIX data.
    response = llm.invoke([sys_message, stix_msg])
    thinking_time = time.time() - start_time

    # Print the output for visibility in the console.
    print("\n" + "-" * 60)
    print(f"  [L2-SCEPTIC] AI thinking for: {thinking_time:.2f} sec.".center(60))
    print("  └── [L2-SKEPTIC] Answer:")
    print(response.content)
    print("-" * 60 + "\n")

    # Store the result in the 'skeptic_report' field of the state.
    return {"skeptic_report": response.content}

def judge_agent(state: IncidentAgentState):
    """
    The L3 Judge agent is the final authority. It correlates the STIX data, the reports from the Hunter and Skeptic, 
    and the physical infrastructure context from Neo4j to render a final True Positive / False Positive verdict.
    """
    target_ip = state.get("target_ip")
    
    print(f"\n[L3-JUDGE] Requesting Neo4j context for IP {target_ip}...")
    
    # Conditionally execute the Neo4j query based on the global configuration flag.
    if USE_NEO4J:
        try:
            neo4j_result = check_network_topology(target_ip)
        except Exception as e:
            neo4j_result = f"Neo4j Python Error: {e}"
    else:
        print("[L3-JUDGE] Neo4j is DISABLED. Skipping graph query.")
        neo4j_result = "Neo4j is DISABLED. Topology data is unavailable."
        
    print("[L3-JUDGE] Context gathered. Generating final verdict...")

    # Construct a highly structured XML-style prompt. This heavily protects against prompt injection
    # and keeps the LLM focused on specific data blocks.
    context_prompt = f"""You are the Lead Incident Responder. Read the data below.

    <target_ip>
    {target_ip}
    </target_ip>

    <neo4j_topology_context>
    {neo4j_result}
    </neo4j_topology_context>

    <stix_bundle_data>
    {state.get('stix_bundle', '')}
    </stix_bundle_data>

    <sub_agents_reports>
    HUNTER AGENT:
    {state.get('hunter_report', '')}

    SKEPTIC AGENT:
    {state.get('skeptic_report', '')}
    </sub_agents_reports>
    """
    
    # The analytical framework guides the LLM on exactly how to evaluate the data,
    # specifically defining the criteria for identifying benign administration versus rogue hackers.
    final_prompt = (
        "You are the Lead SOC L3 Analyst. Your objective is to classify a complex cybersecurity incident by correlating the STIX attack timeline with the Neo4j infrastructure graph.\n\n"
        "ANALYTICAL FRAMEWORK (THINKING PROCESS):\n"
        "You must analyze the incident not as isolated events, but as a sequence of data flows and actor behaviors. Use the following logic:\n"
        "1. ACTOR LEGITIMACY: Analyze the IPs in the STIX data against the <neo4j_topology_context>.\n"
        "   - WARNING: If Neo4j returns actual data for an IP (e.g., 'Server: VM1', 'Zone: External_zone', 'Internal_zone'), this IP is a MANAGED LEGITIMATE ASSET. Do NOT confuse the name 'External_zone' with a rogue actor. It is just a managed DMZ.\n"
        "   - ONLY an IP that strictly returns 'No topology data found' is an UNKNOWN/ROGUE HACKER.\n"
        "2. DIRECTION OF INITIATION: Did the SSH/FTP sessions originate from a managed asset targeting another managed asset (typical of automated admin scripts)? Or did the session originate from a ROGUE HACKER targeting a managed asset (Ingress)?\n"
        "3. DATA LIFECYCLE & EXFILTRATION: Creating database dumps or archiving files in /tmp/ is common admin behavior. However, if a ROGUE HACKER authenticates to the system during or immediately after these files are created, it strongly implies Exfiltration.\n"
        "4. FALSE POSITIVE CRITERIA: If ALL IPs involved have known Neo4j topology data (Managed Assets), and the actions (DB queries, log reading, file creation) stay strictly between these known assets, deduce that this is BENIGN administrative automation.\n"
        "5. TRUE POSITIVE CRITERIA: If a ROGUE HACKER ('No topology data found') is present in the logs AND there is evidence of sensitive file creation/modification (DB dumps, config copies), deduce that this is a cyberattack with intent to exfiltrate.\n\n"
        "FORMAT RULES:\n"
        "- Do not generate conversational text.\n"
        "- You MUST strictly follow the structure below.\n\n"
        "Chain_of_Thought:\n"
        "- Phase 1 (Actor Analysis): [Identify all IPs. Map them to Neo4j. Explicitly state which are MANAGED ASSETS and which is the ROGUE HACKER. Remember: 'External_zone' means Managed Asset].\n"
        "- Phase 2 (Vector & Intent): [Analyze the direction of the actions. Who connected to whom? Is it internal lateral movement or an attack by a Rogue Hacker?]\n"
        "- Phase 3 (Data Flow): [Where did the sensitive files ultimately go? Were they accessed by the Rogue Hacker?]\n\n"
        "Verdict: [True Positive / False Positive]\n"
        "Confidence: [e.g., 95%]\n"
        "MITRE ATT&CK: [e.g., Exfiltration - T1041, Credential Access - T1003 / None]\n"
        "Context: [1-2 sentences summarizing the graph topology impact on your decision]\n"
        "Justification: [Max 2 sentences summarizing why it is an attack or benign automation]\n"
        "Action_Plan:\n"
        "[If True Positive, provide a precise 3-step response playbook referencing actual IPs and files:]\n"
        "1. Containment: [e.g., Block rogue IP <IP> on the external firewall]\n"
        "2. Eradication: [e.g., Delete malicious files like <file_name> and revoke compromised user sessions]\n"
        "3. Recovery: [e.g., Reset database passwords and audit SSH keys for <user>]\n"
        "[If False Positive, provide this exact playbook:]\n"
        "1. Close incident as False Positive.\n"
        "2. Tune Wazuh rules to whitelist benign automation scripts for the involved internal hosts."
    )
    
    # Package the prompts into the LangChain format.
    messages_to_pass = [
        SystemMessage(content=context_prompt),
        HumanMessage(content=final_prompt)
    ]
    
    start_time = time.time()
    # Invoke the LLM to generate the final verdict.
    response = llm.invoke(messages_to_pass) 

    print(f"[L3-JUDGE] Verdict reached in {(time.time()-start_time):.2f} sec.")
    
    # Store the final response inside the 'messages' array of the state, as this is the final output of the graph.
    return {"messages": [response]}
