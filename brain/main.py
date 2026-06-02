import os
import sys
import redis
import json
import time

from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from typing_extensions import TypedDict, Annotated
from langgraph.graph.message import add_messages
from langchain_ollama import ChatOllama
from langgraph.prebuilt import ToolNode, tools_condition
from langchain_core.tools import tool
from neo4j import GraphDatabase
from stix2 import Bundle

# Fix for module imports
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from data_pipeline.STIX_conversion import convert_wazuh_to_stix

# ==========================================
# GLOBAL CONFIGURATION
# ==========================================
ALERTS_QUEUE = 'wazuh_raw_alerts'
TIME_WINDOW_SEC = 300  
HISTORY_WINDOW_SEC = 900 
ALERT_THRESHOLD = 4

USE_NEO4J = True

r_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Expanded state to isolate agent reports and prevent ChatML template collisions
class IncidentAgentState(TypedDict):
    incedent: list
    messages: Annotated[list, add_messages]
    report: str
    escalate: bool     
    target_ip: str 
    stix_bundle: str     
    hunter_report: str   
    skeptic_report: str  

llm = ChatOllama(
    model="llama3.1:8b",
    validate_model_on_init=True,
    temperature=0,
)
# ==========================================
# NEO4J TOOL (SPATIAL CONTEXT)
# ==========================================

def check_network_topology(ip_addresses_str: str) -> str:
    """
    Returns network topology information for multiple IP addresses.
    """
    # Разбиваем входящую строку на чистые IP-адреса
    ips_to_check = [ip.strip(' "\'\n') for ip in ip_addresses_str.split(",") if ip.strip(' "\'\n')]
    
    print("\n" + "-" * 60)
    print(f"[L3-JUDGE -> NEO4J] AI requested topology for IPs: {ips_to_check}")
    
    URI = "bolt://localhost:7687"
    AUTH = ("neo4j", "password") # Убедись, что пароль твой
    
    combined_results = []
    
    try:
        with GraphDatabase.driver(URI, auth=AUTH) as driver:
            with driver.session(database="neo4j") as session:
                query = """
                MATCH (s:Server {ip: $ip})
                OPTIONAL MATCH (srv:Service)-[:RUNS_ON]->(s)
                OPTIONAL MATCH (s)-[:BELONGS_TO]->(z:Zone)
                RETURN s.name AS Server, z.name AS Zone, collect(srv.name) AS Services
                """
                
                # Делаем запрос в базу для каждого IP
                for clean_ip in ips_to_check:
                    result = session.run(query, ip=clean_ip)
                    data = result.single()
                    
                    if data and data["Server"]:
                        result_str = f"IP {clean_ip} -> Server: {data['Server']}, Zone: {data['Zone']}, Services: {', '.join(data['Services'])}"
                        combined_results.append(result_str)
                    else:
                        combined_results.append(f"IP {clean_ip} -> No topology data found.")
                        
    except Exception as e:
        error_msg = f"Neo4j Error: {str(e)}"
        print(f"[NEO4J] CRITICAL ERROR: {error_msg}")
        return error_msg

    final_output = "\n".join(combined_results)
    print(f"[NEO4J] Returning combined data:\n{final_output}")
    print("-" * 60)
    
    return final_output


# ==========================================
# STAGE 1: EXTRACT, BATCH AND TRIGGER
# ==========================================
def check_trigger(ip: str, level: int) -> bool:
    if not ip or ip == "UNKNOWN_IP":
        return False
    if level >= 10:
        print(f"[TRIGGER] CRITICAL: Alert level {level} for IP {ip}!")
        return True

    redis_key = f"alert_history:{ip}"
    current_time = time.time()
    r_client.zadd(redis_key, {str(current_time): current_time})
    r_client.zremrangebyscore(redis_key, 0, current_time - TIME_WINDOW_SEC)
    alert_count = r_client.zcard(redis_key)
    
    if alert_count >= ALERT_THRESHOLD:
        print(f"[TRIGGER] ESCALATION: Accumulated {alert_count}/{ALERT_THRESHOLD} alerts for IP {ip}!")
        r_client.delete(redis_key) 
        return True
    return False


def extrtacting(state: IncidentAgentState):
    try:
        r_client.ping()
    except redis.exceptions.ConnectionError:
        print("[ERROR] Redis connection failed!")
        return {"incedent": [], "messages": [], "escalate": False, "target_ip": ""}

    print("\n[SYSTEM] Extracting all available alerts from queue...")
    
    start_time = time.time()

    raw_logs = []
    while True:
        item = r_client.brpop(ALERTS_QUEUE, timeout=3)
        if item:
            raw_logs.append(item[1])
        else:
            break
            
    if not raw_logs:
        print("[EXTRACT] Queue is empty. No alerts to process.")
        return {"incedent": [], "messages": [], "escalate": False, "target_ip": "UNKNOWN_IP"}
        
    end_time = time.time()
    duration_time = end_time - start_time

    print(f"[EXTRACT] Pulled a batch of {len(raw_logs)} alerts from queue in {duration_time} s.")

    unique_alerts = []
    needs_escalation = False
    escalated_ips = set() # СОБИРАЕМ ВСЕ АТАКОВАННЫЕ IP В СПИСОК

    for log_str in raw_logs:
        sample_log = json.loads(log_str)
        log_data = json.loads(sample_log) if isinstance(sample_log, str) else sample_log

        raw_id = log_data.get("rule", {}).get("id", "UNKNOWN_RULE")
        level = int(log_data.get("rule", {}).get("level", 0))
        
        # 1. IP Агента Wazuh (VM1 или VM2)
        raw_ip = log_data.get("agent", {}).get("ip", "UNKNOWN_IP")
        
        # 2. IP Атакующего (Извлекаем Source IP из логов)
        src_ip = log_data.get("data", {}).get("srcip")
        
        if raw_ip != "UNKNOWN_IP":
            history_key = f"logs_archive:{raw_ip}"
            current_time = time.time()
            r_client.zadd(history_key, {json.dumps(log_data): current_time})
            r_client.zremrangebyscore(history_key, 0, current_time - HISTORY_WINDOW_SEC)

            # Если сработал триггер - добавляем IP в копилку
            if check_trigger(raw_ip, level):
                needs_escalation = True
                # Добавляем сервер-жертву
                escalated_ips.add(raw_ip)
                
                # КРИТИЧЕСКИЙ ФИКС: Добавляем IP хакера (если он есть) в запрос для Neo4j
                if src_ip and src_ip not in ["127.0.0.1", "0.0.0.0", "localhost", "::1"]:
                    escalated_ips.add(src_ip)

        dedup_key = f"dedup:{raw_id}:{raw_ip}"
        is_new_alert = r_client.set(name=dedup_key, value="1", ex=300, nx=True)

        if is_new_alert:
            unique_alerts.append(log_data)

    # Склеиваем все IP через запятую
    if needs_escalation:
        final_ip_str = ", ".join(list(escalated_ips))
        print(f"[EXTRACT] COMPLEX INCIDENT ESCALATED FOR IPs: {final_ip_str}")
    else:
        final_ip_str = unique_alerts[0].get("agent", {}).get("ip", "UNKNOWN_IP") if unique_alerts else "UNKNOWN_IP"

    return {
        "incedent": [], 
        "messages": [HumanMessage(content="Logs collected.")],
        "escalate": needs_escalation,
        "target_ip": final_ip_str
    }


# ==========================================
# STAGE 3: CONTEXT AGGREGATOR
# ==========================================
def summarize_stix_bundle(bundle_objects):
    """
    Преобразует массив объектов STIX в сжатый формат.
    Идеально группирует события, отсекая лишний шум (уникальные таймстемпы).
    """
    event_counter = {}
    rel_counter = {}
    entities = set() 

    # ШАГ 1: Построение словаря для расшифровки UUID в реальные значения
    id_resolver = {}
    for obj in bundle_objects:
        obj_dict = dict(obj)
        obj_type = obj_dict.get("type", "unknown")
        obj_id = obj_dict.get("id", "unknown")
        
        if obj_type == "ipv4-addr":
            ip_val = obj_dict.get("value", "Unknown IP")
            id_resolver[obj_id] = ip_val
            entities.add(f"[IP ADDRESS] {ip_val}")
            
        elif obj_type == "user-account":
            user_val = obj_dict.get("account_login", "Unknown User")
            id_resolver[obj_id] = user_val
            entities.add(f"[USER ACCOUNT] {user_val}")
            
        elif obj_type == "file":
            file_val = obj_dict.get("name", "Unknown File")
            id_resolver[obj_id] = file_val
            entities.add(f"[FILE COMPROMISED] {file_val}")
            
        elif obj_type == "identity":
            name_val = obj_dict.get("name", "Unknown System")
            id_resolver[obj_id] = name_val

    # ШАГ 2: Обработка событий и связей с подстановкой реальных значений
    for obj in bundle_objects:
        obj_dict = dict(obj)
        obj_type = obj_dict.get("type", "unknown")
        
        if obj_type == "observed-data":
            rule_desc = obj_dict.get("x_wazuh_rule_desc", "Unknown Rule")
            level = obj_dict.get("x_wazuh_rule_level", 0)
            
            context_parts = []
            
            # Достаем ТОЛЬКО самое важное "мясо" (без сырых логов)
            syscheck_path = obj_dict.get("x_wazuh_syscheck_path", "")
            if syscheck_path:
                context_parts.append(f"File: {syscheck_path}")
                
            wazuh_data = obj_dict.get("x_wazuh_data", "")
            if wazuh_data:
                context_parts.append(f"Data: {wazuh_data}")

            context_snippet = " | ".join(context_parts)
            
            if context_snippet:
                event_key = f"[EVENT] Lvl: {level} | Desc: {rule_desc} | Context: {context_snippet}"
            else:
                event_key = f"[EVENT] Lvl: {level} | Desc: {rule_desc}"
                
            event_counter[event_key] = event_counter.get(event_key, 0) + 1
            
        elif obj_type == "relationship":
            rel_type = obj_dict.get("relationship_type", "")
            source_id = obj_dict.get("source_ref", "")
            target_id = obj_dict.get("target_ref", "")
            
            source_name = id_resolver.get(source_id, source_id.split("--")[0])
            target_name = id_resolver.get(target_id, target_id.split("--")[0])
            
            rel_key = f"[RELATIONSHIP] {source_name} -> {rel_type} -> {target_name}"
            rel_counter[rel_key] = rel_counter.get(rel_key, 0) + 1

    # ШАГ 3: Формирование финального высокоплотного контекста
    summary_lines = ["--- INVOLVED ENTITIES (THE 'WHO' & 'WHERE') ---"]
    summary_lines.extend(list(entities))
    
    summary_lines.append("\n--- INCIDENT TIMELINE (THE 'WHAT') ---")
    for event_str, count in event_counter.items():
        summary_lines.append(f"{event_str} (Occurred {count} times)" if count > 1 else event_str)
            
    summary_lines.append("\n--- ATTACK GRAPH (HOW THEY CONNECT) ---")
    for rel_str, count in rel_counter.items():
        summary_lines.append(f"{rel_str} (x{count})" if count > 1 else rel_str)
            
    final_stix_text = "\n".join(summary_lines) if len(summary_lines) > 3 else "No meaningful STIX objects extracted."
    
    # Жесткий лимит для защиты памяти Mac
    if len(final_stix_text) > 3500:
        final_stix_text = final_stix_text[:3500] + "\n... [TRUNCATED DUE TO SYSTEM CONSTRAINTS]"
    
    print("#"*50)
    print("#"*50)
    print(final_stix_text)
    print("#"*50)
    print("#"*50)

    return final_stix_text

def context_aggregator(state: IncidentAgentState):
    target_ips_str = state.get("target_ip", "")
    print(f"\n[L2-AGGREGATOR] Building historical context for involved hosts: [{target_ips_str}]...")
    
    ip_list = [ip.strip() for ip in target_ips_str.split(",") if ip.strip()]
    master_objects = []
    
    for ip in ip_list:
        history_key = f"logs_archive:{ip}"
        raw_logs = r_client.zrange(history_key, 0, -1)
        
        for raw_log_str in raw_logs:
            try:
                log_dict = json.loads(raw_log_str)
                bundle = convert_wazuh_to_stix(log_dict)
                master_objects.extend(bundle.objects)
            except Exception:
                continue
            
    seen_ids = set()
    unique_objects = []
    all_discovered_ips = set(ip_list) # Сохраняем изначально переданные IP

    for obj in master_objects:
        obj_id = obj.get("id")
        if obj_id not in seen_ids:
            seen_ids.add(obj_id)
            unique_objects.append(obj)
            
        # КРИТИЧЕСКОЕ ИЗМЕНЕНИЕ: Собираем абсолютно все IP-адреса, засветившиеся в STIX
        if obj.get("type") == "ipv4-addr":
            ip_value = obj.get("value")
            if ip_value and ip_value not in ["127.0.0.1", "0.0.0.0", "localhost", "::1"]:
                all_discovered_ips.add(ip_value)
    
    compressed_stix = summarize_stix_bundle(unique_objects)
    
    # Обновляем target_ip, теперь в нем 100% будут все вовлеченные адреса
    final_ips_str = ", ".join(list(all_discovered_ips))
    
    print(f"[L2-AGGREGATOR] Multi-Host STIX bundle created ({len(compressed_stix)} chars).")
    return {"stix_bundle": compressed_stix, "target_ip": final_ips_str}

# ==========================================
# STAGE 4: AGENTS (HUNTER & SKEPTIC)
# ==========================================

def hunter_agent(state: IncidentAgentState):
    print("  ├── [L2-HUNTER] Prosecuting the incident (Building attack vector)...")
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
    sys_message = SystemMessage(content=hunter_prompt)
    stix_msg = HumanMessage(content=f"STIX BUNDLE:\n{state.get('stix_bundle', '')}")
    
    start_time = time.time()

    response = llm.invoke([sys_message, stix_msg])

    end_time = time.time()
    thinking_time = end_time - start_time

    print("\n" + "-" * 60)
    print(f"   [L2-Hunter] AI thinking for the: {thinking_time:.2f} sec.".center(60))
    print("  └── [L2-HUNTER] Answer:")
    print(response.content)
    print("-" * 60 + "\n")

    return {"hunter_report": response.content}

def skeptic_agent(state: IncidentAgentState):
    print("  └── [L2-SKEPTIC] Defending the incident (Searching for False Positives)...")
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
    sys_message = SystemMessage(content=skeptic_prompt)
    stix_msg = HumanMessage(content=f"STIX BUNDLE:\n{state.get('stix_bundle', '')}")
    
    start_time = time.time()

    response = llm.invoke([sys_message, stix_msg])

    end_time = time.time()
    thinking_time = end_time - start_time

    print("\n" + "-" * 60)
    print(f"  [L2-SCEPTIC] AI thinking for the: {thinking_time:.2f} sec.".center(60))
    print("  └── [L2-SKEPTIC] Answer:")
    print(response.content)
    print("-" * 60 + "\n")

    return {"skeptic_report": response.content}
# ==========================================
# STAGE 5: JUDGE (GRAPHRAG RESOLUTION)
# ==========================================
# ==========================================
# STAGE 5: JUDGE (ONE-PASS RESOLUTION)
# ==========================================
def judge_agent(state: IncidentAgentState):
    target_ip = state.get("target_ip")
    
    print(f"\n[L3-JUDGE] Requesting Neo4j context for IP {target_ip}...")
    
    # 1. УДОБНЫЙ ПЕРЕКЛЮЧАТЕЛЬ USE_NEO4J (Прямой вызов Python функции)
    if USE_NEO4J:
        try:
            neo4j_result = check_network_topology(target_ip)
        except Exception as e:
            neo4j_result = f"Neo4j Python Error: {e}"
    else:
        print("[L3-JUDGE] Neo4j is DISABLED. Skipping graph query.")
        neo4j_result = "Neo4j is DISABLED. Topology data is unavailable."
        
    print("[L3-JUDGE] Context gathered. Generating final verdict...")

    # 2. ИЗОЛИРОВАННЫЙ КОНТЕКСТ В XML (Защита от загрязнения)
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

    
    messages_to_pass = [
        SystemMessage(content=context_prompt),
        HumanMessage(content=final_prompt)
    ]
    
    start_time = time.time()
    # Делаем ЕДИНСТВЕННЫЙ вызов ИИ
    response = llm.invoke(messages_to_pass) 

    print(f"[L3-JUDGE] Verdict reached in {(time.time()-start_time):.2f} sec.")
    return {"messages": [response]}

# ==========================================
# МАРШРУТИЗАЦИЯ И СБОРКА ГРАФА
# ==========================================
def route_after_extracting(state: IncidentAgentState):
    if state.get("escalate") or state.get("messages"):
        return "context_aggregator"
    return "end_node"

builder = StateGraph(IncidentAgentState)
builder.add_node('extrtacting', extrtacting)
builder.add_node('context_aggregator', context_aggregator)
builder.add_node('hunter_agent', hunter_agent)
builder.add_node('skeptic_agent', skeptic_agent)
builder.add_node('judge_agent', judge_agent)
# Узел 'tools' полностью удален

builder.add_edge(START, "extrtacting")

builder.add_conditional_edges(
    "extrtacting", 
    route_after_extracting,
    {
        "context_aggregator": "context_aggregator",
        "end_node": END
    }
)

builder.add_edge("context_aggregator", "hunter_agent")
builder.add_edge("hunter_agent", "skeptic_agent")
builder.add_edge("skeptic_agent", "judge_agent")
# Судья теперь напрямую идет в конец
builder.add_edge("judge_agent", END)

graph = builder.compile()


if __name__ == "__main__":
    print("=" * 60)
    print("SOC AI:")
    print("=" * 60)

    total_start_time = time.time()

    try:
        # Инициализируем пустое состояние
        initial_state = {
            "incedent": [], 
            "messages": [], 
            "report": "", 
            "escalate": False, 
            "target_ip": "",
            "stix_bundle": "",
            "hunter_report": "",
            "skeptic_report": ""
        }
        
        # ЗАПУСКАЕМ ГРАФ ОДИН РАЗ
        final_state = graph.invoke(initial_state, {"recursion_limit": 15})
        
        total_end_time = time.time()
        total_duration = total_end_time - total_start_time

        # Если дошли до финала и есть сообщения, выводим вердикт Судьи
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
        # Всегда очищаем базу Redis перед выходом, чтобы следующий запуск был "чистым"
        print("\n[SYSTEM] Flushing Redis database to clear deduplication keys and archives...")
        try:
            r_client.flushdb()
            print("[SYSTEM] Cleanup successful. Goodbye!")
        except Exception as e:
            print(f"[ERROR] Cleanup failed: {e}")