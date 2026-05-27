import os
import sys
import json
import time
import redis
from langchain_core.messages import SystemMessage, HumanMessage

# Подтягиваем наши настройки и состояние
from brain.state import IcedentAgentState
from brain.config import r_client, llm, ALERTS_QUEUE, TIME_WINDOW_SEC, ALERT_THRESHOLD

# Костыль для импорта из соседних папок (STIX)
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

from data_pipeline.STIX_conversion import convert_wazuh_to_stix




def check_trigger(ip: str, level: int) -> bool:
    """Логика умного триггера с использованием Redis"""
    if not ip:
        return False
        
    if level >= 10:
        print(f"🔥 Триггер сработал: Критический уровень алерта ({level}) для IP {ip}!")
        return True

    redis_key = f"alert_history:{ip}"
    current_time = time.time()
    
    r_client.zadd(redis_key, {str(current_time): current_time})
    r_client.zremrangebyscore(redis_key, 0, current_time - TIME_WINDOW_SEC)
    alert_count = r_client.zcard(redis_key)
    
    if alert_count >= ALERT_THRESHOLD:
        print(f"🔥 Триггер сработал: Накоплено {alert_count} алертов за 5 минут для IP {ip}!")
        r_client.delete(redis_key)
        return True
        
    return False




def extracting(state: IcedentAgentState):
    try:
        r_client.ping()
    except redis.exceptions.ConnectionError:
        return {"incedent": [], "messages": [], "escalate": False, "target_ip": ""}

    queue_name, raw_log_string = r_client.brpop(ALERTS_QUEUE)
    sample_log = json.loads(raw_log_string)
    log_data = json.loads(sample_log) if isinstance(sample_log, str) else sample_log

    raw_id = log_data.get("rule", {}).get("id", None)
    level = int(log_data.get("rule", {}).get("level", 0))
    raw_ip = log_data.get("agent", {}).get("ip", None)
        
    dedup_key = f"dedup:{raw_id}:{raw_ip}"
    is_new_alert = r_client.set(name=dedup_key, value="1", ex=30, nx=True)

    if is_new_alert:
        needs_escalation = check_trigger(raw_ip, level)
        bundle = convert_wazuh_to_stix(sample_log)
        stix_json = bundle.serialize(indent=4)
        
        prompt_content = f"Проанализируй алерт:\n{stix_json}"
            
        return {
            "incedent": [bundle], 
            "messages": [HumanMessage(content=prompt_content)],
            "escalate": needs_escalation,
            "target_ip": raw_ip
        }
    else:
        return {"incedent": [], "messages": [], "escalate": False, "target_ip": ""}

def analising(state: IcedentAgentState):
    # Если нужна эскалация, L1 молчит
    if state["escalate"]:
        return {"report": ""}

    base_prompt = (
        "Ты — старший аналитик SOC. Оцени алерт (True/False Positive). Не доверяй слепо уровню Wazuh.\n"
        "ВАЖНО: Злоумышленники часто используют легитимные команды и рутинные запросы "
        "(например, чтение системных файлов, базовые SQL-запросы) для разведки (Reconnaissance) и продвижения по сети (Lateral Movement).\n"
        "Всегда оценивай контекст! Если легитимная команда исходит от нетипичного IP-адреса, направлена на критическую зону (Internal_zone) "
        "или выглядит как попытка собрать информацию о системе — это часть атаки (True Positive).\n"
    )

    format_prompt = (
        "Твой ответ ДОЛЖЕН СТРОГО соответствовать шаблону:\n\n"
        "**Вердикт:** [True Positive или False Positive]\n"
        "**Уверенность:** [XX%]\n"
        "**Резюме инцидента:** [2-3 предложения, описывающие суть произошедшего]\n"
        "**Матрица MITRE ATT&CK:** [Тактика и техника]\n"
        "**Обоснование:** [3-4 предложения. Детально объясни логику: почему лог указывает на атаку или норму? Как это связано с топологией Neo4j? Упомяни конкретные данные из лога.]\n"
        "**Действие:** [Конкретный шаг для реагирования]"
    )

    sys_message = SystemMessage(content=base_prompt + format_prompt)
    messages_to_send = [sys_message] + state["messages"]
    
    start_time = time.time()
    response = llm.invoke(messages_to_send)
    end_time = time.time()
    
    print(f"⏱️ L1 Triage занял: {(end_time-start_time):.2f} сек.")
    print("-" * 50)
    
    return {"messages": [response], "report": response.content}