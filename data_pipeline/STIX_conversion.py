import redis
import json
import re
from datetime import datetime
from stix2 import Identity, IPv4Address, URL, Indicator, Relationship, Bundle


ALERTS = 'wazuh_raw_alerts'

import json
import re
from datetime import datetime, timezone
from stix2 import (
    Identity, 
    IPv4Address, 
    UserAccount, 
    ObservedData, 
    Relationship, 
    Bundle, 
    File, 
    URL
)

def format_stix_timestamp(raw_time):
    """
    [ИЗ ТВОЕГО СКРИПТА]: Форматирование времени Wazuh в стандарт STIX (UTC)
    """
    if raw_time:
        return raw_time.replace("+0000", "Z")
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def convert_wazuh_to_stix(raw_log_json):
    """
    Универсальный конвертер JSON Wazuh -> STIX 2.1 Bundle
    Поддерживает: Сетевые атаки, Syscheck (файлы), Nginx (Web), MySQL, FTP.
    """
    if isinstance(raw_log_json, str):
        try:
            log_data = json.loads(raw_log_json)
        except json.JSONDecodeError:
            print("Ошибка: Невалидный JSON")
            return None
    else:
        log_data = raw_log_json

    stix_objects = []

    # --- 1. ИЗВЛЕЧЕНИЕ ДАННЫХ ИЗ WAZUH ---
    agent_name = log_data.get("agent", {}).get("name", "Unknown_Agent")
    agent_ip = log_data.get("agent", {}).get("ip")
    
    data_block = log_data.get("data", {})
    src_ip = data_block.get("srcip")
    dst_user = data_block.get("dstuser") or data_block.get("uid")
    
    rule_id = log_data.get("rule", {}).get("id", "0")
    rule_desc = log_data.get("rule", {}).get("description", "Unknown Alert")
    rule_level = log_data.get("rule", {}).get("level", 0)
    full_log = log_data.get("full_log", "")
    stix_time = format_stix_timestamp(log_data.get("timestamp"))

    # --- 2. БАЗОВЫЕ ОБЪЕКТЫ (SCO & SDO) ---
    
    # [ИЗ ТВОЕГО СКРИПТА]: Создаем Identity (Узел инфраструктуры)
    target_identity = None
    if agent_name:
        target_identity = Identity(
            name=f"Wazuh Agent: {agent_name}",
            identity_class="system",
            description="Compromised or targeted internal system"
        )
        stix_objects.append(target_identity)

    target_ip_obj = None
    if agent_ip:
        target_ip_obj = IPv4Address(value=agent_ip)
        stix_objects.append(target_ip_obj)

    src_ip_obj = None
    if src_ip:
        src_ip_obj = IPv4Address(value=src_ip)
        stix_objects.append(src_ip_obj)

    user_obj = None
    if dst_user:
        user_obj = UserAccount(account_login=dst_user)
        stix_objects.append(user_obj)

    # --- 3. ДИНАМИЧЕСКАЯ МАРШРУТИЗАЦИЯ (Файлы, Web, Базы данных) ---
    file_obj = None
    target_url_obj = None

    # Сценарий: Работа с файлами (Syscheck) или FTP
    if "syscheck" in log_data or "url" in data_block and "DOWNLOAD" in data_block.get("status", ""):
        syscheck = log_data.get("syscheck", {})
        # Путь может быть в syscheck или в data.url (для FTP скачиваний)
        file_path = syscheck.get("path") or data_block.get("url", "unknown_file")
        file_hashes = {}
        
        if "sha256_after" in syscheck:
            file_hashes["SHA-256"] = syscheck["sha256_after"]
        elif "md5_after" in syscheck:
            file_hashes["MD5"] = syscheck["md5_after"]

        file_obj = File(
            name=file_path.split("/")[-1],
            hashes=file_hashes if file_hashes else None,
            allow_custom=True,
            x_file_path=file_path # Сохраняем полный путь для контекста ИИ
        )
        stix_objects.append(file_obj)

    # Сценарий: Веб-запросы (Nginx) - используем гибридный поиск URL
        extracted_url = data_block.get("url")
        if not extracted_url:
            # [ИЗ ТВОЕГО СКРИПТА]: Запасной план (fallback) через регулярное выражение
            url_match = re.search(r'(?:GET|POST|PUT|DELETE)\s+(/\S+)', full_log)
            extracted_url = url_match.group(1) if url_match else None

        if extracted_url and not file_obj: # Игнорируем, если url это скачанный файл по FTP
            target_url_obj = URL(value=f"http://{agent_ip or 'localhost'}{extracted_url}")
            stix_objects.append(target_url_obj)

    # --- 4. ПОСТРОЕНИЕ ГРАФА СВЯЗЕЙ (Relationships для Neo4j) ---
    
    # [ИЗ ТВОЕГО СКРИПТА]: Агент находится на конкретном IP
    if target_identity and target_ip_obj:
        stix_objects.append(Relationship(
            source_ref=target_identity.id,
            target_ref=target_ip_obj.id,
            relationship_type="located-at"
        ))

    # Атакующий подключается к жертве (например, SSH или база данных)
    if src_ip_obj and target_ip_obj:
        stix_objects.append(Relationship(
            source_ref=src_ip_obj.id,
            target_ref=target_ip_obj.id,
            relationship_type="communicates-with"
        ))

    # Атакующий использует учетку
    if src_ip_obj and user_obj:
        stix_objects.append(Relationship(
            source_ref=src_ip_obj.id,
            target_ref=user_obj.id,
            relationship_type="uses"
        ))

    # Атакующий обращается к вредоносному URL (Web Attack)
    if src_ip_obj and target_url_obj:
        stix_objects.append(Relationship(
            source_ref=src_ip_obj.id,
            target_ref=target_url_obj.id,
            relationship_type="requests"
        ))

    # Жертва содержит скомпрометированный файл
    if target_identity and file_obj:
        stix_objects.append(Relationship(
            source_ref=target_identity.id,
            target_ref=file_obj.id,
            relationship_type="hosts"
        ))

    # --- 5. СОБЫТИЕ АЛЕРТА (ObservedData) ---
    sco_refs = [
        obj.id for obj in stix_objects 
        if hasattr(obj, 'id') and obj.type not in ['identity', 'relationship', 'indicator']
    ]
    
    if sco_refs:
        # ДОСТАЕМ "МЯСО" для передачи в агрегатор
        extracted_path = log_data.get("syscheck", {}).get("path", "")
        extracted_data = data_block.get("data", "") # В Wazuh тут часто лежат запросы MySQL
        
        # Упаковываем весь контекст Wazuh внутрь наблюдаемого события
        observed_event = ObservedData(
            first_observed=stix_time,
            last_observed=stix_time,
            number_observed=1,
            object_refs=sco_refs,
            allow_custom=True,
            x_wazuh_rule_id=rule_id,
            x_wazuh_rule_desc=rule_desc,
            x_wazuh_rule_level=rule_level,
            # Передаем извлеченные детали:
            x_wazuh_syscheck_path=extracted_path,
            x_wazuh_data=extracted_data,
            x_wazuh_full_log=full_log
        )
        stix_objects.append(observed_event)

    # --- 6. УПАКОВКА В BUNDLE ---
    if stix_objects:
        # Обязательно разрешаем кастомные поля (allow_custom=True) при упаковке бандла
        bundle = Bundle(objects=stix_objects, allow_custom=True)
        return bundle
    return None

# # --- TESTING ---
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




