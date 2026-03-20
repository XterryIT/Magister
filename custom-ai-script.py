#!/var/ossec/framework/python/bin/pip3 python3
import sys
import json
import redis
import os

# --- CONFIGURATION ---
REDIS_HOST = "192.168.100.39" 
REDIS_PORT = 6379
REDIS_PASSWORD = "MyAdmin123"
QUEUE_NAME = "wazuh_raw_alerts"

# Кастомный лог-файл для дебага (Wazuh должен иметь права на запись сюда)
DEBUG_LOG_FILE = "/var/ossec/logs/custom_redis_integration.log"

def log_debug(message):
    """Вспомогательная функция для записи логов в файл, так как print() в Wazuh теряется."""
    try:
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(message + "\n")
    except Exception:
        pass # Если нет прав на запись, просто игнорируем

def main():
    if len(sys.argv) < 2:
        log_debug("ERROR: Wazuh не передал путь к файлу алерта (sys.argv[1] пуст).")
        return

    alert_file = sys.argv[1]
    
    try:
        # 1. Читаем сырой алерт от Wazuh
        with open(alert_file, 'r', encoding="utf-8") as f:
            alert_data = json.load(f)

        # Пишем в наш дебаг-лог, чтобы видеть, что именно мы поймали
        log_debug("--- NEW ALERT TRIGGERED ---")
        log_debug(f"Alert file path: {alert_file}")
        
        # 2. Подключаемся к Redis на Mac Mini
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
           # password=REDIS_PASSWORD,
            socket_timeout=5,
            decode_responses=True # Автоматически декодирует байты в строки
        )

        # 3. Отправляем JSON в очередь
        r.lpush(QUEUE_NAME, json.dumps(alert_data))
        log_debug("SUCCESS: Алерт успешно отправлен в очередь Redis.\n")
        
    except Exception as e:
        # Теперь любая ошибка (нет коннекта, нет файла) будет записана в лог
        log_debug(f"INTEGRATION ERROR: {str(e)}\n")

if __name__ == "__main__":
    main()