import redis
from langchain_ollama import ChatOllama

# Настройки триггера
ALERTS_QUEUE = 'wazuh_raw_alerts'
TIME_WINDOW_SEC = 300  # 5 минут
ALERT_THRESHOLD = 4    # 4 алерта

# Подключение к Redis
r_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Инициализация LLM (Модель для L1 Triage)
llm = ChatOllama(
    model="qwen3.5:4b", 
    validate_model_on_init=True,
    temperature=0, 
)