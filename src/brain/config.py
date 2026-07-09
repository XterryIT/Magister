import os
import redis
from langchain_ollama import ChatOllama
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

# Load environment variables (fallback to defaults if .env not present)
ALERTS_QUEUE = os.getenv('ALERTS_QUEUE', 'wazuh_raw_alerts')
HISTORY_WINDOW_SEC = int(os.getenv('HISTORY_WINDOW_SEC', 900))
ALERT_THRESHOLD = int(os.getenv('ALERT_THRESHOLD', 4))
USE_NEO4J = os.getenv('USE_NEO4J', 'False').lower() in ('true', '1', 't')

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)

# Initialize Redis client
r_client = redis.Redis(
    host=REDIS_HOST, 
    port=REDIS_PORT, 
    password=REDIS_PASSWORD,
    decode_responses=True
)

# Initialize LLM
OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
MODEL_NAME = os.getenv('MODEL_NAME', 'llama3.1:8b')

llm = ChatOllama(
    base_url=OLLAMA_BASE_URL,
    model=MODEL_NAME,
    validate_model_on_init=True,
    temperature=0,
)