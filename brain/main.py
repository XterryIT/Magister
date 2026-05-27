import os
import sys
import time
from langgraph.graph import StateGraph, START, END

# --- МАГИЯ ДЛЯ ПРАВИЛЬНЫХ ИМПОРТОВ ---
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)
# -------------------------------------

# Теперь Python "видит" папку Magister и без проблем импортирует из brain
from brain.state import IcedentAgentState
from brain.nodes import extracting, analising

# СБОРКА ГРАФА
builder = StateGraph(IcedentAgentState)
builder.add_node('extracting', extracting)
builder.add_node('analising', analising)

builder.add_edge(START, "extracting")
builder.add_edge("extracting", "analising")
builder.add_edge("analising", END)

graph = builder.compile()

if __name__ == "__main__":
    print("🤖 ИИ-Аналитик L1 запущен!")
    print("⏳ Ожидание алертов...")
    print("=" * 50)

    while True:
        try:
            # Очищаем память перед каждым новым алертом
            initial_state = {"incedent": [], "messages": [], "report": "", "escalate": False, "target_ip": ""}
            final_state = graph.invoke(initial_state, {"recursion_limit": 5})

            # Логика Умного Триггера
            if final_state.get("escalate"):
                print("\n" + "❗"*25)
                print(f"🚨 ВНИМАНИЕ: ЭСКАЛАЦИЯ НА УРОВЕНЬ L2 ДЛЯ IP {final_state['target_ip']}!")
                print("Здесь в будущем запустится Сборщик STIX и многоагентное расследование.")
                print("❗"*25 + "\n")
            
            # Логика обычного вывода
            elif final_state.get("report"):
                print("\n=== БЫСТРЫЙ L1 ОТЧЕТ ===")
                print(final_state["report"])
                print("=" * 50)
            
            print("⏳ Ожидание следующего алерта...")
            
        except KeyboardInterrupt:
            print("\n🛑 Остановлено.")
            break
        except Exception as e:
            print(f"\n❌ Ошибка: {e}")
            time.sleep(5)