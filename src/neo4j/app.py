import os
from dotenv import load_dotenv
load_dotenv()


from neo4j import GraphDatabase

from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "password")

def create_topology():
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        with driver.session() as session:
            # Очищаем базу перед созданием новой карты
            session.run("MATCH (n) DETACH DELETE n")

            query = """
            // 1. Создаем сетевые зоны
            CREATE (ext:Zone {name: 'External_zone', description: 'Зона, смотрящая в интернет (DMZ)'})
            CREATE (int:Zone {name: 'Internal_zone', description: 'Изолированная внутренняя сеть'})

            // 2. Создаем серверы (Агенты Wazuh)
            CREATE (vm1:Server {name: 'VM1', ip: '172.16.1.4', os: 'Ubuntu'})
            CREATE (vm2:Server {name: 'VM2', ip: '172.16.1.5', os: 'Ubuntu'})

            // 3. Создаем сервисы на серверах
            CREATE (nginx:Service {name: 'Nginx', port: 80})
            CREATE (django:Service {name: 'Juice Shop', port: 8000})
            CREATE (redis:Service {name: 'Redis', port: 6379})
            CREATE (mysql:Service {name: 'MySQL', port: 3306})
            CREATE (ftp:Service {name: 'vsftpd', port: 21})

            // 4. Создаем пользователей (Учетные записи)
            CREATE (u1:User {name: 'user1', role: 'Administrator', privileges: 'unrestricted'})
            CREATE (u2:User {name: 'user2', role: 'Administrator', privileges: 'unrestricted'})

            // 5. Строим связи инфраструктуры (Что где находится и работает)
            CREATE (vm1)-[:BELONGS_TO]->(ext)
            CREATE (vm2)-[:BELONGS_TO]->(int)
            
            CREATE (nginx)-[:RUNS_ON]->(vm1)
            CREATE (django)-[:RUNS_ON]->(vm1)
            
            CREATE (redis)-[:RUNS_ON]->(vm2)
            CREATE (mysql)-[:RUNS_ON]->(vm2)
            CREATE (ftp)-[:RUNS_ON]->(vm2)

            // 6. Строим связи для пользователей (Локальный доступ и права)
            CREATE (u1)-[:HAS_ACCOUNT_ON]->(vm1)
            CREATE (u2)-[:HAS_ACCOUNT_ON]->(vm2)

            // 7. Реализация свободного перемещения (Межсистемный доступ без ограничений)
            CREATE (u1)-[:CAN_ACCESS]->(vm2)
            CREATE (u2)-[:CAN_ACCESS]->(vm1)

            // 8. Правила сетевого доступа для сервисов
            CREATE (ext)-[:CAN_ROUT_TO]->(int)
            CREATE (nginx)-[:COMMUNICATES_WITH]->(django)
            CREATE (django)-[:COMMUNICATES_WITH]->(mysql)
            CREATE (django)-[:COMMUNICATES_WITH]->(redis)
            """
            session.run(query)
            print("Топология сети, пользователи и права доступа успешно загружены в Neo4j!")

if __name__ == "__main__":
    create_topology()