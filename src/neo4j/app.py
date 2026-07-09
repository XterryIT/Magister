"""
Initializes and builds the Neo4j Graph Database with the predefined network topology.
This script provides the AI with a spatial understanding of the infrastructure it is protecting.
"""
import os
from dotenv import load_dotenv

# Load variables from .env to keep configurations out of source code.
load_dotenv()

# Import the official Neo4j Python driver
from neo4j import GraphDatabase

# Configuration for Neo4j. In a production environment, this should be pulled from os.getenv.
# We fall back to localhost defaults if the environment variables aren't set.
URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
AUTH = (os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", "password"))

def create_topology():
    """
    Connects to Neo4j, wipes any existing data, and builds a fresh, deterministic 
    network topology representing our testing environment.
    """
    # Establish a connection to the database. The context manager ('with') ensures the connection
    # is properly closed when the block finishes.
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        # Open a new database session.
        with driver.session() as session:
            
            # ------------------------------------------
            # RESET DATABASE
            # ------------------------------------------
            # Clear the database before creating a new map to prevent duplicate nodes.
            # MATCH (n) selects all nodes, DETACH removes all relationships, DELETE n removes the nodes.
            session.run("MATCH (n) DETACH DELETE n")

            # ------------------------------------------
            # BUILD NETWORK TOPOLOGY (CYPHER QUERY)
            # ------------------------------------------
            query = """
            // 1. Create Network Zones
            // Defines the logical separation of the network.
            CREATE (ext:Zone {name: 'External_zone', description: 'Internet facing zone (DMZ)'})
            CREATE (int:Zone {name: 'Internal_zone', description: 'Isolated internal network'})

            // 2. Create Servers (Wazuh Agents)
            // Defines the physical/virtual machines we are monitoring.
            CREATE (vm1:Server {name: 'VM1', ip: '172.16.1.4', os: 'Ubuntu'})
            CREATE (vm2:Server {name: 'VM2', ip: '172.16.1.5', os: 'Ubuntu'})

            // 3. Create Services on Servers
            // Defines the applications running on those machines.
            CREATE (nginx:Service {name: 'Nginx', port: 80})
            CREATE (django:Service {name: 'Juice Shop', port: 8000})
            CREATE (redis:Service {name: 'Redis', port: 6379})
            CREATE (mysql:Service {name: 'MySQL', port: 3306})
            CREATE (ftp:Service {name: 'vsftpd', port: 21})

            // 4. Create Users (Accounts)
            // Defines the legitimate user accounts on the system.
            CREATE (u1:User {name: 'user1', role: 'Administrator', privileges: 'unrestricted'})
            CREATE (u2:User {name: 'user2', role: 'Administrator', privileges: 'unrestricted'})

            // 5. Build Infrastructure Relationships
            // Connects the nodes: Which server is in which zone? Which service runs on which server?
            CREATE (vm1)-[:BELONGS_TO]->(ext)
            CREATE (vm2)-[:BELONGS_TO]->(int)
            
            CREATE (nginx)-[:RUNS_ON]->(vm1)
            CREATE (django)-[:RUNS_ON]->(vm1)
            
            CREATE (redis)-[:RUNS_ON]->(vm2)
            CREATE (mysql)-[:RUNS_ON]->(vm2)
            CREATE (ftp)-[:RUNS_ON]->(vm2)

            // 6. Build User Relationships (Local Access)
            // Defines which user accounts exist on which servers.
            CREATE (u1)-[:HAS_ACCOUNT_ON]->(vm1)
            CREATE (u2)-[:HAS_ACCOUNT_ON]->(vm2)

            // 7. Implement Lateral Movement Paths
            // Defines allowed inter-system access.
            CREATE (u1)-[:CAN_ACCESS]->(vm2)
            CREATE (u2)-[:CAN_ACCESS]->(vm1)

            // 8. Network Routing Rules
            // Defines how traffic flows between zones and services.
            CREATE (ext)-[:CAN_ROUT_TO]->(int)
            CREATE (nginx)-[:COMMUNICATES_WITH]->(django)
            CREATE (django)-[:COMMUNICATES_WITH]->(mysql)
            CREATE (django)-[:COMMUNICATES_WITH]->(redis)
            """
            # Execute the massive Cypher query.
            session.run(query)
            # Print a success message confirming the initialization.
            print("Network topology, users, and access rights successfully loaded into Neo4j!")

# Boilerplate to ensure the script only executes when run directly.
if __name__ == "__main__":
    create_topology()