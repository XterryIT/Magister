"""
Contains tools and utilities used by the LangGraph agents.
"""
import os
from neo4j import GraphDatabase

def check_network_topology(ip_addresses_str: str) -> str:
    """
    Returns network topology information for multiple IP addresses by querying Neo4j.
    """
    # Split incoming string into clean IP addresses
    ips_to_check = [ip.strip(' "\'\n') for ip in ip_addresses_str.split(",") if ip.strip(' "\'\n')]
    
    print("\n" + "-" * 60)
    print(f"[L3-JUDGE -> NEO4J] AI requested topology for IPs: {ips_to_check}")
    
    # Load Neo4j configuration from environment
    URI = os.getenv('NEO4J_URI', "bolt://localhost:7687")
    AUTH = (os.getenv('NEO4J_USER', "neo4j"), os.getenv('NEO4J_PASSWORD', "password"))
    
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
                
                # Query database for each IP
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
