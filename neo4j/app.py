import os
from dotenv import load_dotenv
load_dotenv()


from neo4j import GraphDatabase


# Initialize the Neo4j driver
driver = GraphDatabase.driver(
   os.getenv('NEO4J_URI'),
   auth=(
       os.getenv('NEO4J_USERNAME'),
       os.getenv('NEO4J_PASSWORD')
   )
)


# Verify the connection
driver.verify_connectivity()


# Define the query
cypher_query = """
MATCH (r:Review)-[:WRITTEN_FOR]->(:Book)<-[:AUTHORED]-(a:Author)
WHERE a.name = $name
RETURN r {.text, .rating}
ORDER BY r.rating DESC
LIMIT 10
"""


# Execute the query with a parameter
records, summary, keys = driver.execute_query(
   cypher_query,
   name="Jennifer Weiner"
)


# Parse the result
for record in records:
   # Print the return values
   print(f"record: {record}")


# Close the driver
driver.close()
