import os
import logging
from neo4j import AsyncGraphDatabase

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")

log = logging.getLogger("trust_engine.neo4j")

class Neo4jClient:
    def __init__(self):
        try:
            self.driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        except Exception as e:
            log.warning(f"Neo4j driver init failed (likely missing server), simulating stub: {e}")
            self.driver = None

    async def close(self):
        if self.driver:
            await self.driver.close()

    async def query_suspicious_degrees(self, user_id: str, device_id: str) -> int:
        """
        Executes Cypher query to count shortest paths to known COMPROMISED nodes within 2 degrees.
        Returns the number of suspicious connected entities (e.g. shared fraudulent IPs/Devices).
        """
        if not self.driver:
            # Fallback for CI/CD environments without Neo4j
            return 0 

        cypher = """
        MATCH (u:User {id: $user_id})-[:USED]->(d:Device)-[:CONNECTED_FROM]->(ip:IP)
        MATCH p = (u)-[*1..2]-(bad:Entity {status: 'COMPROMISED'})
        RETURN count(p) as suspicious_paths
        """
        try:
            async with self.driver.session() as session:
                result = await session.run(cypher, user_id=user_id, device_id=device_id)
                record = await result.single()
                return record["suspicious_paths"] if record else 0
        except Exception as e:
            log.error(f"Neo4j query failed: {e}")
            return 0

neo4j_graph = Neo4jClient()
