"""
Neo4j Graph Adapter — replaces JSON-file graph with Neo4j when available.

Auto-detects Neo4j at NEO4J_URI (default: bolt://localhost:7687).
Falls back to JSON-file KnowledgeGraph if Neo4j is unavailable.
Same API surface — drop-in replacement.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

NEO4J_AVAILABLE = False

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    pass


class Neo4jGraph:
    """Neo4j-backed knowledge graph. Same interface as watson.graph.KnowledgeGraph."""

    def __init__(self, uri: str | None = None, user: str = "neo4j", password: str = ""):
        if not NEO4J_AVAILABLE:
            raise ImportError("neo4j package not installed. pip install neo4j")
        
        self.uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        self.user = user
        self.password = password
        self._driver = None

    def connect(self):
        if self._driver is None:
            self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # Verify connection
            self._driver.verify_connectivity()
            self._ensure_schema()
        return self._driver

    def _ensure_schema(self):
        """Create constraints and indexes if they don't exist."""
        with self._driver.session() as session:
            session.run("CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE")
            session.run("CREATE INDEX entity_type IF NOT EXISTS FOR (e:Entity) ON (e.type)")
            session.run("CREATE INDEX entity_value IF NOT EXISTS FOR (e:Entity) ON (e.value)")

    def add_entity(self, entity_id: str, entity_type: str, value: str, label: str = "", case_id: str = ""):
        with self._driver.session() as session:
            session.run("""
                MERGE (e:Entity {id: $id})
                SET e.type = $type, e.value = $value, e.label = $label,
                    e.last_seen = datetime()
                ON CREATE SET e.first_seen = datetime(), e.case_ids = [$case_id]
                ON MATCH SET e.case_ids = CASE
                    WHEN $case_id IN e.case_ids THEN e.case_ids
                    ELSE e.case_ids + $case_id
                END
            """, id=entity_id, type=entity_type, value=value, label=label or value, case_id=case_id)

    def add_relation(self, source_id: str, target_id: str, relation_type: str,
                     case_id: str = "", source_url: str = "", confidence: float = 0.5):
        with self._driver.session() as session:
            session.run("""
                MATCH (a:Entity {id: $source_id})
                MATCH (b:Entity {id: $target_id})
                MERGE (a)-[r:RELATES {type: $rel_type}]->(b)
                SET r.case_id = $case_id,
                    r.source_url = $source_url,
                    r.confidence = $confidence,
                    r.timestamp = datetime()
            """, source_id=source_id, target_id=target_id, rel_type=relation_type,
                 case_id=case_id, source_url=source_url, confidence=confidence)

    def context_for_investigation(self, query: str) -> dict:
        """Return prior graph context relevant to a new investigation."""
        with self._driver.session() as session:
            result = session.run("""
                MATCH (e:Entity)
                WHERE toLower(e.value) CONTAINS toLower($query)
                   OR toLower(e.label) CONTAINS toLower($query)
                OPTIONAL MATCH (e)-[r:RELATES]-(other:Entity)
                RETURN e, collect(DISTINCT {type: r.type, target: other.value, case: r.case_id}) as relations
                LIMIT 20
            """, query=query)
            
            entities = []
            for record in result:
                e = record["e"]
                entities.append({
                    "id": e["id"], "type": e["type"], "value": e["value"],
                    "label": e["label"], "case_ids": e.get("case_ids", []),
                    "relations": record["relations"],
                })
            
            return {"entities": entities, "count": len(entities)}

    def stats(self) -> dict:
        with self._driver.session() as session:
            nodes = session.run("MATCH (e:Entity) RETURN count(e) as c").single()["c"]
            rels = session.run("MATCH ()-[r:RELATES]->() RETURN count(r) as c").single()["c"]
            return {"entities": nodes, "relations": rels, "backend": "neo4j"}

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None


def get_graph() -> "Neo4jGraph | KnowledgeGraph":
    """Return Neo4j graph if available, otherwise fall back to JSON-file graph."""
    if NEO4J_AVAILABLE:
        try:
            graph = Neo4jGraph()
            graph.connect()
            return graph
        except Exception:
            pass
    
    from watson.graph import KnowledgeGraph
    return KnowledgeGraph()
