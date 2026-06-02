"""
Knowledge graph engine — the Watson moat.

Every investigation writes to a persistent entity-relationship graph.
Future investigations auto-surface connections from past cases.
This is what makes Watson smarter over time — no general agent has this.

Graph structure:
  Node = Entity (person, company, domain, email, location, etc.)
  Edge = Relationship (registered_by, director_of, hosted_on, etc.)
  Each edge carries: provenance (case_id), source URL, confidence, timestamp
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class Entity:
    id: str  # sha256 of (type + value)
    type: str  # person, company, domain, email, location, ip, etc.
    value: str  # canonical value
    label: str = ""  # display name
    first_seen: str = ""  # ISO timestamp of first discovery
    last_seen: str = ""  # ISO timestamp of most recent discovery
    case_ids: list[str] = field(default_factory=list)  # which cases found this

    def __post_init__(self):
        if not self.id:
            self.id = self._hash(self.type, self.value)
        if not self.label:
            self.label = self.value
        now = datetime.now(timezone.utc).isoformat()
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = now

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "label": self.label,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "case_ids": self.case_ids,
        }

    @staticmethod
    def _hash(type_: str, value: str) -> str:
        raw = f"{type_.lower()}:{value.lower().strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Relation:
    id: str
    source_entity: str  # entity ID
    target_entity: str  # entity ID
    relation_type: str  # registered_by, director_of, hosted_on, uses_email, etc.
    case_id: str  # which case discovered this
    source_url: str = ""  # URL or tool that produced this
    confidence: float = 0.5
    timestamp: str = ""
    evidence: str = ""

    def __post_init__(self):
        if not self.id:
            raw = f"{self.source_entity}|{self.relation_type}|{self.target_entity}|{self.case_id}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_entity": self.source_entity,
            "target_entity": self.target_entity,
            "relation_type": self.relation_type,
            "case_id": self.case_id,
            "source_url": self.source_url,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
        }


class KnowledgeGraph:
    """Persistent entity-relationship graph with case provenance."""

    def __init__(self, data_dir: str | Path = "~/.watson/graph"):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._entities: dict[str, Entity] = {}
        self._relations: dict[str, Relation] = {}
        self._loaded = False

    # ── Persistence ──────────────────────────────────────────────

    def load(self) -> None:
        """Load graph from disk."""
        if self._loaded:
            return

        entities_path = self.data_dir / "entities.jsonl"
        if entities_path.exists():
            for line in entities_path.read_text().splitlines():
                if line.strip():
                    d = json.loads(line)
                    e = Entity(**d)
                    self._entities[e.id] = e

        relations_path = self.data_dir / "relations.jsonl"
        if relations_path.exists():
            for line in relations_path.read_text().splitlines():
                if line.strip():
                    d = json.loads(line)
                    r = Relation(**d)
                    self._relations[r.id] = r

        self._loaded = True

    def save(self) -> None:
        """Persist graph to disk."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

        with open(self.data_dir / "entities.jsonl", "w") as f:
            for e in self._entities.values():
                f.write(json.dumps(e.to_dict()) + "\n")

        with open(self.data_dir / "relations.jsonl", "w") as f:
            for r in self._relations.values():
                f.write(json.dumps(r.to_dict()) + "\n")

    # ── Entity CRUD ──────────────────────────────────────────────

    def upsert_entity(
        self,
        type_: str,
        value: str,
        case_id: str,
        label: str = "",
    ) -> Entity:
        """Create or update an entity, linking it to a case."""
        self.load()
        entity_id = Entity._hash(type_, value)  # type: ignore[arg-type]

        if entity_id in self._entities:
            entity = self._entities[entity_id]
            entity.last_seen = datetime.now(timezone.utc).isoformat()
            if case_id not in entity.case_ids:
                entity.case_ids.append(case_id)
            if label and label != entity.value:
                entity.label = label
        else:
            entity = Entity(
                id=entity_id,
                type=type_,
                value=value,
                label=label or value,
                case_ids=[case_id],
            )
            self._entities[entity_id] = entity

        self.save()
        return entity

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """Get entity by ID."""
        self.load()
        return self._entities.get(entity_id)

    def find_entity(self, type_: str, value: str) -> Optional[Entity]:
        """Find entity by type + value (case-insensitive)."""
        self.load()
        entity_id = Entity._hash(type_, value)  # type: ignore[arg-type]
        return self._entities.get(entity_id)

    def search_entities(self, query: str, limit: int = 20) -> list[Entity]:
        """Search entities by value substring."""
        self.load()
        q = query.lower()
        results = []
        for e in self._entities.values():
            if q in e.value.lower() or q in e.label.lower():
                results.append(e)
                if len(results) >= limit:
                    break
        return results

    # ── Relations ────────────────────────────────────────────────

    def add_relation(
        self,
        source_type: str,
        source_value: str,
        relation_type: str,
        target_type: str,
        target_value: str,
        case_id: str,
        source_url: str = "",
        confidence: float = 0.5,
        evidence: str = "",
    ) -> Relation:
        """Add a directed relationship between two entities."""
        self.load()

        # Upsert both entities
        source = self.upsert_entity(source_type, source_value, case_id)
        target = self.upsert_entity(target_type, target_value, case_id)

        relation = Relation(
            id="",
            source_entity=source.id,
            target_entity=target.id,
            relation_type=relation_type,
            case_id=case_id,
            source_url=source_url,
            confidence=confidence,
            evidence=evidence,
        )

        # Deduplicate
        if relation.id in self._relations:
            existing = self._relations[relation.id]
            if confidence > existing.confidence:
                existing.confidence = confidence
                existing.evidence = evidence
            return existing

        self._relations[relation.id] = relation
        self.save()
        return relation

    # ── Traversal ────────────────────────────────────────────────

    def traverse(
        self,
        entity_value: str,
        entity_type: str | None = None,
        hops: int = 1,
    ) -> dict:
        """Traverse the graph from an entity, returning N-hop neighborhood."""
        self.load()
        entity = None

        if entity_type:
            entity = self.find_entity(entity_type, entity_value)
        if not entity:
            # Try all types
            for e in self._entities.values():
                if e.value.lower() == entity_value.lower():
                    entity = e
                    break

        if not entity:
            return {"entity": None, "relations": [], "neighbors": [], "error": "Entity not found"}

        relations = []
        neighbor_ids: set[str] = set()

        for r in self._relations.values():
            if r.source_entity == entity.id:
                relations.append(r.to_dict())
                neighbor_ids.add(r.target_entity)
            elif r.target_entity == entity.id:
                # Reverse relation
                rev = r.to_dict()
                rev["direction"] = "incoming"
                relations.append(rev)
                neighbor_ids.add(r.source_entity)

        neighbors = []
        for nid in neighbor_ids:
            if nid in self._entities:
                e = self._entities[nid]
                neighbor_info = e.to_dict()
                # Collect all relations for context
                neighbor_info["relations"] = [
                    r.to_dict()
                    for r in self._relations.values()
                    if r.source_entity == e.id or r.target_entity == e.id
                ]
                neighbors.append(neighbor_info)

        return {
            "entity": entity.to_dict(),
            "relations": relations,
            "neighbors": neighbors,
            "hop_count": hops,
        }

    def context_for_investigation(
        self,
        query: str,
        max_entities: int = 10,
    ) -> dict:
        """Before investigating, check if any entities are already in the graph.
        Returns relevant prior findings to prime the new investigation."""
        self.load()

        relevant_entities = self.search_entities(query, limit=max_entities)
        if not relevant_entities:
            return {"known_entities": [], "prior_relations": [], "relevant_cases": []}

        prior_relations: list[dict] = []
        relevant_cases: set[str] = set()
        entity_ids = {e.id for e in relevant_entities}

        for r in self._relations.values():
            if r.source_entity in entity_ids or r.target_entity in entity_ids:
                prior_relations.append(r.to_dict())
                relevant_cases.add(r.case_id)

        return {
            "known_entities": [e.to_dict() for e in relevant_entities],
            "prior_relations": prior_relations,
            "relevant_cases": sorted(relevant_cases),
        }

    # ── Stats ────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Graph statistics."""
        self.load()
        type_counts: dict[str, int] = {}
        case_set: set[str] = set()
        for e in self._entities.values():
            type_counts[e.type] = type_counts.get(e.type, 0) + 1
            case_set.update(e.case_ids)

        return {
            "entity_count": len(self._entities),
            "relation_count": len(self._relations),
            "case_count": len(case_set),
            "entity_types": type_counts,
            "top_entities": sorted(
                [
                    {"value": e.value, "type": e.type, "case_count": len(e.case_ids)}
                    for e in self._entities.values()
                    if len(e.case_ids) > 1
                ],
                key=lambda x: -x["case_count"],
            )[:10],
        }
