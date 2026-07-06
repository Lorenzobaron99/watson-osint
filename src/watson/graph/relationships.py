"""Typed relationships for the Watson entity graph.

Each relationship connects two entities and carries metadata about how
the connection was discovered (source transform, confidence, timestamp).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar


class RelationshipType(str, Enum):
    """Standard OSINT relationship types — mirrors Maltego's link labels."""
    # Infrastructure
    RESOLVES_TO = "resolves_to"          # Domain → IPAddress
    HAS_SUBDOMAIN = "has_subdomain"       # Domain → Domain
    HOSTED_ON = "hosted_on"               # Website → IPAddress
    USES_NAMESERVER = "uses_nameserver"    # Domain → Domain (NS record)

    # People & Organizations
    HAS_EMAIL = "has_email"               # Domain/Person → Email
    WORKS_AT = "works_at"                 # Person → Organization
    OWNS = "owns"                         # Person → Domain/Website
    CONTACT_FOR = "contact_for"           # Email → Organization (role-based)

    # Location
    LOCATED_IN = "located_in"             # IPAddress → Location
    BASED_IN = "based_in"                 # Organization → Location
    REGISTERED_IN = "registered_in"       # Domain → Location

    # Content
    MENTIONS = "mentions"                 # Website/Document → Entity
    CONTAINS = "contains"                 # Document → Entity (extracted)
    REFERENCES = "references"             # Website → Website/Document

    # Generic
    RELATED_TO = "related_to"             # Any → Any (fallback)


@dataclass
class Relationship:
    """A directed, typed link between two entities."""

    source_id: str         # Entity ID of the source node
    target_id: str         # Entity ID of the target node
    rel_type: RelationshipType
    confidence: float = field(default=0.7, metadata={"ge": 0.0, "le": 1.0})
    source_transform: str = ""  # Which transform created this
    evidence: list[str] = field(default_factory=list)  # Source URLs/proof
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    properties: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Unique relationship ID."""
        raw = f"{self.source_id}:{self.rel_type.value}:{self.target_id}"
        import hashlib
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Relationship):
            return False
        return self.id == other.id

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "rel_type": self.rel_type.value,
            "confidence": self.confidence,
            "source_transform": self.source_transform,
            "evidence": self.evidence,
            "properties": self.properties,
        }

    def __repr__(self) -> str:
        return (
            f"Relationship({self.source_id[:8]} "
            f"-{self.rel_type.value}→ "
            f"{self.target_id[:8]})"
        )


# ── Shorthand aliases for readability ─────────────────────────────

# Infrastructure
RESOLVES_TO = RelationshipType.RESOLVES_TO
HAS_SUBDOMAIN = RelationshipType.HAS_SUBDOMAIN
HOSTED_ON = RelationshipType.HOSTED_ON
USES_NAMESERVER = RelationshipType.USES_NAMESERVER

# People & Organizations
HAS_EMAIL = RelationshipType.HAS_EMAIL
WORKS_AT = RelationshipType.WORKS_AT
OWNS = RelationshipType.OWNS
CONTACT_FOR = RelationshipType.CONTACT_FOR

# Location
LOCATED_IN = RelationshipType.LOCATED_IN
BASED_IN = RelationshipType.BASED_IN
REGISTERED_IN = RelationshipType.REGISTERED_IN

# Content
MENTIONS = RelationshipType.MENTIONS
CONTAINS = RelationshipType.CONTAINS
REFERENCES = RelationshipType.REFERENCES

# Generic
RELATED_TO = RelationshipType.RELATED_TO
