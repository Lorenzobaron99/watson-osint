"""Typed OSINT entities for the Watson entity graph.

Each entity type corresponds to a real-world OSINT artifact that can be
discovered, enriched, and pivoted from.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Optional


class EntityType(str, Enum):
    """Core entity types — maps to Maltego's entity palette."""
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    PERSON = "person"
    ORGANIZATION = "organization"
    WEBSITE = "website"
    LOCATION = "location"
    DOCUMENT = "document"
    UNKNOWN = "unknown"


@dataclass
class Entity:
    """Base entity — all entities have a unique ID derived from their value + type."""

    entity_type: EntityType = EntityType.UNKNOWN
    value: str = ""  # Canonical string representation (lowercased, normalized)
    display_name: str = ""  # Human-readable label
    confidence: float = field(default=0.8, metadata={"ge": 0.0, "le": 1.0})
    source: str = ""  # Transform name or tool that discovered this
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    properties: dict[str, Any] = field(default_factory=dict)

    # Subclasses override this to set their entity_type
    _entity_type: ClassVar[EntityType] = EntityType.UNKNOWN

    def __post_init__(self):
        if not self.display_name:
            self.display_name = self.value
        # Set entity_type from class variable if not explicitly passed
        if self.entity_type == EntityType.UNKNOWN and self._entity_type != EntityType.UNKNOWN:
            self.entity_type = self._entity_type

    @property
    def id(self) -> str:
        """Deterministic entity ID — same value+type always produces same ID."""
        raw = f"{self.entity_type.value}:{self.value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def label(self) -> str:
        """Short label for graph display."""
        return f"{self.entity_type.value}:{self.display_name[:40]}"

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Entity):
            return False
        return self.id == other.id

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "value": self.value,
            "display_name": self.display_name,
            "confidence": self.confidence,
            "source": self.source,
            "properties": self.properties,
        }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(value={self.value!r}, conf={self.confidence:.2f})"


# ── Concrete entity types ─────────────────────────────────────────


@dataclass(eq=False)
class Domain(Entity):
    """A DNS domain name."""
    _entity_type: ClassVar[EntityType] = EntityType.DOMAIN
    tld: str = ""
    registrar: str = ""

    def __post_init__(self):
        super().__post_init__()
        self.value = self.value.lower().rstrip(".")
        if not self.tld and "." in self.value:
            self.tld = self.value.rsplit(".", 1)[-1]


@dataclass(eq=False)
class IPAddress(Entity):
    """An IPv4 or IPv6 address."""
    _entity_type: ClassVar[EntityType] = EntityType.IP_ADDRESS
    is_ipv6: bool = False
    asn: str = ""
    isp: str = ""

    def __post_init__(self):
        super().__post_init__()
        self.is_ipv6 = ":" in self.value


@dataclass(eq=False)
class Email(Entity):
    """An email address."""
    _entity_type: ClassVar[EntityType] = EntityType.EMAIL
    local_part: str = ""
    domain: str = ""

    def __post_init__(self):
        super().__post_init__()
        self.value = self.value.lower()
        if "@" in self.value and not self.local_part:
            self.local_part, self.domain = self.value.split("@", 1)


@dataclass(eq=False)
class Person(Entity):
    """A person (name or identity)."""
    _entity_type: ClassVar[EntityType] = EntityType.PERSON
    given_name: str = ""
    surname: str = ""

    def __post_init__(self):
        super().__post_init__()
        if not self.given_name and not self.surname:
            parts = self.value.split()
            if len(parts) >= 2:
                self.given_name = parts[-1]  # Western order assumption
                self.surname = parts[0]
            elif len(parts) == 1:
                self.surname = parts[0]


@dataclass(eq=False)
class Organization(Entity):
    """A company, NGO, government body, etc."""
    _entity_type: ClassVar[EntityType] = EntityType.ORGANIZATION
    industry: str = ""
    country: str = ""


@dataclass(eq=False)
class Website(Entity):
    """A specific web page or site URL."""
    _entity_type: ClassVar[EntityType] = EntityType.WEBSITE
    url: str = ""

    def __post_init__(self):
        super().__post_init__()
        if not self.url:
            self.url = self.value
        self.value = self.url.lower().rstrip("/")


@dataclass(eq=False)
class Location(Entity):
    """A physical location (city, country, coordinates)."""
    _entity_type: ClassVar[EntityType] = EntityType.LOCATION
    latitude: float = 0.0
    longitude: float = 0.0
    country_code: str = ""


@dataclass(eq=False)
class Document(Entity):
    """A document, file, or extracted text snippet."""
    _entity_type: ClassVar[EntityType] = EntityType.DOCUMENT
    snippet: str = ""
    source_url: str = ""


# ── Entity factory ────────────────────────────────────────────────


def make_entity(
    entity_type: EntityType,
    value: str,
    **kwargs,
) -> Entity:
    """Create an entity of the appropriate type."""
    _type_map: dict[EntityType, type[Entity]] = {
        EntityType.DOMAIN: Domain,
        EntityType.IP_ADDRESS: IPAddress,
        EntityType.EMAIL: Email,
        EntityType.PERSON: Person,
        EntityType.ORGANIZATION: Organization,
        EntityType.WEBSITE: Website,
        EntityType.LOCATION: Location,
        EntityType.DOCUMENT: Document,
    }
    cls = _type_map.get(entity_type, Entity)
    if cls is Entity:
        kwargs["entity_type"] = entity_type
    return cls(value=value, **kwargs)
