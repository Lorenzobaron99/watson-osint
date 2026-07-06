"""Watson Entity Graph — typed entities, relationships, and transform engine.

This module provides Maltego-style graph-based OSINT discovery:
  - Typed entities (Domain, IPAddress, Email, Person, Website, etc.)
  - Typed relationships (RESOLVES_TO, HAS_SUBDOMAIN, LOCATED_IN, etc.)
  - EntityGraph: a networkx-backed graph with type-safe operations
  - TransformEngine: recursive entity→entity transform chaining

Integration: the graph engine runs as an enrichment layer AFTER the surface
phase of the existing pipeline. It does NOT modify the pipeline — it adds
new findings derived from the graph transforms, while all existing phases
continue unchanged.

Usage:
    from watson.graph import EntityGraph, TransformEngine
    g = EntityGraph()
    g.add_entity(Domain("automattic.com"))
    engine = TransformEngine(g)
    await engine.run_transforms(max_depth=3)
    findings = g.to_findings()
"""

from .entities import (
    Entity,
    Domain,
    IPAddress,
    Email,
    Person,
    Organization,
    Website,
    Location,
    Document,
)
from .relationships import (
    Relationship,
    RESOLVES_TO,
    HAS_SUBDOMAIN,
    LOCATED_IN,
    HAS_EMAIL,
    MENTIONS,
    CONTAINS,
    OWNS,
    RELATED_TO,
)
from .graph import EntityGraph
from .transforms import TransformEngine

__all__ = [
    "Entity",
    "Domain",
    "IPAddress",
    "Email",
    "Person",
    "Organization",
    "Website",
    "Location",
    "Document",
    "Relationship",
    "RESOLVES_TO",
    "HAS_SUBDOMAIN",
    "LOCATED_IN",
    "HAS_EMAIL",
    "MENTIONS",
    "CONTAINS",
    "OWNS",
    "RELATED_TO",
    "EntityGraph",
    "TransformEngine",
]
