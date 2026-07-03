"""Shared protocol — data models used across Watson's investigation pipeline.

This module is the canonical source of Finding, AgentRole, SourceClass, and
AgentContext. All orchestration, resolution, and synthesis modules import from
here to avoid circular dependencies and divergent copies.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class AgentRole(str, Enum):
    """Roles for specialized investigation agents."""
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    SOCIAL = "social"
    CORPORATE = "corporate"
    CRYPTO = "crypto"
    GEO = "geo"
    MEDIA = "media"
    PEOPLE = "people"
    DARK = "dark"

    # Aliases for backward compat with agents/__init__.py
    COORDINATOR = "orchestrator"
    DOMAIN_RESEARCHER = "recon"
    SOCIAL_MEDIA_ANALYST = "social"
    CORPORATE_ANALYST = "corporate"
    CRYPTO_ANALYST = "crypto"
    GEOLOCATION_ANALYST = "geo"
    IMAGE_ANALYST = "media"
    PEOPLE_SEARCHER = "people"
    DARKWEB_SCOUT = "dark"
    CROSS_REFERENCER = "orchestrator"


class SourceClass(str, Enum):
    """Source classification tiers (Bazzell-standard)."""
    PRIMARY = "primary"        # Court records, gov registries, OFAC sanctions
    SECONDARY = "secondary"    # News articles, corporate registries, breach data
    TERTIARY = "tertiary"       # Wikipedia, social media, self-reported
    UNVERIFIED = "unverified"   # Anonymous sources, forum posts, single mentions


@dataclass
class Finding:
    """Intelligence finding with source tracking and confidence.

    This is the canonical Finding used across the entire pipeline.
    The orchestration engine has its own Finding (in engine.py) but
    both are duck-type compatible — resolution and synthesis use getattr().
    """
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    description: str = ""
    agent: AgentRole = AgentRole.ORCHESTRATOR
    source_class: SourceClass = SourceClass.SECONDARY
    source_type: str = "web_search"
    source_url: str = ""
    source_tier: str = "SECONDARY"
    confidence: float = 0.5
    entities: list[dict] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    phase: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def tier(self) -> str:
        if self.confidence >= 0.90:
            return "CONFIRMED"
        if self.confidence >= 0.70:
            return "PROBABLE"
        if self.confidence >= 0.40:
            return "POSSIBLE"
        if self.confidence >= 0.10:
            return "UNLIKELY"
        return "UNSUBSTANTIATED"

    @property
    def agent_value(self) -> str:
        return self.agent.value if isinstance(self.agent, AgentRole) else str(self.agent)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "agent": self.agent_value,
            "source_class": self.source_class.value if isinstance(self.source_class, SourceClass) else str(self.source_class),
            "source_type": self.source_type,
            "source_url": self.source_url,
            "source_tier": self.source_tier,
            "confidence": self.confidence,
            "tier": self.tier,
            "entities": self.entities,
            "phase": self.phase,
            "timestamp": self.timestamp,
        }


@dataclass
class AgentContext:
    """Context passed to investigation agents."""
    query: str = ""
    target_type: str = "unknown"
    target_value: str = ""
    focus: str = ""
    depth: int = 2
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Target classification ────────────────────────────────────

def classify_target(query: str) -> tuple[str, str]:
    """Quick deterministic target classification.
    
    Returns (target_type, target_value).
    Used by tests and as a fast-path before the LLM classifier.
    """
    import re
    q = query.strip()
    
    # Email
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', q):
        return "email", q.lower()
    
    # Ethereum wallet
    if re.match(r'^0x[a-fA-F0-9]{40}$', q):
        return "crypto", q
    
    # Bitcoin address
    if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', q):
        return "crypto", q
    
    # IPv4
    if re.match(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$', q):
        return "ip", q
    
    # .onion
    if '.onion' in q:
        return "onion", q
    
    # GPS coordinates
    if re.match(r'^-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+$', q):
        return "gps", q
    
    # Flight code
    if re.match(r'^[A-Z]{2}\d{2,4}$', q):
        return "flight", q
    
    # Image file
    if re.match(r'^.*\.(jpg|jpeg|png|gif|bmp|webp|tiff)$', q, re.I):
        return "image", q
    
    # Domain
    if re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|io|gov|edu|co|me|ai|app|dev|xyz|info|biz)$', q, re.I):
        return "domain", q.lower()
    
    # Breach keywords
    if any(kw in q.lower() for kw in ['breach', 'leaked', 'passwords', 'data dump']):
        return "breach", q
    
    # Company indicators
    if any(suffix in q for suffix in ['Inc', 'LLC', 'Ltd', 'Corp', 'GmbH', 'SA', 'AG', 'Group']):
        return "company", q
    
    # Default: person
    if ' ' in q and len(q.split()) >= 2:
        return "person", q
    
    # Single word — could be username or company
    return "person", q


def select_agents(target_type: str) -> list[AgentRole]:
    """Select which agents to dispatch for a given target type."""
    mapping = {
        "domain": [AgentRole.RECON, AgentRole.CORPORATE, AgentRole.PEOPLE],
        "email": [AgentRole.SOCIAL, AgentRole.DARK, AgentRole.RECON],
        "ip": [AgentRole.RECON, AgentRole.GEO],
        "crypto": [AgentRole.CRYPTO, AgentRole.DARK],
        "gps": [AgentRole.GEO, AgentRole.MEDIA],
        "image": [AgentRole.MEDIA, AgentRole.GEO],
        "onion": [AgentRole.DARK, AgentRole.RECON],
        "company": [AgentRole.CORPORATE, AgentRole.RECON, AgentRole.SOCIAL],
        "person": [AgentRole.SOCIAL, AgentRole.PEOPLE, AgentRole.RECON, AgentRole.CORPORATE],
        "breach": [AgentRole.DARK, AgentRole.SOCIAL],
        "flight": [AgentRole.GEO, AgentRole.RECON],
    }
    return mapping.get(target_type, [AgentRole.RECON, AgentRole.SOCIAL])
