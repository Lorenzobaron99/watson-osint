"""Agents registry — list all available OSINT sub-agents.

Provides get_all_agents() for the /api/agent/agents endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    DOMAIN_RESEARCHER = "domain_researcher"
    SOCIAL_MEDIA_ANALYST = "social_media_analyst"
    CORPORATE_ANALYST = "corporate_analyst"
    CRYPTO_ANALYST = "crypto_analyst"
    GEOLOCATION_ANALYST = "geolocation_analyst"
    IMAGE_ANALYST = "image_analyst"
    PEOPLE_SEARCHER = "people_searcher"
    DARKWEB_SCOUT = "darkweb_scout"
    CROSS_REFERENCER = "cross_referencer"


@dataclass
class AgentInfo:
    role: AgentRole
    description: str
    capabilities: List[str] = field(default_factory=list)
    tool_count: int = 0


# Registry of all specialized agents
_AGENTS: Dict[str, AgentInfo] = {
    "coordinator": AgentInfo(
        role=AgentRole.COORDINATOR,
        description="Orchestrates investigations, dispatches sub-agents, and synthesizes findings",
        capabilities=["multi_agent_orchestration", "finding_synthesis", "gap_analysis"],
        tool_count=5,
    ),
    "domain_researcher": AgentInfo(
        role=AgentRole.DOMAIN_RESEARCHER,
        description="Domain & DNS investigation — WHOIS, certificate transparency, DNS records",
        capabilities=["whois_lookup", "dns_lookup", "crt_sh", "wayback_machine"],
        tool_count=4,
    ),
    "social_media_analyst": AgentInfo(
        role=AgentRole.SOCIAL_MEDIA_ANALYST,
        description="Social media investigation — profiles, posts, network analysis",
        capabilities=["social_search", "profile_analysis", "network_mapping"],
        tool_count=3,
    ),
    "corporate_analyst": AgentInfo(
        role=AgentRole.CORPORATE_ANALYST,
        description="Corporate investigation — company registries, directors, financial records",
        capabilities=["opencorporates_search", "sec_filings", "sanctions_check"],
        tool_count=3,
    ),
    "crypto_analyst": AgentInfo(
        role=AgentRole.CRYPTO_ANALYST,
        description="Cryptocurrency investigation — blockchain analysis, wallet tracing",
        capabilities=["etherscan_lookup", "wallet_tracing", "transaction_analysis"],
        tool_count=3,
    ),
    "geolocation_analyst": AgentInfo(
        role=AgentRole.GEOLOCATION_ANALYST,
        description="Geolocation investigation — satellite imagery, location verification",
        capabilities=["satellite_analysis", "geolocation", "reverse_image_search"],
        tool_count=3,
    ),
    "image_analyst": AgentInfo(
        role=AgentRole.IMAGE_ANALYST,
        description="Image & video investigation — EXIF analysis, deepfake detection, visual forensics",
        capabilities=["exif_analysis", "reverse_image_search", "deepfake_detection"],
        tool_count=3,
    ),
    "people_searcher": AgentInfo(
        role=AgentRole.PEOPLE_SEARCHER,
        description="People investigation — public records, professional profiles, background checks",
        capabilities=["people_search", "professional_profiles", "public_records"],
        tool_count=3,
    ),
    "darkweb_scout": AgentInfo(
        role=AgentRole.DARKWEB_SCOUT,
        description="Dark web investigation — .onion sites, forums, marketplaces",
        capabilities=["darkweb_search", "onion_scan", "forum_monitoring"],
        tool_count=3,
    ),
    "cross_referencer": AgentInfo(
        role=AgentRole.CROSS_REFERENCER,
        description="Cross-references findings across agents and external sources",
        capabilities=["cross_reference", "entity_linking", "pattern_detection"],
        tool_count=2,
    ),
}


def get_all_agents() -> Dict[str, AgentInfo]:
    """Return all registered agents."""
    return _AGENTS
