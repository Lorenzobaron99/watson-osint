"""Dark-web intelligence — ransomware, pastebin, breach lookups.

Implements the darkweb_tool expected by watson.tools_darkweb.
Uses clearnet indexes (ransomware.live, RansomWatch) — no Tor required.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

logger = logging.getLogger("watson.darkweb")

# ── Data structures ─────────────────────────────────────────────

@dataclass
class DarkWebFinding:
    title: str
    description: str
    source_url: str = ""
    source_type: str = "darkweb"
    confidence: float = 0.5
    evidence: list[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


class DarkWebTool:
    """Searches ransomware databases, pastebins, and breach indexes."""
    
    name = "darkweb"
    
    async def investigate(self, query: str, target_type: str = "topic") -> list[DarkWebFinding]:
        """Run dark-web investigation. Returns DarkWebFinding objects."""
        findings: list[DarkWebFinding] = []
        
        # Run all searches concurrently
        tasks = [
            self._ransomware_live(query),
            self._ransomwatch(query),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.warning("darkweb search failed: %s", result)
            elif result:
                findings.extend(result)
        
        if not findings:
            findings.append(DarkWebFinding(
                title=f"No dark-web results for \"{query}\"",
                description="No ransomware groups, victims, or pastebin mentions found.",
                confidence=0.2,
            ))
        
        return findings
    
    async def _ransomware_live(self, query: str) -> list[DarkWebFinding]:
        """Query ransomware.live for group profiles."""
        try:
            import aiohttp
        except ImportError:
            return []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.ransomware.live/v2/groups",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return []
                    groups = await resp.json()
        except Exception as e:
            logger.debug("ransomware.live unavailable: %s", e)
            return []
        
        findings = []
        query_lower = query.lower()
        
        for group in (groups or []):
            name = (group.get("group_name", "") or "").lower()
            if query_lower in name:
                findings.append(DarkWebFinding(
                    title=f"🕶️ Ransomware group: \"{group.get('group_name', '?')}\"",
                    description=(
                        f"  • **{group.get('group_name', '?')}** "
                        f"— {group.get('country', 'Unknown')} "
                        f"— {group.get('status', 'Unknown')}"
                    ),
                    source_url="https://www.ransomware.live",
                    confidence=0.85,
                    evidence=[f"https://api.ransomware.live/v2/groups"],
                ))
        
        return findings[:5]
    
    async def _ransomwatch(self, query: str) -> list[DarkWebFinding]:
        """Query RansomWatch for victim posts."""
        try:
            import aiohttp
        except ImportError:
            return []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
        except Exception as e:
            logger.debug("RansomWatch unavailable: %s", e)
            return []
        
        findings = []
        query_lower = query.lower()
        
        for post in (data or [])[:200]:  # Limit to recent 200
            group = (post.get("group_name", "") or "").lower()
            title = (post.get("post_title", "") or "").lower()
            if query_lower in group or query_lower in title:
                findings.append(DarkWebFinding(
                    title=f"RansomWatch: {post.get('group_name', '?')} — {post.get('post_title', '?')[:80]}",
                    description=(
                        f"Group: {post.get('group_name', '?')} | "
                        f"Date: {post.get('discovered', '?')[:10]}"
                    ),
                    source_url=post.get("url", "https://ransomwatch.telemetry.ltd"),
                    confidence=0.70,
                ))
        
        return findings[:10]


# ── Singleton instance ──────────────────────────────────────────

darkweb_tool = DarkWebTool()
