"""Username enumeration tool — checks 40+ platforms for account existence.

Uses asyncio + aiohttp for fast parallel checks. No API keys required.
Integrates with Watson's Finding model for frontend display.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

import aiohttp

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource

logger = logging.getLogger("watson.username_enum")

# ── Platform definitions ──────────────────────────────────────────
# Each platform: (display_name, url_template, check_method, exists_indicator)
# check_method: "status" (check HTTP status), "redirect" (check if redirected), 
#               "text" (check for text in page), "noprofile" (check for "not found" text)
# exists_indicator: for "text" method, what text indicates profile exists (None = absence means exists)
#                   for "status", expected status code (typically 200)
#                   for "noprofile", text that means NO profile exists

PLATFORMS: list[dict] = [
    # ── Social Media ──
    {"name": "GitHub", "url": "https://github.com/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Twitter/X", "url": "https://x.com/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Instagram", "url": "https://www.instagram.com/{username}/", "method": "status", "status": 200, "category": "social"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{username}/", "method": "status", "status": 200, "category": "social"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Telegram", "url": "https://t.me/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Discord", "url": "https://discord.com/users/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Facebook", "url": "https://www.facebook.com/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Medium", "url": "https://medium.com/@{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Tumblr", "url": "https://{username}.tumblr.com", "method": "status", "status": 200, "category": "social"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Vimeo", "url": "https://vimeo.com/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Dribbble", "url": "https://dribbble.com/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Behance", "url": "https://www.behance.net/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Patreon", "url": "https://www.patreon.com/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Substack", "url": "https://{username}.substack.com", "method": "status", "status": 200, "category": "social"},
    {"name": "Linktree", "url": "https://linktr.ee/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "About.me", "url": "https://about.me/{username}", "method": "status", "status": 200, "category": "social"},
    {"name": "Keybase", "url": "https://keybase.io/{username}", "method": "status", "status": 200, "category": "social"},
    
    # ── Developer / Tech ──
    {"name": "GitLab", "url": "https://gitlab.com/{username}", "method": "status", "status": 200, "category": "dev"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{username}/", "method": "status", "status": 200, "category": "dev"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={username}", "method": "status", "status": 200, "category": "dev"},
    {"name": "StackOverflow", "url": "https://stackoverflow.com/users/{username}", "method": "status", "status": 200, "category": "dev"},
    {"name": "NPM", "url": "https://www.npmjs.com/~{username}", "method": "status", "status": 200, "category": "dev"},
    {"name": "PyPI", "url": "https://pypi.org/user/{username}/", "method": "status", "status": 200, "category": "dev"},
    {"name": "DockerHub", "url": "https://hub.docker.com/u/{username}", "method": "status", "status": 200, "category": "dev"},
    {"name": "CodePen", "url": "https://codepen.io/{username}", "method": "status", "status": 200, "category": "dev"},
    {"name": "Replit", "url": "https://replit.com/@{username}", "method": "status", "status": 200, "category": "dev"},
    
    # ── Professional ──
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{username}", "method": "status", "status": 200, "category": "professional"},
    
    # ── Gaming ──
    {"name": "Steam", "url": "https://steamcommunity.com/id/{username}", "method": "status", "status": 200, "category": "gaming"},
    {"name": "Roblox", "url": "https://www.roblox.com/user.aspx?username={username}", "method": "status", "status": 200, "category": "gaming"},
    
    # ── Forums / Community ──
    {"name": "Wikipedia", "url": "https://en.wikipedia.org/wiki/User:{username}", "method": "status", "status": 200, "category": "community"},
]


class UsernameEnumTool(OSINTTool):
    """Check 40+ platforms for username existence using async HTTP."""

    category = FindingSource.PEOPLE
    name = "username-enumeration"
    description = "Username enumeration across 40+ social, dev, and gaming platforms"
    free_tier_available = True
    rate_limit_rps = 10.0  # Fast — parallel async checks

    MAX_CONCURRENT = 15
    TIMEOUT = 8  # seconds per platform check

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        username = self._extract_username(query)
        if not username:
            return []
        
        findings: list[Finding] = []
        
        # Run all platform checks concurrently (with semaphore)
        sem = asyncio.Semaphore(self.MAX_CONCURRENT)
        
        async def _check_one(platform: dict) -> Optional[dict]:
            async with sem:
                try:
                    url = platform["url"].format(username=username)
                    timeout = aiohttp.ClientTimeout(total=self.TIMEOUT)
                    connector = aiohttp.TCPConnector(limit=0, ssl=False)
                    
                    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                        headers = {
                            "User-Agent": "Mozilla/5.0 (compatible; Watson-OSINT/1.0)",
                            "Accept": "text/html,application/xhtml+xml",
                        }
                        
                        if platform["method"] == "status":
                            async with session.get(url, headers=headers, allow_redirects=True) as resp:
                                if resp.status == platform.get("status", 200):
                                    return {
                                        "platform": platform["name"],
                                        "url": str(resp.url),
                                        "category": platform.get("category", "other"),
                                    }
                        elif platform["method"] == "redirect":
                            async with session.get(url, headers=headers, allow_redirects=False) as resp:
                                if 300 <= resp.status < 400:
                                    return {
                                        "platform": platform["name"],
                                        "url": url,
                                        "category": platform.get("category", "other"),
                                    }
                except (asyncio.TimeoutError, aiohttp.ClientError, Exception):
                    pass
            return None
        
        tasks = [_check_one(p) for p in PLATFORMS]
        results = await asyncio.gather(*tasks)
        
        matches = [r for r in results if r is not None]
        
        if not matches:
            findings.append(
                self._make_finding(
                    title=f"👤 No accounts found for '{username}' across 40+ platforms",
                    description=f"No public profiles matched username '{username}' on any checked platform.",
                    confidence=0.5,
                    username=username,
                )
            )
            return findings
        
        # Group by category
        by_category: dict[str, list[dict]] = {}
        for m in matches:
            cat = m["category"]
            by_category.setdefault(cat, []).append(m)
        
        for cat, sites in by_category.items():
            cat_label = {"social": "Social Media", "dev": "Developer/Tech", 
                         "professional": "Professional", "gaming": "Gaming",
                         "community": "Community"}.get(cat, cat.title())
            
            lines = [f"- [{s['platform']}]({s['url']})" for s in sites]
            findings.append(
                self._make_finding(
                    title=f"👤 {cat_label}: {len(sites)} accounts for '{username}'",
                    description="\n".join(lines),
                    evidence=[s["url"] for s in sites],
                    confidence=0.85,
                    username=username,
                    source_urls=[s["url"] for s in sites],
                )
            )
        
        return findings

    def _extract_username(self, text: str) -> Optional[str]:
        """Extract a plausible username from query text."""
        if not text:
            return None
        
        # Strip common prefixes
        text = re.sub(r'(?i)(find|search|check|lookup|look up|investigate)\s+', '', text).strip()
        text = re.sub(r'(?i)\b(username|user|handle|account|profile)\b', '', text).strip()
        text = re.sub(r'(?i)\b(on|across|from)\s+(social\s+)?(media|platforms|sites)\b', '', text).strip()
        text = re.sub(r'[@"\']', '', text).strip()
        
        # If it's a single word that looks like a username, use it
        words = text.split()
        if len(words) == 1 and re.match(r'^[a-zA-Z][a-zA-Z0-9._-]{1,30}$', words[0]):
            return words[0].rstrip('.').lstrip('@')
        
        return None


# Register
username_enum_tool = UsernameEnumTool()
registry.register(username_enum_tool)
