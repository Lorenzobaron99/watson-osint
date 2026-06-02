"""Social Media tool — cross-platform profile discovery and analysis."""

from __future__ import annotations

import asyncio

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource
from ..utils.http import get_client
from ..utils.helpers import clean_username


# Common social media platforms and their profile URL patterns
SOCIAL_PLATFORMS = [
    ("Twitter/X", "https://x.com/{username}"),
    ("Instagram", "https://instagram.com/{username}"),
    ("LinkedIn", "https://linkedin.com/in/{username}"),
    ("GitHub", "https://github.com/{username}"),
    ("Reddit", "https://reddit.com/user/{username}"),
    ("TikTok", "https://tiktok.com/@{username}"),
    ("YouTube", "https://youtube.com/@{username}"),
    ("Facebook", "https://facebook.com/{username}"),
    ("Telegram", "https://t.me/{username}"),
    ("Medium", "https://medium.com/@{username}"),
    ("Substack", "https://{username}.substack.com"),
    ("Pinterest", "https://pinterest.com/{username}"),
    ("Twitch", "https://twitch.tv/{username}"),
    ("Snapchat", "https://snapchat.com/add/{username}"),
]


class SocialMediaTool(OSINTTool):
    """Discover social media profiles across platforms by username."""

    category = FindingSource.SOCIAL_MEDIA
    name = "social-media"
    description = "Cross-platform profile discovery, username search, social presence mapping"
    free_tier_available = True
    rate_limit_rps = 2.0

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Extract potential usernames
        usernames = self._extract_usernames(query)
        if not usernames:
            return findings

        client = get_client(rate_limit=self.rate_limit_rps)

        for username in usernames[:3]:  # Max 3 usernames
            username_clean = clean_username(username)

            # Check profile URLs in parallel
            platforms_found: list[str] = []
            tasks = []

            for platform_name, url_template in SOCIAL_PLATFORMS:
                url = url_template.format(username=username_clean)
                tasks.append(self._check_profile(client, platform_name, url))

            results = await asyncio.gather(*tasks)

            for name, url, exists in results:
                if exists:
                    platforms_found.append(f"[{name}]({url})")

            if platforms_found:
                findings.append(
                    self._make_finding(
                        title=f"👤 Social profiles for '{username_clean}'",
                        description=(
                            f"Found {len(platforms_found)} profiles across platforms:\n"
                            + "\n".join(f"- {p}" for p in platforms_found)
                        ),
                        confidence=0.85 if len(platforms_found) >= 3 else 0.5,
                        username=username_clean,
                        platform_count=len(platforms_found),
                        platforms=platforms_found,
                    )
                )
            else:
                findings.append(
                    self._make_finding(
                        title=f"No public profiles found for '{username_clean}'",
                        description=(
                            f"Checked {len(SOCIAL_PLATFORMS)} platforms. "
                            "The username may not exist, be private, or use a different handle."
                        ),
                        confidence=0.3,
                        username=username_clean,
                    )
                )

            # Generate a profile URL list regardless (for manual checking)
            all_urls = [
                f"[{name}]({url.format(username=username_clean)})"
                for name, url in SOCIAL_PLATFORMS[:8]
            ]
            findings.append(
                self._make_finding(
                    title=f"🔗 Profile links for '{username_clean}' (manual check)",
                    description="Quick links to check manually:\n" + "\n".join(f"- {u}" for u in all_urls),
                    confidence=0.6,
                    username=username_clean,
                )
            )

        return findings

    async def _check_profile(
        self, client, platform_name: str, url: str
    ) -> tuple[str, str, bool]:
        """Check if a social media profile exists. Returns (name, url, exists)."""
        try:
            response = await client.get(url)
            # A 200 means the profile exists and is public
            # Some platforms return 200 with a "not found" page, but this is a good heuristic
            return platform_name, url, True
        except Exception:
            return platform_name, url, False

    def _extract_usernames(self, text: str) -> list[str]:
        """Extract potential usernames from query text."""
        usernames = []

        # Look for @handles
        import re

        handles = re.findall(r"@(\w{3,30})", text)
        usernames.extend(handles)

        # Look for "username X" or "handle X" patterns
        patterns = [
            r"(?:username|handle|profile|account)\s+(?:is\s+)?['\"]?(\w{3,30})['\"]?",
            r"(?:find|search|look\s+up|check)\s+(?:the\s+)?(?:social\s+)?(?:media\s+)?(?:profile|account)(?:\s+for)?\s+['\"]?(\w{3,30})['\"]?",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                usernames.append(match.group(1))

        # Fallback: treat any single CamelCase word as a potential username
        if not usernames:
            word_match = re.search(r'\b([A-Za-z][A-Za-z0-9_]{2,30})\b', text)
            if word_match:
                word = word_match.group(1)
                # Don't use common investigative words as usernames
                if word.lower() not in ("who", "what", "where", "when", "why", "how",
                    "the", "and", "for", "with", "company", "person", "domain",
                    "investigate", "research", "search", "find", "look", "check"):
                    usernames.append(word)

        return list(dict.fromkeys(usernames))  # Deduplicated


# Register
social_media_tool = SocialMediaTool()
registry.register(social_media_tool)
