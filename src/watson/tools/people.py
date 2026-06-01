"""People search tool — username enumeration, email lookup, breach data."""

from __future__ import annotations

import asyncio
import hashlib

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource
from ..utils.http import get_client
from ..utils.helpers import is_email, clean_username


class PeopleTool(OSINTTool):
    """Search for individuals — username enumeration, email breach check, name search."""

    category = FindingSource.PEOPLE
    name = "people-search"
    description = "Username enumeration, Have I Been Pwned check, email/name investigation"
    free_tier_available = True
    rate_limit_rps = 1.5

    HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    MAILCHECK_API = "https://api.mailcheck.ai/email/{email}"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []
        client = get_client(rate_limit=self.rate_limit_rps)

        emails = self._extract_emails(query)

        for email in emails[:3]:  # Max 3 emails
            # Check HIBP
            hibp_result = await self._check_hibp(client, email)
            if hibp_result:
                findings.append(hibp_result)

            # Check if email is disposable
            disp_result = await self._check_disposable(client, email)
            if disp_result:
                findings.append(disp_result)

        # Username enumeration
        usernames = self._extract_usernames(query)
        if usernames:
            uname = clean_username(usernames[0])
            findings.append(
                self._make_finding(
                    title=f"👤 Username '{uname}' — enumeration guidance",
                    description=(
                        f"To enumerate this username across platforms:\n"
                        f"- Use `watson investigate @{uname}` for social media sweep\n"
                        f"- Check https://whatsmyname.app for cross-platform lookup\n"
                        f"- Search Google: `\"{uname}\" site:github.com OR site:reddit.com OR site:twitter.com`\n"
                        f"- Check https://namechk.com for availability across 100+ platforms"
                    ),
                    evidence=[
                        f"https://whatsmyname.app/?q={uname}",
                        f"https://namechk.com/check?q={uname}",
                        f"https://www.google.com/search?q=%22{uname}%22+site%3Agithub.com+OR+site%3Areddit.com",
                    ],
                    confidence=0.6,
                    username=uname,
                )
            )

        return findings

    async def _check_hibp(self, client, email: str) -> Finding | None:
        """Check email against Have I Been Pwned."""
        try:
            response = await client.get(
                self.HIBP_API.format(email=email),
                headers={"hibp-api-key": ""},  # Works without key for v3
            )
            breaches = response.json()

            if isinstance(breaches, list) and breaches:
                breach_names = [b.get("Name", "Unknown") for b in breaches[:5]]
                return self._make_finding(
                    title=f"⚠️ Breach alert: {email}",
                    description=(
                        f"Found in {len(breaches)} known data breaches: "
                        + ", ".join(breach_names)
                    ),
                    evidence=[f"https://haveibeenpwned.com/account/{email}"],
                    confidence=0.95,
                    email=email,
                    breach_count=len(breaches),
                )
            else:
                return self._make_finding(
                    title=f"✅ No breaches found: {email}",
                    description="This email was not found in any known data breaches (HIBP).",
                    confidence=0.7,
                    email=email,
                )

        except Exception:
            return None

    async def _check_disposable(self, client, email: str) -> Finding | None:
        """Check if email is from a disposable provider."""
        try:
            data = await client.get_json(self.MAILCHECK_API.format(email=email))
            if isinstance(data, dict) and data.get("disposable"):
                return self._make_finding(
                    title=f"📧 Disposable email: {email}",
                    description="This appears to be a disposable/temporary email address.",
                    confidence=0.8,
                    email=email,
                )
        except Exception:
            pass
        return None

    def _extract_emails(self, text: str) -> list[str]:
        """Extract email addresses from text."""
        import re

        pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        return list(dict.fromkeys(re.findall(pattern, text)))

    def _extract_usernames(self, text: str) -> list[str]:
        """Extract potential usernames from text."""
        import re

        usernames = []

        # @handles
        usernames.extend(re.findall(r"@(\w{3,30})", text))

        # "username/handle X"
        match = re.search(r"(?:username|handle|alias)\s+(?:is\s+)?['\"]?(\w{3,30})['\"]?", text, re.IGNORECASE)
        if match:
            usernames.append(match.group(1))

        return list(dict.fromkeys(usernames))


# Register
people_tool = PeopleTool()
registry.register(people_tool)
