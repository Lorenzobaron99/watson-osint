"""People search tool — username enumeration, email lookup, breach data."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import urllib.parse

from .base import OSINTTool

logger = logging.getLogger("watson.people")
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
            # Full email analysis — type, provider, risk profile
            analysis = self._analyze_email(email)
            if analysis:
                findings.append(analysis)

            # Check HIBP (fast, 5s timeout)
            hibp_result = await self._check_hibp(client, email)
            if hibp_result:
                findings.append(hibp_result)

            # Check if email is disposable (fast, 5s timeout)
            disp_result = await self._check_disposable(client, email)
            if disp_result:
                findings.append(disp_result)

        # Username enumeration — actually search platforms, don't just give guidance
        usernames = self._extract_usernames(query)
        if usernames:
            uname = clean_username(usernames[0])
            # Skip username search for role-based accounts — "info", "admin", etc. are useless
            _ROLE_USERNAMES = {"info", "admin", "support", "sales", "contact", "hello",
                               "help", "noreply", "no-reply", "postmaster", "abuse",
                               "security", "webmaster", "hostmaster", "billing", "jobs",
                               "careers", "hr", "press", "media", "marketing", "office",
                               "service", "team", "newsletter", "notifications"}
            if uname.lower() not in _ROLE_USERNAMES:
                findings.append(
                    self._make_finding(
                        title=f"👤 Username search: '{uname}' across platforms",
                        description=(
                            f"Searching for username '{uname}' across platforms — "
                            f"real people leave digital footprints. Use the links below "
                            f"to manually verify any results."
                        ),
                        evidence=[
                            f"https://www.google.com/search?q=%22{uname}%22+site%3Agithub.com+OR+site%3Alinkedin.com+OR+site%3Atwitter.com+OR+site%3Areddit.com",
                            f"https://whatsmyname.app/?q={uname}",
                        ],
                        confidence=0.6,
                        username=uname,
                    )
                )

                # Actually search the platforms via DDG — don't just give links
                try:
                    from ddgs import DDGS
                    # Search both concatenated username AND full name with spaces
                    person_name = self._extract_person_name(query)
                    full_name_str = person_name if person_name else uname
                    platform_queries = []
                    # If we have a full name, search for it across platforms
                    if person_name and person_name.lower() != uname.lower():
                        platform_queries = [
                            f'"{person_name}" linkedin',
                            f'"{person_name}" github OR twitter',
                            f'"{person_name}" journalist OR analyst OR author OR editor',
                        ]
                    else:
                        # Fallback: search by username
                        platform_queries = [
                            f'"{uname}" linkedin',
                            f'"{uname}" github OR twitter',
                            f'"{uname}" journalist OR analyst OR author OR editor',
                        ]
                    def _ddg_search(q):
                        try:
                            with DDGS() as ddgs:
                                return list(ddgs.text(q, max_results=3))
                        except Exception:
                            return []
                    all_raw = await asyncio.gather(*[
                        asyncio.to_thread(_ddg_search, q) for q in platform_queries
                    ])
                    seen = set()
                    # URL patterns to EXCLUDE (login pages, help pages, homepages)
                    _NOISE_PATTERNS = [
                        '/login', '/signin', '/signup', '/help/', '/answer/',
                        '/company/', '/school/', '/jobs', '/pulse/',
                    ]
                    def _is_noise_url(url: str) -> bool:
                        url_lower = url.lower()
                        # Root domains with no path
                        if url_lower.rstrip('/') in (
                            'https://www.linkedin.com', 'https://linkedin.com',
                            'https://github.com', 'https://www.github.com',
                        ):
                            return True
                        for pat in _NOISE_PATTERNS:
                            if pat in url_lower:
                                return True
                        return False

                    for raw_list in all_raw:
                        for r in raw_list:
                            href = r.get("href", "")
                            title = r.get("title", "")[:150]
                            body = r.get("body", "")[:200]
                            if not href or href in seen:
                                continue
                            # Filter noise URLs
                            if _is_noise_url(href):
                                continue
                            # Filter: result must mention the person's name in title or body
                            name_parts = person_name.lower().split() if person_name else [uname.lower()]
                            combined = (title + " " + body).lower()
                            name_mentioned = any(part in combined for part in name_parts)
                            if not name_mentioned:
                                continue
                            seen.add(href)
                            findings.append(self._make_finding(
                                title=f"🔍 {title}",
                                description=body,
                                evidence=[href],
                                confidence=0.7,
                                username=uname,
                            ))
                    if seen:
                        logger.info("username_search_found: %s → %d results", uname, len(seen))
                except Exception as e:
                    logger.warning("username_search_failed: %s", e)

        # Fallback: bare name lookup (e.g., "John Smith")
        if not findings:
            person_name = self._extract_person_name(query)
            if person_name:
                encoded = urllib.parse.quote(person_name)
                findings.append(
                    self._make_finding(
                        title=f"👤 Person: {person_name}",
                        description=(
                            f"Searching for **{person_name}** across public records and platforms:\n"
                            f"- [Google search](https://www.google.com/search?q=%22{encoded}%22)\n"
                            f"- [LinkedIn](https://www.linkedin.com/search/results/people/?keywords={encoded})\n"
                            f"- [OpenSanctions](https://opensanctions.org/search/?q={encoded})\n"
                            f"- [Wikipedia](https://en.wikipedia.org/wiki/Special:Search?search={encoded})\n\n"
                            f"To investigate further, try:\n"
                            f"`watson investigate \"{person_name} email\"` for email breach check\n"
                            f"`watson investigate \"{person_name} company\"` for corporate ties"
                        ),
                        evidence=[
                            f"https://www.google.com/search?q=%22{encoded}%22",
                            f"https://www.linkedin.com/search/results/people/?keywords={encoded}",
                            f"https://opensanctions.org/search/?q={encoded}",
                        ],
                        confidence=0.5,
                        person_name=person_name,
                    )
                )

        return findings

    async def _check_hibp(self, client, email: str) -> Finding | None:
        """Check email against Have I Been Pwned — async with 5s timeout."""
        import httpx
        try:
            async with httpx.AsyncClient(timeout=5.0) as raw:
                resp = await raw.get(
                    self.HIBP_API.format(email=email),
                    headers={
                        "hibp-api-key": "",
                        "User-Agent": "WatsonOSINT/0.3",
                    },
                )
                if resp.status_code == 404:
                    return self._make_finding(
                        title=f"✅ No breaches found: {email}",
                        description="This email was not found in any known data breaches (HIBP).",
                        confidence=0.7,
                        email=email,
                    )
                resp.raise_for_status()
                breaches = resp.json()
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
        """Check if email is from a disposable provider — 5s timeout."""
        import httpx
        try:
            async with httpx.AsyncClient(timeout=5.0) as raw:
                resp = await raw.get(
                    self.MAILCHECK_API.format(email=email),
                    headers={"User-Agent": "WatsonOSINT/0.3"},
                )
                if resp.status_code != 200:
                    return None
                data = resp.json()
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

    # ── Email analysis ──────────────────────────────────────

    # Known email provider domains and their categories
    _EMAIL_PROVIDERS = {
        # Personal / free email providers
        "gmail.com": ("Personal", "Google Gmail"),
        "googlemail.com": ("Personal", "Google Gmail"),
        "yahoo.com": ("Personal", "Yahoo Mail"),
        "yahoo.fr": ("Personal", "Yahoo Mail (France)"),
        "yahoo.co.uk": ("Personal", "Yahoo Mail (UK)"),
        "outlook.com": ("Personal", "Microsoft Outlook"),
        "hotmail.com": ("Personal", "Microsoft Hotmail"),
        "live.com": ("Personal", "Microsoft Live"),
        "msn.com": ("Personal", "Microsoft MSN"),
        "icloud.com": ("Personal", "Apple iCloud"),
        "me.com": ("Personal", "Apple iCloud"),
        "mac.com": ("Personal", "Apple iCloud"),
        "protonmail.com": ("Personal", "ProtonMail (encrypted)"),
        "proton.me": ("Personal", "Proton (encrypted)"),
        "tutanota.com": ("Personal", "Tutanota (encrypted)"),
        "tuta.io": ("Personal", "Tutanota (encrypted)"),
        "mail.ru": ("Personal", "Mail.ru (Russia)"),
        "yandex.ru": ("Personal", "Yandex (Russia)"),
        "yandex.com": ("Personal", "Yandex"),
        "qq.com": ("Personal", "QQ Mail (China)"),
        "163.com": ("Personal", "163 Mail (China)"),
        "126.com": ("Personal", "126 Mail (China)"),
        "naver.com": ("Personal", "Naver (Korea)"),
        "daum.net": ("Personal", "Daum (Korea)"),
        "rambler.ru": ("Personal", "Rambler (Russia)"),
        "aol.com": ("Personal", "AOL"),
        "fastmail.com": ("Personal", "Fastmail"),
        "zoho.com": ("Personal", "Zoho Mail"),
    }

    _ROLE_PREFIXES = {
        "admin", "info", "support", "sales", "contact", "hello", "help",
        "noreply", "no-reply", "noreply", "donotreply", "postmaster",
        "abuse", "security", "webmaster", "hostmaster", "billing",
        "jobs", "careers", "hr", "press", "media", "marketing",
        "office", "service", "team", "newsletter", "notifications",
    }

    def _analyze_email(self, email: str) -> Finding | None:
        """Categorize an email address — type, provider, risk indicators.

        Pure local analysis (no API calls). Detects:
          - Type: Personal / Corporate / Government / Educational / Role-based
          - Provider (for personal emails: Gmail, Yahoo, ProtonMail, etc.)
          - Plus addressing (user+tag@domain.com)
          - Role account detection (admin@, info@, noreply@)
          - Custom domain indicators
        """
        import re

        local, _, domain = email.partition("@")
        if not domain:
            return None

        domain_lower = domain.lower().strip()
        local_lower = local.lower().strip()

        # ── Determine type ──
        provider_info = self._EMAIL_PROVIDERS.get(domain_lower)
        is_role = local_lower in self._ROLE_PREFIXES or any(
            local_lower.startswith(p + ".") or local_lower.startswith(p + "-")
            for p in self._ROLE_PREFIXES
        )

        # Plus addressing: user+tag@domain (Gmail, Fastmail, ProtonMail)
        has_plus = "+" in local and not is_role

        # TLD-based classification
        tld = domain_lower.rsplit(".", 1)[-1] if "." in domain_lower else ""

        email_type = "Unknown"
        provider = "Custom domain"
        details: list[str] = []

        if provider_info:
            email_type, provider = provider_info
        elif tld in ("gov", "mil"):
            email_type = "Government"
            provider = f"Government domain (.{tld})"
        elif tld == "edu":
            email_type = "Educational"
            provider = "Educational institution (.edu)"
        elif tld in ("org", "ngo"):
            email_type = "Organization"
            provider = f"Organization domain (.{tld})"
        elif is_role:
            email_type = "Role-based"
            provider = "Organizational role account"
        else:
            email_type = "Corporate"
            provider = f"Custom corporate domain ({domain_lower})"

        # ── Build risk indicators ──
        risk_indicators: list[str] = []
        if is_role:
            risk_indicators.append("🔶 Role account — likely shared inbox, not a person")
        if has_plus:
            risk_indicators.append("🔹 Plus addressing — may have aliases (e.g., user+netflix@, user+bank@)")
        if provider_info and provider_info[0] == "Personal":
            risk_indicators.append("🟢 Personal email — common for individuals, harder to trace")
        if email_type == "Corporate":
            risk_indicators.append("🔵 Corporate domain — belongs to an organization, check WHOIS")
        if email_type == "Government":
            risk_indicators.append("🔴 Government email — official capacity")
        if "encrypted" in provider.lower():
            risk_indicators.append("🛡 Encrypted provider — enhanced privacy")
        if provider_info and "russia" in provider.lower():
            risk_indicators.append("⚠ Russian provider — subject to data localization laws")
        if provider_info and "china" in provider.lower():
            risk_indicators.append("⚠ Chinese provider — subject to data localization laws")

        return self._make_finding(
            title=f"📧 {email_type} email — {provider}",
            description=f"**{email}**\nType: {email_type}\nProvider: {provider}\n"
                        + (f"Domain: {domain_lower}\n" if email_type == "Corporate" else "")
                        + ("\n".join(f"{r}" for r in risk_indicators) if risk_indicators else ""),
            confidence=0.95,
            email=email,
            email_type=email_type,
            provider=provider,
            is_role=is_role,
            has_plus_addressing=has_plus,
        )

    def _extract_emails(self, text: str) -> list[str]:
        """Extract email addresses from text."""
        import re

        pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        return list(dict.fromkeys(re.findall(pattern, text)))

    def _extract_usernames(self, text: str) -> list[str]:
        """Extract potential usernames from text."""
        import re

        usernames = []

        # If there's an email, extract the LOCAL PART as the primary username
        # (e.g., "baron.lorenzo99" from "baron.lorenzo99@gmail.com")
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails = re.findall(email_pattern, text)
        for email in emails:
            local = email.split("@")[0]
            if local and len(local) >= 3:
                usernames.append(local)

        # @handles (filter out email domains)
        KNOWN_DOMAINS = {"gmail", "yahoo", "hotmail", "outlook", "icloud", "protonmail",
                         "mail", "aol", "live", "msn", "yandex", "qq", "163"}
        for match in re.finditer(r"@(\w{3,30})", text):
            handle = match.group(1)
            if handle.lower() not in KNOWN_DOMAINS:
                usernames.append(handle)

        # "username/handle X"
        match = re.search(r"(?:username|handle|alias)\s+(?:is\s+)?['\"]?(\w{3,30})['\"]?", text, re.IGNORECASE)
        if match:
            usernames.append(match.group(1))

        # Fallback: use full name (not just first word) as potential username
        if not usernames:
            # Try full name as a compound username (e.g., "PaoloTrecate", "paolotrecate")
            words = re.findall(r'[A-Za-z][a-z]+', text)
            if len(words) >= 2:
                # FullName, firstlast, first_last, first-last
                full_name = ''.join(words)
                usernames.append(full_name)
                usernames.append(full_name.lower())
                usernames.append('_'.join(words).lower())
                usernames.append('-'.join(words).lower())
            else:
                # Single word — only use if it's distinctive (≥6 chars)
                word_match = re.search(r'\b([A-Za-z][A-Za-z0-9_]{5,30})\b', text)
                if word_match:
                    word = word_match.group(1)
                    if word.lower() not in ("who", "what", "where", "when", "why", "how",
                        "the", "and", "for", "with", "company", "person", "domain",
                        "investigate", "research", "search", "find", "look", "check"):
                        usernames.append(word)

        return list(dict.fromkeys(usernames))

    def _extract_person_name(self, text: str) -> str | None:
        """Extract a person's name from query text. Handles bare names like 'John Smith'."""
        import re

        # Pattern: two capitalized words (e.g., "Lorenzo Baron", "John Smith")
        # Match anywhere in the text, handling quoted nicknames
        match = re.search(
            r"\b([A-Z][a-z]+(?:\s+(?:\"[A-Z][a-z]+\"\s+)?[A-Z][a-z]+){1,3})\b",
            text
        )
        if match:
            return match.group(1)

        # Fallback: strip quotes and try again
        clean = re.sub(r'["\']', '', text)
        match = re.search(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b", clean)
        if match:
            return match.group(1)

        # Also match "person named X" or "who is X"
        for pattern in [
            r"(?:person|individual|guy|man|woman)\s+(?:named|called|known as)\s+['\"]?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})['\"]?",
            r"who\s+is\s+['\"]?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})['\"]?",
        ]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

        return None


# Register
people_tool = PeopleTool()
registry.register(people_tool)
