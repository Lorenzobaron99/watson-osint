"""Transform Engine — recursive entity→entity discovery for the Watson graph.

Maltego's core innovation: transforms are functions that take entities as
input and produce new entities+relationships as output, applied recursively
to grow the investigation graph.

This engine:
  1. Takes an entity graph populated from phase 2 (SURFACE) findings
  2. Applies built-in transforms (DNS resolution, IP geolocation, email
     extraction) recursively up to max_depth
  3. Uses OSINT Framework to enrich findings with direct tool links
  4. Converts new discoveries back to Finding objects for the pipeline

Built-in transforms (no external APIs needed):
  - dns_resolution:   Domain → IPAddress via dnspython
  - subdomain_enum:   Domain → Domain via crt.sh SSL certificates
  - ip_geolocation:   IPAddress → Location via ip-api.com (free, no key)
  - email_discovery:  Domain → Email via WHOIS/website scraping
  - osint_enrichment: Any entity → tool links from OSINT Framework

Each transform is a coroutine that takes (graph, entity) and returns a list
of new entities. The engine applies them to new entities discovered at each
depth level.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional

from .entities import (
    Entity,
    EntityType,
    Domain,
    IPAddress,
    Email,
    Person,
    Organization,
    Location,
    make_entity,
)
from .relationships import Relationship, RelationshipType
from .graph import EntityGraph
from .osint_framework import get_framework

logger = logging.getLogger("watson.graph.transforms")

# ── Transform type ───────────────────────────────────────────────
# A transform is an async function that takes the graph + an entity
# and returns new entities to add.

TransformFn = Callable[
    [EntityGraph, Entity],
    Awaitable[list[Entity]],
]


class TransformEngine:
    """Recursive entity transform engine.

    Usage:
        engine = TransformEngine(graph)
        await engine.run(max_depth=3)

    This runs transforms on entities at each depth level. Newly discovered
    entities are added to the graph and become seeds for the next depth.
    """

    def __init__(self, graph: EntityGraph):
        self.graph = graph

        # Registry: entity_type → list of transforms that accept it
        self._registry: dict[EntityType, list[TransformFn]] = {}

        # Register built-in transforms
        self._register_builtins()

    def register(self, entity_type: EntityType, transform: TransformFn) -> None:
        """Register a transform for an entity type."""
        if entity_type not in self._registry:
            self._registry[entity_type] = []
        self._registry[entity_type].append(transform)

    def _register_builtins(self) -> None:
        """Register all built-in Maltego-style transforms."""
        # Infrastructure transforms
        self.register(EntityType.DOMAIN, _dns_resolution)
        self.register(EntityType.DOMAIN, _subdomain_enum)
        self.register(EntityType.DOMAIN, _email_discovery)
        self.register(EntityType.IP_ADDRESS, _ip_geolocation)

        # Reverse-pivot transforms: bridge infrastructure → people/orgs
        self.register(EntityType.EMAIL, _email_to_person)
        self.register(EntityType.PERSON, _person_to_org)
        self.register(EntityType.ORGANIZATION, _org_to_people)

        # Enrichment
        self.register(EntityType.DOMAIN, _osint_enrichment)
        self.register(EntityType.IP_ADDRESS, _osint_enrichment)
        self.register(EntityType.EMAIL, _osint_enrichment)
        self.register(EntityType.PERSON, _osint_enrichment)
        self.register(EntityType.ORGANIZATION, _osint_enrichment)

    # ── Main execution ───────────────────────────────────────────

    async def run(
        self,
        max_depth: int = 3,
        entity_types: Optional[list[EntityType]] = None,
    ) -> int:
        """Run transforms recursively up to max_depth.

        At each depth, applies registered transforms to entities of the
        given types. Newly discovered entities become seeds for the next
        depth. Returns total number of new entities discovered.

        Args:
            max_depth: How many levels of transforms to apply (1-5).
                       Depth 1 = transforms on initial entities.
                       Depth 2 = transforms on entities discovered at depth 1.
                       etc.
            entity_types: Only transform these entity types. None = all.

        Returns:
            Total new entities added to the graph.
        """
        total_new = 0

        # Get initial seeds — entities to transform
        if entity_types:
            seeds = [
                e for et in entity_types
                for e in self.graph.entities_of_type(et)
            ]
        else:
            seeds = list(self.graph.iter_entities())

        if not seeds:
            logger.info("transform_engine: no seed entities to transform")
            return 0

        # Track which entities have been transformed (by ID) to avoid loops
        transformed: set[str] = set()

        for depth in range(1, max_depth + 1):
            new_this_round = 0
            next_seeds: list[Entity] = []

            # Get transforms applicable to current seeds
            for entity in seeds:
                if entity.id in transformed:
                    continue
                transformed.add(entity.id)

                entity_transforms = self._registry.get(entity.entity_type, [])
                if not entity_transforms:
                    continue

                # Run all transforms for this entity type IN PARALLEL
                results = await asyncio.gather(
                    *[tf(self.graph, entity) for tf in entity_transforms],
                    return_exceptions=True,
                )

                for i, result in enumerate(results):
                    if isinstance(result, BaseException):
                        logger.warning(
                            "transform_failed: entity=%s transform=%d error=%s",
                            entity.id[:8], i, result,
                        )
                        continue
                    if not isinstance(result, list):
                        continue

                    for new_entity in result:
                        if new_entity is None:
                            continue
                        try:
                            added = self.graph.add_entity(new_entity)
                            if added.id == new_entity.id and new_entity.id not in transformed:
                                # New entity — add to next round
                                next_seeds.append(new_entity)
                                new_this_round += 1
                        except Exception as e:
                            logger.warning(
                                "transform_add_entity_failed: %s", e,
                            )

            total_new += new_this_round
            logger.info(
                "transform_engine: depth=%d new=%d total=%d graph=%s",
                depth, new_this_round, total_new, self.graph,
            )

            if not next_seeds:
                logger.info("transform_engine: no new seeds — stopping")
                break

            seeds = next_seeds

        return total_new


# ═══════════════════════════════════════════════════════════════════
# Built-in Transforms
# ═══════════════════════════════════════════════════════════════════


async def _dns_resolution(graph: EntityGraph, entity: Entity) -> list[Entity]:
    """Resolve a Domain to its IP addresses using dnspython.

    Creates IPAddress entities and RESOLVES_TO relationships.
    """
    if entity.entity_type != EntityType.DOMAIN:
        return []

    try:
        import dns.resolver
    except ImportError:
        logger.debug("dns_resolution: dnspython not installed, skipping")
        return []

    domain = entity.value
    new_entities: list[Entity] = []

    try:
        answers = await asyncio.to_thread(
            lambda: dns.resolver.resolve(domain, "A")
        )
        for answer in answers:
            ip = answer.to_text()
            ip_entity = make_entity(
                EntityType.IP_ADDRESS,
                ip,
                source="dns_resolution",
                confidence=0.95,
                display_name=f"{ip} (from {domain})",
            )
            new_entities.append(ip_entity)

            # Create relationship
            try:
                rel = Relationship(
                    source_id=entity.id,
                    target_id=ip_entity.id,
                    rel_type=RelationshipType.RESOLVES_TO,
                    confidence=0.95,
                    source_transform="dns_resolution",
                    evidence=[f"DNS A record: {domain} → {ip}"],
                )
                # Add entity first, then relationship
                graph.add_entity(ip_entity)
                graph.add_relationship(rel)
            except ValueError:
                pass  # Entity not in graph yet — will be added later

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        logger.debug("dns_resolution: no A records for %s", domain)
    except Exception as e:
        logger.warning("dns_resolution: %s → %s", domain, e)

    return new_entities


# ── Shared HTTP infrastructure (avoids per-transform client creation) ──

_shared_client = None  # httpx.AsyncClient — created lazily, shared across transforms
_crt_cache: dict[str, list[dict]] = {}  # domain → parsed crt.sh JSON


async def _get_shared_client() -> "httpx.AsyncClient":
    """Return a shared httpx client with connection pooling. Created once per session."""
    global _shared_client
    if _shared_client is None or _shared_client.is_closed:
        import httpx
        _shared_client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
            headers={"User-Agent": "WatsonOSINT/0.4"},
        )
    return _shared_client


async def _fetch_crt(domain: str) -> list[dict]:
    """Fetch crt.sh certificate transparency data for a domain. Results are cached
    so subdomain_enum and email_discovery share a single HTTP call per domain."""
    if domain in _crt_cache:
        return _crt_cache[domain]

    try:
        client = await _get_shared_client()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = await client.get(url)
        if resp.status_code != 200:
            _crt_cache[domain] = []
            return []
        certs = resp.json()
        if not isinstance(certs, list):
            _crt_cache[domain] = []
            return []
        _crt_cache[domain] = certs
        return certs
    except Exception:
        _crt_cache[domain] = []
        return []


async def _subdomain_enum(graph: EntityGraph, entity: Entity) -> list[Entity]:
    """Discover subdomains via crt.sh SSL certificate transparency logs.

    Creates Domain entities and HAS_SUBDOMAIN relationships.
    Uses shared HTTP client + crt.sh cache to avoid duplicate requests.
    """
    if entity.entity_type != EntityType.DOMAIN:
        return []

    domain = entity.value
    new_entities: list[Entity] = []

    try:
        certs = await _fetch_crt(domain)
        if not certs:
            return []

        seen: set[str] = set()
        for cert in certs[:100]:
            names = cert.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lower()
                if not name or name == domain:
                    continue
                if name.startswith("*."):
                    name = name[2:]
                if name in seen:
                    continue
                seen.add(name)

                sub_entity = make_entity(
                    EntityType.DOMAIN,
                    name,
                    source="subdomain_enum",
                    confidence=0.80,
                    display_name=name,
                )
                new_entities.append(sub_entity)

                try:
                    rel = Relationship(
                        source_id=entity.id,
                        target_id=sub_entity.id,
                        rel_type=RelationshipType.HAS_SUBDOMAIN,
                        confidence=0.80,
                        source_transform="subdomain_enum",
                        evidence=[
                            f"https://crt.sh/?q=%25.{domain}"
                        ],
                    )
                    graph.add_entity(sub_entity)
                    graph.add_relationship(rel)
                except ValueError:
                    pass

        if new_entities:
            logger.info(
                "subdomain_enum: %s → %d subdomains",
                domain, len(new_entities),
            )

    except Exception as e:
        logger.warning("subdomain_enum: %s → %s", domain, e)

    return new_entities


async def _ip_geolocation(graph: EntityGraph, entity: Entity) -> list[Entity]:
    """Geolocate an IP address using ip-api.com (free, no API key).

    Creates Location entities and LOCATED_IN relationships.
    """
    if entity.entity_type != EntityType.IP_ADDRESS:
        return []

    ip = entity.value
    new_entities: list[Entity] = []

    # Skip private/reserved IPs
    if _is_private_ip(ip):
        return []

    try:
        import httpx

        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,lat,lon,isp,org,as"
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []

            data = resp.json()
            if data.get("status") != "success":
                return []

            city = data.get("city", "")
            country = data.get("country", "")
            country_code = data.get("countryCode", "")
            lat = data.get("lat", 0.0)
            lon = data.get("lon", 0.0)
            isp = data.get("isp", "")
            org = data.get("org", "")

            # Create location entity
            loc_name = f"{city}, {country}" if city else country
            loc_entity = Location(
                value=loc_name.lower(),
                display_name=loc_name,
                latitude=lat,
                longitude=lon,
                country_code=country_code,
                source="ip_geolocation",
                confidence=0.90,
                properties={
                    "isp": isp,
                    "org": org,
                    "ip": ip,
                },
            )
            new_entities.append(loc_entity)

            # Enrich the IP entity with ISP/ASN info
            if isp:
                entity.properties["isp"] = isp
                entity.display_name = f"{ip} ({isp})"
            if org:
                entity.properties["org"] = org

            try:
                rel = Relationship(
                    source_id=entity.id,
                    target_id=loc_entity.id,
                    rel_type=RelationshipType.LOCATED_IN,
                    confidence=0.90,
                    source_transform="ip_geolocation",
                    evidence=[f"ip-api.com: {ip} → {loc_name}"],
                )
                graph.add_entity(loc_entity)
                graph.add_relationship(rel)
            except ValueError:
                pass

    except Exception as e:
        logger.warning("ip_geolocation: %s → %s", ip, e)

    return new_entities


async def _email_discovery(graph: EntityGraph, entity: Entity) -> list[Entity]:
    """Discover email addresses associated with a domain.

    Searches crt.sh for email references in certificate issuer fields.
    Uses the shared crt.sh cache — avoids a duplicate HTTP call if
    subdomain_enum already fetched this domain.
    """
    if entity.entity_type != EntityType.DOMAIN:
        return []

    domain = entity.value
    new_entities: list[Entity] = []
    seen_emails: set[str] = set()

    try:
        import re

        # Reuse crt.sh data already fetched by subdomain_enum (or fetch now)
        certs = await _fetch_crt(domain)
        if certs:
            email_re = re.compile(r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}')
            for cert in certs[:50]:
                issuer = cert.get("issuer_name", "")
                for match in email_re.finditer(issuer):
                    email = match.group(0).lower()
                    if email not in seen_emails:
                        seen_emails.add(email)

        # Create entity + relationship for each discovered email
        for email in seen_emails:
            email_entity = make_entity(
                EntityType.EMAIL,
                email,
                source="email_discovery",
                confidence=0.55,
                display_name=email,
            )
            new_entities.append(email_entity)

            try:
                rel = Relationship(
                    source_id=entity.id,
                    target_id=email_entity.id,
                    rel_type=RelationshipType.HAS_EMAIL,
                    confidence=0.55,
                    source_transform="email_discovery",
                    evidence=[f"https://crt.sh/?q=%25.{domain}"],
                )
                graph.add_entity(email_entity)
                graph.add_relationship(rel)
            except ValueError:
                pass

        if seen_emails:
            logger.info(
                "email_discovery: %s → %d emails",
                domain, len(seen_emails),
            )

    except Exception as e:
        logger.warning("email_discovery: %s → %s", domain, e)

    return new_entities


async def _osint_enrichment(graph: EntityGraph, entity: Entity) -> list[Entity]:
    """Enrich any entity with OSINT Framework tool links.

    This doesn't create new entities — it enriches the existing entity's
    properties with direct links to OSINT Framework tools relevant to
    this entity type. These links appear in the finding's evidence.

    This is the key integration that compensates for Watson not having
    direct access to paid databases like Maltego does.
    """
    framework = get_framework()

    tools = framework.get_search_urls(
        entity.entity_type,
        entity.value,
        max_results=8,
    )

    if tools:
        entity.properties["osint_framework_tools"] = [
            {"name": t["tool"], "url": t["url"], "category": t["category"]}
            for t in tools
        ]
        entity.source = entity.source or "osint_enrichment"

    return []  # No new entities — enrichment only


# ═══════════════════════════════════════════════════════════════════
# Reverse-Pivot Transforms: Email → Person → Organization
# ═══════════════════════════════════════════════════════════════════
# These bridge the infrastructure graph to the people/organization
# pipeline — the Maltego "pivot to person" equivalent.


async def _email_to_person(graph: EntityGraph, entity: Entity) -> list[Entity]:
    """Extract person identity from an email address.

    - Parses the local part for name patterns (baron.lorenzo → Lorenzo Baron)
    - Checks Have I Been Pwned for breach context
    - Searches the web for identity clues (LinkedIn, GitHub, etc.)

    Creates Person entities and EMAIL→PERSON relationships.
    """
    if entity.entity_type != EntityType.EMAIL:
        return []

    email = entity.value
    new_entities: list[Entity] = []

    if "@" not in email:
        return []

    local_part = email.split("@")[0]
    domain = email.split("@")[1]

    # Skip role-based emails — can't extract person from "support@company.com"
    _role_prefixes = {
        "admin", "support", "info", "contact", "hello", "help",
        "noreply", "no-reply", "postmaster", "abuse", "security",
        "webmaster", "hostmaster", "billing", "jobs", "sales",
        "marketing", "press", "media", "legal", "hr", "office",
    }
    if local_part.lower().rstrip("0123456789") in _role_prefixes:
        logger.debug("email_to_person: skipping role email %s", email)
        return []

    # Parse name from email username
    import re as _re

    # Split on common separators: dots, underscores, hyphens, numbers
    name_parts = _re.sub(r'[\d._\-+]+', ' ', local_part).strip().split()
    name_parts = [p for p in name_parts if len(p) >= 2 and not p.isdigit()]

    if len(name_parts) < 1:
        return []

    # Try both name orders (western: given surname, eastern: surname given)
    candidates: list[tuple[str, str, str, str]] = []  # (full_name, given, surname, entity_value)

    if len(name_parts) == 1:
        # Single name — treat as given name only (low confidence)
        single_name = name_parts[0].title()
        candidates.append((
            single_name,
            name_parts[0],  # given
            "",             # unknown surname
            single_name.lower(),
        ))
    elif len(name_parts) >= 2:
        # Western order: "john.smith" → John Smith (given first)
        # Eastern/Hungarian order: "bodi.ildiko" → Bódi Ildikó (surname first)
        # We try BOTH — creating separate Person entities for each interpretation
        western_display = " ".join(name_parts).title()
        eastern_display = " ".join(reversed(name_parts)).title()

        # Western candidate: given=surname order
        candidates.append((
            western_display,
            name_parts[0],   # given = first
            name_parts[-1],  # surname = last
            western_display.lower(),  # value for entity ID
        ))
        # Eastern candidate: surname=given order (different entity)
        candidates.append((
            eastern_display,
            name_parts[-1],  # given = original last part
            name_parts[0],   # surname = original first part
            eastern_display.lower(),
        ))

    for full_name, given, surname, entity_value in candidates:
        # Skip if it looks like a company name, not a person
        _company_words = {
            "inc", "corp", "ltd", "llc", "gmbh", "group", "holdings",
            "solutions", "technologies", "services", "studio", "agency",
            "team", "department", "office",
        }
        if any(w in _company_words for w in name_parts):
            continue

        person = Person(
            value=entity_value,
            display_name=full_name.title(),
            given_name=given.title(),
            surname=surname.title() if surname else "",
            source="email_to_person",
            confidence=0.35 if not surname else 0.50,  # Lower for single-name
            properties={
                "email": email,
                "domain": domain,
                "extraction_method": "email_username_parsing",
            },
        )
        new_entities.append(person)

        try:
            rel = Relationship(
                source_id=entity.id,
                target_id=person.id,
                rel_type=RelationshipType.OWNS,
                confidence=0.50,
                source_transform="email_to_person",
                evidence=[f"Email username parsed: {local_part} → {full_name}"],
            )
            graph.add_entity(person)
            graph.add_relationship(rel)
        except ValueError:
            pass

    if new_entities:
        logger.info(
            "email_to_person: %s → %d person candidates",
            email, len(new_entities),
        )

    return new_entities


async def _person_to_org(graph: EntityGraph, entity: Entity) -> list[Entity]:
    """Infer organization from a person's context.

    If the person was discovered from an email, the email's domain
    suggests their organization. If from LinkedIn, the company profile.

    Creates Organization entities and WORKS_AT relationships.
    """
    if entity.entity_type != EntityType.PERSON:
        return []

    new_entities: list[Entity] = []

    # Check if this person was derived from an email
    if "email" in entity.properties and "@" in entity.properties["email"]:
        domain = entity.properties["email"].split("@")[-1]

        # Skip known email providers
        _providers = {
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
            "protonmail.com", "icloud.com", "aol.com", "mail.com",
            "gmx.com", "live.com", "msn.com",
        }
        if domain.lower() in _providers:
            return []

        # Create organization from domain
        org_name = domain.split(".")[0].title()
        org = Organization(
            value=domain.lower(),
            display_name=org_name,
            source="person_to_org",
            confidence=0.45,
            properties={
                "domain": domain,
                "inferred_from": entity.value,
            },
        )
        new_entities.append(org)

        try:
            rel = Relationship(
                source_id=entity.id,
                target_id=org.id,
                rel_type=RelationshipType.WORKS_AT,
                confidence=0.45,
                source_transform="person_to_org",
                evidence=[f"Email domain match: {entity.properties['email']}"],
            )
            graph.add_entity(org)
            graph.add_relationship(rel)
        except ValueError:
            pass

    # If this person already has org connections, recurse to find more
    existing_orgs = graph.get_neighbors_by_type(
        entity.id, EntityType.ORGANIZATION
    )
    for org in existing_orgs:
        # Enrich with OSINT Framework corporate tools
        framework = get_framework()
        tools = framework.get_search_urls(
            EntityType.ORGANIZATION,
            org.value,
            max_results=5,
        )
        if tools:
            org.properties["osint_framework_tools"] = [
                {"name": t["tool"], "url": t["url"]}
                for t in tools
            ]

    return new_entities


async def _org_to_people(graph: EntityGraph, entity: Entity) -> list[Entity]:
    """Discover people associated with an organization.

    Searches for publicly listed employees, executives, or contacts.
    Currently uses OSINT Framework links for manual follow-up.
    Future: integrate LinkedIn API, RocketReach, or Hunter.io.
    """
    if entity.entity_type != EntityType.ORGANIZATION:
        return []

    # Enrich org with people-search tool links from OSINT Framework
    framework = get_framework()
    people_tools = framework.get_search_urls(
        EntityType.PERSON,
        entity.value,
        max_results=5,
    )

    if people_tools:
        entity.properties["osint_framework_people_tools"] = [
            {"name": t["tool"], "url": t["url"]}
            for t in people_tools
        ]

    return []  # No new entities — enrichment only (for now)


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False
