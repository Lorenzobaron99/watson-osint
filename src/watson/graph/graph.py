"""EntityGraph — type-safe graph of OSINT entities and relationships.

Pure Python implementation (no networkx dependency). Supports:
  - Adding/querying entities by type, value, or ID
  - Adding typed relationships between entities
  - Traversal queries (neighbors, paths, subgraphs)
  - Export to findings for pipeline integration
  - Import from existing findings (reverse extraction)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterator, Optional

from .entities import (
    Entity,
    EntityType,
    Domain,
    IPAddress,
    Email,
    Person,
    Organization,
    Website,
    Location,
    Document,
    make_entity,
)
from .relationships import (
    Relationship,
    RelationshipType,
)

logger = logging.getLogger("watson.graph")


class EntityGraph:
    """A directed, typed OSINT entity graph.

    Entities are nodes. Relationships are directed edges with a type label.
    The graph supports traversal queries and can export to the existing
    Finding model for pipeline integration.
    """

    def __init__(self):
        # Primary storage
        self._entities: dict[str, Entity] = {}          # id → Entity
        self._relationships: dict[str, Relationship] = {}  # id → Relationship

        # Indexes for fast lookup
        self._by_type: dict[EntityType, set[str]] = defaultdict(set)   # type → {entity_id, ...}
        self._by_value: dict[str, str] = {}              # "type:value" → entity_id
        self._adj_out: dict[str, set[str]] = defaultdict(set)   # source_id → {rel_id, ...}
        self._adj_in: dict[str, set[str]] = defaultdict(set)    # target_id → {rel_id, ...}

    # ── CRUD ─────────────────────────────────────────────────────

    @property
    def entity_count(self) -> int:
        return len(self._entities)

    @property
    def relationship_count(self) -> int:
        return len(self._relationships)

    def has_entity(self, entity_id: str) -> bool:
        return entity_id in self._entities

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        return self._entities.get(entity_id)

    def get_entity_by_value(self, entity_type: EntityType, value: str) -> Optional[Entity]:
        """Look up an entity by type + value (deterministic)."""
        key = f"{entity_type.value}:{value.lower().strip()}"
        entity_id = self._by_value.get(key)
        if entity_id:
            return self._entities.get(entity_id)
        return None

    def add_entity(self, entity: Entity) -> Entity:
        """Add an entity. If it already exists (same ID), merge confidence and properties."""
        existing = self._entities.get(entity.id)
        if existing:
            # Merge: take the higher confidence, merge properties
            existing.confidence = max(existing.confidence, entity.confidence)
            existing.properties.update(entity.properties)
            if entity.source and not existing.source:
                existing.source = entity.source
            return existing

        self._entities[entity.id] = entity
        self._by_type[entity.entity_type].add(entity.id)
        key = f"{entity.entity_type.value}:{entity.value.lower().strip()}"
        self._by_value[key] = entity.id
        return entity

    def add_relationship(self, rel: Relationship) -> Relationship:
        """Add a relationship between two entities. Both must exist."""
        if rel.id in self._relationships:
            return self._relationships[rel.id]

        if rel.source_id not in self._entities:
            raise ValueError(f"Source entity {rel.source_id} not in graph")
        if rel.target_id not in self._entities:
            raise ValueError(f"Target entity {rel.target_id} not in graph")

        self._relationships[rel.id] = rel
        self._adj_out[rel.source_id].add(rel.id)
        self._adj_in[rel.target_id].add(rel.id)
        return rel

    def add_or_get(self, entity_type: EntityType, value: str, **kwargs) -> Entity:
        """Convenience: get existing entity or create + add a new one."""
        existing = self.get_entity_by_value(entity_type, value)
        if existing:
            return existing
        entity = make_entity(entity_type, value, **kwargs)
        return self.add_entity(entity)

    # ── Traversal ─────────────────────────────────────────────────

    def get_outgoing(self, entity_id: str) -> list[Relationship]:
        """Get all relationships where entity is the source."""
        rel_ids = self._adj_out.get(entity_id, set())
        return [self._relationships[rid] for rid in rel_ids if rid in self._relationships]

    def get_incoming(self, entity_id: str) -> list[Relationship]:
        """Get all relationships where entity is the target."""
        rel_ids = self._adj_in.get(entity_id, set())
        return [self._relationships[rid] for rid in rel_ids if rid in self._relationships]

    def get_neighbors(self, entity_id: str) -> list[Entity]:
        """Get all entities directly connected to this one."""
        neighbors: dict[str, Entity] = {}
        for rel in self.get_outgoing(entity_id):
            if rel.target_id in self._entities:
                neighbors[rel.target_id] = self._entities[rel.target_id]
        for rel in self.get_incoming(entity_id):
            if rel.source_id in self._entities:
                neighbors[rel.source_id] = self._entities[rel.source_id]
        return list(neighbors.values())

    def get_neighbors_by_type(
        self, entity_id: str, entity_type: EntityType
    ) -> list[Entity]:
        """Get neighbors of a specific type."""
        return [
            e for e in self.get_neighbors(entity_id)
            if e.entity_type == entity_type
        ]

    def entities_of_type(self, entity_type: EntityType) -> list[Entity]:
        """Get all entities of a given type."""
        ids = self._by_type.get(entity_type, set())
        return [self._entities[eid] for eid in ids if eid in self._entities]

    def iter_entities(self) -> Iterator[Entity]:
        """Iterate over all entities."""
        yield from self._entities.values()

    def iter_relationships(self) -> Iterator[Relationship]:
        """Iterate over all relationships."""
        yield from self._relationships.values()

    # ── Import from findings ──────────────────────────────────────

    def ingest_findings(
        self,
        findings: list,
        source_transform: str = "surface_ingest",
    ) -> int:
        """Extract entities from existing investigation findings.

        Parses finding titles/descriptions for domains, IPs, emails, and
        adds them to the graph. Returns number of entities added.

        This is the bridge between the existing pipeline and the graph engine.
        It does NOT modify the pipeline — it reads findings and populates the
        graph for further enrichment.
        """
        import re
        added = 0

        # Extraction patterns
        _domain_re = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}\b'
        )
        _ip_re = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        _email_re = re.compile(r'\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b')

        # Known publisher/platform domains to skip during graph ingestion.
        # These are news outlets, social media, blogging platforms, and other
        # domains that appear in findings as *sources* rather than as the
        # subject of investigation. Kept broad to minimize noise while
        # allowing real domains (openai.com, gratitudamerica.org, etc.) through.
        _skip_domains = {
            # ── Social media / platforms ──
            "linkedin.com", "twitter.com", "x.com", "facebook.com", "fb.com",
            "instagram.com", "github.com", "youtube.com", "youtu.be",
            "reddit.com", "t.me", "telegram.org", "whatsapp.com",
            "tiktok.com", "snapchat.com", "pinterest.com", "discord.com",
            "twitch.tv", "vimeo.com", "dailymotion.com",
            # ── Reference / wiki ──
            "wikipedia.org", "wikidata.org", "wikimedia.org",
            "web.archive.org", "archive.org", "archive.is", "archive.today",
            "snopes.com", "politifact.com", "factcheck.org",
            # ── Search / email / infra (never targets) ──
            "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
            "amazon.com",  # IP WHOIS noise
            "gmail.com", "outlook.com", "hotmail.com", "protonmail.com",
            "live.com", "icloud.com", "mail.com", "yandex.com",
            "googlemail.com",  # MX record noise
            # ── Blogging / newsletter platforms ──
            "medium.com", "substack.com", "wordpress.com", "blogspot.com",
            "blogger.com", "tumblr.com", "ghost.io", "typepad.com",
            # ── Major US/UK news ──
            "nytimes.com", "washingtonpost.com", "wsj.com", "bloomberg.com",
            "reuters.com", "apnews.com", "bbc.com", "bbc.co.uk",
            "cnn.com", "foxnews.com", "nbcnews.com", "cbsnews.com",
            "abcnews.go.com", "usatoday.com", "latimes.com", "chicagotribune.com",
            "theguardian.com", "independent.co.uk", "telegraph.co.uk",
            "dailymail.co.uk", "mirror.co.uk", "nypost.com", "newsweek.com",
            "time.com", "politico.com", "axios.com", "thehill.com",
            # ── European / international news (publisher domains from OSINT findings) ──
            "digi24.ro", "adevarul.ro", "knews.media", "monitorulcj.ro",
            "informat.ro", "hotnews.ro", "stirileprotv.ro", "mediafax.ro",
            "ziare.com", "gandul.ro", "libertatea.ro", "evz.ro",
            "spiegel.de", "zeit.de", "faz.net", "sueddeutsche.de",
            "dw.com", "bild.de", "welt.de", "tagesschau.de",
            "lemonde.fr", "lefigaro.fr", "liberation.fr", "france24.com",
            "elpais.com", "elmundo.es", "abc.es", "lavanguardia.com",
            "corriere.it", "repubblica.it", "lastampa.it", "ilsole24ore.com",
            "ansa.it", "rainews.it", "ilfattoquotidiano.it",
            "rferl.org", "euractiv.com", "euronews.com",
            # ── Business / tech news ──
            "forbes.com", "fortune.com", "inc.com", "entrepreneur.com",
            "businessinsider.com", "insider.com", "fastcompany.com",
            "techcrunch.com", "theverge.com", "arstechnica.com", "wired.com",
            "engadget.com", "gizmodo.com", "mashable.com", "thenextweb.com",
            "zdnet.com", "cnet.com",
            # ── General-interest / long-form ──
            "vox.com", "slate.com", "salon.com", "thedailybeast.com",
            "buzzfeed.com", "buzzfeednews.com", "vice.com",
            "huffpost.com", "huffingtonpost.com", "theatlantic.com",
            "newyorker.com", "vanityfair.com", "rollingstone.com",
            "esquire.com", "qz.com", "recode.net",
            "motherjones.com", "prospect.org", "newrepublic.com",
            "thenation.com", "nationalreview.com",
            # ── AOL / legacy portals ──
            "aol.com", "msn.com",
            # ── Legal/crime news (publishers, not registries) ──
            "npr.org", "legalclarity.org", "ukcolumn.org",
            # ── OSINT / investigative tools (not targets) ──
            "opensanctions.org", "crt.sh", "shodan.io",
            "censys.io", "zoomeye.org", "fofa.info",
            "urlscan.io", "virustotal.com", "abuseipdb.com",
            "opencorporates.com",  # corporate registry tool
            # ── Financial / legal reference sites (publishers, not targets) ──
            "gurufocus.com", "natlawreview.com",
            "cornerstone.com",  # legal research firm
            "johnsonfistel.com",  # law firm
            # ── Profile / platform domains (NOT targets — profile hosts) ──
            "happenstance.ai",  # AI profile aggregator
            "authortrends.com",  # author directory platform
            "jailexchange.com",  # jail inmate lookup platform
            "courtcasefinder.com",  # court case aggregator
            "volza.com",  # B2B trade platform
            "rocketreach.co", "rocketreach.com",  # email finders
            "signalhire.com",  # recruiting platform
            "zoominfo.com",  # B2B contact database
            "marketscreener.com",  # financial profile aggregator
            "researchgate.net",  # academic profile host
            # ── Aggregators / link shorteners ──
            "apple.news", "news.google.com", "flipboard.com",
            "bit.ly", "tinyurl.com", "ow.ly", "buff.ly", "t.co",
            # ── Political / activism platforms (source URLs, not targets) ──
            "abgeordnetenwatch.de", "bewegung.social", "change.org",
            "petition.org.uk", "avaaz.org", "openpetition.de",
            # ── GitHub proxy / mirror sites (never targets) ──
            "githubhosts.xuanyuan.me",
            # ── CDN / image hosts / file hosting ──
            "iconarchive.com", "flaticon.com", "shutterstock.com",
            "gettyimages.com", "istockphoto.com", "unsplash.com",
            "pexels.com", "pixabay.com", "freepik.com", "vecteezy.com",
            "cloudfront.net", "akamai.net", "akamaized.net",
            "fastly.net", "jsdelivr.net", "cdn.jsdelivr.net",
            "unpkg.com", "cdnjs.com", "googleapis.com",
            "gstatic.com", "googleusercontent.com",
            "dropbox.com", "box.com", "drive.google.com",
            "onedrive.live.com", "mega.nz", "mediafire.com",
            "zippyshare.com", "wetransfer.com",
            "s123-cdn-static.com", "s123-cdn-static-c.com",
            "shopify.com", "myshopify.com",
            # ── Known spam / parked domains ──
            # None hardcoded; the heuristics below catch .top, .xyz, etc.
        }

        # TLDs overwhelmingly used for spam/parked domains — skip all
        _skip_tlds = {".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq"}

        def _should_skip_domain(domain: str) -> bool:
            """Check if a domain should be skipped based on blocklist + TLD."""
            if domain in _skip_domains:
                return True
            # Parent domain check
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                if ".".join(parts[i:]) in _skip_domains:
                    return True
            # AWS DNS / infrastructure noise (ns-N.awsdns-M.*)
            if any("awsdns" in part for part in parts):
                return True
            # Spam TLD check
            if any(domain.endswith(tld) for tld in _skip_tlds):
                return True
            return False

        for f in findings:
            title = getattr(f, "title", "") or ""
            desc = getattr(f, "description", "") or ""
            text = f"{title} {desc}"
            source_url = getattr(f, "source_url", "") or ""

            # Extract domains
            for match in _domain_re.finditer(text):
                domain = match.group(0).lower().rstrip(".")
                # Normalize: strip 'www.' prefix
                if domain.startswith("www."):
                    domain = domain[4:]
                if _should_skip_domain(domain):
                    continue
                entity = self.add_or_get(
                    EntityType.DOMAIN, domain,
                    source=source_transform,
                    confidence=0.75,
                )
                if entity.source == source_transform:
                    added += 1

            # Extract IPs
            for match in _ip_re.finditer(text):
                ip = match.group(0)
                entity = self.add_or_get(
                    EntityType.IP_ADDRESS, ip,
                    source=source_transform,
                    confidence=0.85,
                )
                if entity.source == source_transform:
                    added += 1

            # Extract emails
            for match in _email_re.finditer(text):
                email = match.group(0).lower()
                if any(skip in email for skip in _skip_domains):
                    continue
                entity = self.add_or_get(
                    EntityType.EMAIL, email,
                    source=source_transform,
                    confidence=0.70,
                )
                if entity.source == source_transform:
                    added += 1

        logger.info(
            "graph_ingest: %d entities from %d findings → graph now has %d entities",
            added, len(findings), self.entity_count,
        )
        return added

    # ── Export ────────────────────────────────────────────────────

    def to_findings(self, source_transform: str = "graph_enrichment") -> list:
        """Convert graph entities and relationships into Finding objects.

        Returns a list compatible with the existing pipeline's Finding model.
        Each entity becomes a finding, and significant relationships become
        findings as well.
        """
        findings = []

        for entity in self._entities.values():
            # Skip entities that came from the original pipeline (already findings)
            if entity.source and entity.source not in (
                "dns_resolution", "ip_geolocation", "email_extraction",
                "subdomain_enum", "graph_enrichment", "transform_chain",
            ):
                continue

            # Create a finding for each graph-discovered entity
            f = self._entity_to_finding(entity, source_transform)
            if f:
                findings.append(f)

        # Add relationship findings for significant connections
        for rel in self._relationships.values():
            if rel.source_transform and rel.source_transform not in (
                "surface_ingest", "initial",
            ):
                f = self._rel_to_finding(rel)
                if f:
                    findings.append(f)

        return findings

    def _entity_to_finding(self, entity: Entity, source_transform: str):
        """Convert a single entity to a Finding."""
        from uuid import uuid4

        type_labels = {
            EntityType.DOMAIN: "🌐",
            EntityType.IP_ADDRESS: "📍",
            EntityType.EMAIL: "✉️",
            EntityType.PERSON: "👤",
            EntityType.ORGANIZATION: "🏢",
            EntityType.WEBSITE: "🔗",
            EntityType.LOCATION: "🗺️",
            EntityType.DOCUMENT: "📄",
        }
        icon = type_labels.get(entity.entity_type, "🔍")

        return {
            "id": f"graph-{uuid4().hex[:12]}",
            "source": "graph_enrichment",
            "tool": source_transform,
            "title": f"{icon} {entity.display_name}",
            "description": (
                f"Discovered {entity.entity_type.value}: **{entity.value}**\n"
                f"Confidence: {entity.confidence:.0%} | Source: {entity.source or 'graph transform'}"
            ),
            "evidence": entity.properties.get("evidence", []),
            "severity": "info",
            "confidence": entity.confidence,
            "timestamp": entity.discovered_at.isoformat(),
            "metadata": entity.to_dict(),
        }

    def _rel_to_finding(self, rel: Relationship):
        """Convert a significant relationship to a Finding."""
        from uuid import uuid4

        source = self._entities.get(rel.source_id)
        target = self._entities.get(rel.target_id)
        if not source or not target:
            return None

        return {
            "id": f"graph-rel-{uuid4().hex[:12]}",
            "source": "graph_enrichment",
            "tool": rel.source_transform or "graph_relationship",
            "title": f"🔗 {source.display_name} → {rel.rel_type.value} → {target.display_name}",
            "description": (
                f"Connection discovered: **{source.value}** "
                f"({source.entity_type.value}) is linked to "
                f"**{target.value}** ({target.entity_type.value}) "
                f"via **{rel.rel_type.value}**.\n"
                f"Confidence: {rel.confidence:.0%}"
            ),
            "evidence": rel.evidence,
            "severity": "info",
            "confidence": rel.confidence,
            "timestamp": rel.created_at.isoformat(),
            "metadata": rel.to_dict(),
        }

    # ── Stats ─────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return summary statistics."""
        return {
            "entity_count": self.entity_count,
            "relationship_count": self.relationship_count,
            "by_type": {
                et.value: len(ids)
                for et, ids in self._by_type.items()
                if ids
            },
        }

    def __repr__(self) -> str:
        return (
            f"<EntityGraph {self.entity_count} entities, "
            f"{self.relationship_count} relationships>"
        )
