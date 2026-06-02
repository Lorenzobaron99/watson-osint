"""
Investigation engine — Watson's core methodology.

Multi-angle parallel dispatch with cross-referencing,
knowledge graph integration, and structured case generation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .agents.base import AgentAdapter, InvestigationResult
from .graph import KnowledgeGraph


@dataclass
class Finding:
    """A single finding with source, confidence, and evidence."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    description: str = ""
    source_type: str = ""  # web_search, api, browser, vision
    source_url: str = ""
    confidence: float = 0.5  # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)
    entities: list[dict] = field(default_factory=list)  # [{type, value, label}]


@dataclass
class InvestigationCase:
    """A complete investigation case."""
    id: str = field(default_factory=lambda: f"CASE-{uuid.uuid4().hex[:8].upper()}")
    query: str = ""
    target_type: str = ""  # person, domain, company, email, topic, etc.
    angles: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    cross_references: list[dict] = field(default_factory=list)
    graph_updates: dict = field(default_factory=dict)
    markdown: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    published: bool = False  # free tier: published to community MCP


# ── Angle definitions by target type ───────────────────────────

ANGLE_DEFINITIONS: dict[str, list[dict]] = {
    "person": [
        {"name": "Social Media Presence", "query_template": '"{name}" site:linkedin.com OR site:twitter.com OR site:instagram.com OR site:github.com OR site:facebook.com'},
        {"name": "Username Enumeration", "query_template": '"{name}" username OR @ OR profile — cross-platform social media accounts'},
        {"name": "Professional History", "query_template": '"{name}" company OR founder OR CEO OR director OR worked at'},
        {"name": "Public Records", "query_template": '"{name}" public records OR court OR filing OR registration'},
        {"name": "News & Media", "query_template": '"{name}" news OR article OR press OR interview OR scandal OR controversy'},
        {"name": "Corporate Ties", "query_template": '"{name}" company director OR shareholder OR beneficial owner — OpenCorporates OpenSanctions'},
    ],
    "domain": [
        {"name": "SSL Certificate History", "query_template": "crt.sh certificate transparency {domain}"},
        {"name": "DNS & Infrastructure", "query_template": "{domain} DNS records nameservers hosting provider"},
        {"name": "Wayback History", "query_template": "site:web.archive.org {domain}"},
        {"name": "WHOIS Registration", "query_template": "{domain} whois registrant owner registration history"},
        {"name": "Related Domains", "query_template": "{domain} subdomains related domains same owner"},
        {"name": "Security Reputation", "query_template": "{domain} malware phishing scam review — VirusTotal urlscan.io"},
    ],
    "company": [
        {"name": "Corporate Registry", "query_template": '"{company}" OpenCorporates Companies House registration'},
        {"name": "Sanctions & Watchlists", "query_template": '"{company}" sanctions OFAC EU UN watchlist restricted'},
        {"name": "Financial Leaks", "query_template": '"{company}" offshore leaks Panama Papers ICIJ OCCRP'},
        {"name": "News & Controversy", "query_template": '"{company}" scandal fraud investigation lawsuit settlement'},
        {"name": "Leadership & Owners", "query_template": '"{company}" CEO founder director beneficial owner shareholder'},
        {"name": "Supply Chain", "query_template": '"{company}" supply chain import export shipping subsidiaries'},
    ],
    "email": [
        {"name": "Breach Check", "query_template": '"{email}" data breach leak exposed — HaveIBeenPwned DeHashed'},
        {"name": "Account Association", "query_template": '"{email}" account profile social media'},
        {"name": "Domain Investigation", "query_template": "{domain_part} domain investigation WHOIS owner"},
    ],
    "topic": [
        {"name": "News Coverage", "query_template": "{query} news OR investigation OR report OR analysis"},
        {"name": "Academic Research", "query_template": "{query} research paper study analysis site:arxiv.org OR site:scholar.google.com"},
        {"name": "Social Conversation", "query_template": "{query} site:reddit.com OR site:twitter.com OR site:t.me"},
        {"name": "OSINT Databases", "query_template": "{query} site:wikileaks.org OR site:occrp.org OR site:bellingcat.com"},
        {"name": "Knowledge Bases", "query_template": "{query} site:wikidata.org OR site:wikipedia.org"},
    ],
    "image": [
        {"name": "Reverse Image Search", "query_template": "reverse image search {description} — Google Images Yandex TinEye"},
        {"name": "Geolocation Clues", "query_template": "geolocation landmarks signs architecture vegetation climate"},
        {"name": "Metadata Analysis", "query_template": "EXIF metadata analysis image forensics FotoForensics"},
        {"name": "Context & Source", "query_template": "image source origin first posted viral spread"},
    ],
}


class InvestigationEngine:
    """Watson's core investigation engine — multi-angle dispatch + graph integration."""

    # ── Bellingcat investigation angles by target type ──────────

    INVESTIGATION_ANGLES: dict[str, list[str]] = {
        "person": [
            "Social media presence and digital footprint",
            "Professional history and corporate ties",
            "Public records, legal, and court documents",
            "News coverage and media mentions",
            "Username enumeration across platforms",
            "Associated domains, emails, and infrastructure",
        ],
        "domain": [
            "SSL certificate transparency and subdomains (crt.sh)",
            "DNS records, nameservers, and hosting infrastructure",
            "Wayback Machine historical snapshots",
            "WHOIS registration history and registrant identity",
            "Related domains and infrastructure sharing",
            "Security reputation (VirusTotal, urlscan.io)",
        ],
        "company": [
            "Corporate registry records (OpenCorporates, Companies House)",
            "Sanctions, watchlists, and compliance databases",
            "Offshore leaks and financial investigations",
            "Leadership, beneficial owners, and directors",
            "News coverage, controversies, and legal actions",
            "Supply chain and subsidiary mapping",
        ],
        "email": [
            "Data breach exposure (HIBP, DeHashed, IntelX)",
            "Account association across platforms",
            "Domain ownership and infrastructure",
        ],
        "topic": [
            "News coverage across multiple sources and languages",
            "Academic research and institutional publications",
            "Social media discourse and community discussion",
            "OSINT databases and investigative journalism",
        ],
        "image": [
            "Reverse image search across multiple engines",
            "Geolocation estimation from visual clues",
            "Metadata extraction and forensic analysis",
            "Source tracing and first-appearance tracking",
        ],
    }

    # ── Source recommendations by target type ───────────────────

    RECOMMENDED_SOURCES: dict[str, list[str]] = {
        "person": [
            "OpenSanctions (sanctions and watchlists)",
            "ICIJ Offshore Leaks (financial connections)",
            "OCCRP Aleph (investigative data)",
            "Have I Been Pwned (breach exposure)",
            "WhatsMyName (username enumeration)",
            "OpenCorporates (corporate roles)",
        ],
        "domain": [
            "crt.sh (SSL certificate transparency)",
            "urlscan.io (domain scanning)",
            "Shodan / Censys (infrastructure)",
            "Wayback Machine (historical snapshots)",
            "VirusTotal (security reputation)",
            "SecurityTrails (DNS history)",
        ],
        "company": [
            "OpenCorporates (company registry)",
            "OpenSanctions (sanctions check)",
            "ICIJ Offshore Leaks (financial)",
            "OCCRP Aleph (investigative data)",
            "SEC EDGAR (US filings)",
            "Companies House (UK registry)",
        ],
        "email": [
            "Have I Been Pwned (breach check)",
            "DeHashed (credential exposure)",
            "IntelX (intelligence search)",
        ],
    }

    def __init__(
        self,
        agent: AgentAdapter,
        graph: KnowledgeGraph | None = None,
        cases_dir: str | Path = "~/watson-cases",
        max_concurrent_angles: int = 4,
    ):
        self.agent = agent
        self.graph = graph or KnowledgeGraph()
        self.cases_dir = Path(cases_dir).expanduser().resolve()
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self.max_concurrent = max_concurrent_angles

    def _classify_target(self, query: str) -> str:
        """Heuristic target type classification."""
        import re
        q = query.lower().strip()

        if re.search(r"\.(com|org|net|io|gov|edu|uk|de|fr|ru|cn|ai|dev)\b", q):
            return "domain"
        if re.search(r"@[\w.-]+\.\w+", q):
            return "email"
        if re.search(r"^(what|who|how|why).*(company|organization|corp|inc|ltd)", q):
            return "company"
        if re.search(r"(image|photo|picture|screenshot)", q):
            return "image"
        if re.search(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b", query):
            return "person"
        return "topic"

    def _resolve_angles(self, target_type: str, query: str) -> list[str]:
        """Get investigation angles for a target type, resolving templates."""
        angles = self.INVESTIGATION_ANGLES.get(target_type, self.INVESTIGATION_ANGLES["topic"])
        return [angle for angle in angles]

    def _get_search_queries(self, target_type: str, query: str) -> list[tuple[str, str]]:
        """Generate concrete search queries from angle definitions."""
        angle_defs = ANGLE_DEFINITIONS.get(target_type, ANGLE_DEFINITIONS["topic"])
        queries = []
        for ad in angle_defs:
            template = ad["query_template"]
            # Simple template resolution
            resolved = template
            resolved = resolved.replace("{query}", query)
            resolved = resolved.replace("{name}", query)
            resolved = resolved.replace("{company}", query)
            resolved = resolved.replace("{domain}", query)
            resolved = resolved.replace("{email}", query)

            # Extract domain part for email investigations
            import re
            domain_match = re.search(r"@(.+)", query)
            domain_part = domain_match.group(1) if domain_match else query
            resolved = resolved.replace("{domain_part}", domain_part)

            resolved = resolved.replace("{description}", query)
            queries.append((ad["name"], resolved))
        return queries

    async def investigate(self, query: str) -> InvestigationCase:
        """Run a full multi-angle investigation.

        1. Classify target type
        2. Check knowledge graph for prior findings
        3. Dispatch parallel investigation angles
        4. Cross-reference results
        5. Generate case .md
        6. Write to knowledge graph

        Returns a complete InvestigationCase.
        """
        # Strip common prefixes
        clean_query = query
        for prefix in ("investigate ", "research ", "look up ", "find ", "search for "):
            if clean_query.lower().startswith(prefix):
                clean_query = clean_query[len(prefix):]
                break

        target_type = self._classify_target(clean_query)
        angles = self._resolve_angles(target_type, clean_query)
        search_queries = self._get_search_queries(target_type, clean_query)

        # ── Phase 0: Check knowledge graph ──────────────────────
        graph_context = self.graph.context_for_investigation(query)
        prior_entities = graph_context.get("known_entities", [])
        prior_relations = graph_context.get("prior_relations", [])

        # ── Phase 1: Parallel angle dispatch ────────────────────
        sem = asyncio.Semaphore(self.max_concurrent)

        async def run_angle(idx: int, angle: str, search_q: str) -> tuple[int, InvestigationResult]:
            async with sem:
                result = await self.agent.investigate_angle(angle, search_q)
                return idx, result

        tasks = [
            run_angle(i, angles[i], sq[1])
            for i, sq in enumerate(search_queries[: self.max_concurrent])
        ]
        angle_results = await asyncio.gather(*tasks, return_exceptions=True)

        # ── Phase 2: Collect findings ───────────────────────────
        findings: list[Finding] = []
        for result in angle_results:
            if isinstance(result, BaseException):
                continue
            idx, angle_result = result
            # Convert InvestigationResult to Findings
            for f_data in angle_result.findings:
                findings.append(Finding(
                    title=f_data.get("title", angles[idx]),
                    description=f_data.get("snippet", ""),
                    source_type="web_search",
                    source_url=f_data.get("url", ""),
                    confidence=angle_result.confidence,
                    evidence=f_data.get("url", "").split() if f_data.get("url") else [],
                ))
            # If no findings, still record the angle
            if not angle_result.findings:
                findings.append(Finding(
                    title=f"✓ Angle completed: {angles[idx]}",
                    description=angle_result.raw[:500] if angle_result.raw else f"Searched: {search_queries[idx][1]}",
                    source_type="agent",
                    confidence=self._estimate_confidence(angle_result.raw),
                    evidence=[search_queries[idx][1]],
                ))

        # ── Phase 3: Cross-reference ────────────────────────────
        cross_refs = self._cross_reference(findings, prior_entities, prior_relations)

        # ── Phase 4: Build case ─────────────────────────────────
        case = InvestigationCase(
            query=query,
            target_type=target_type,
            angles=angles[:self.max_concurrent],
            findings=findings,
            cross_references=cross_refs,
        )

        # ── Phase 5: Generate markdown ──────────────────────────
        case.markdown = self._generate_markdown(case, graph_context)

        # ── Phase 6: Write to knowledge graph ───────────────────
        self._update_graph(case)

        # ── Phase 7: Save case file ─────────────────────────────
        self._save_case(case)

        return case

    @staticmethod
    def _estimate_confidence(raw: str) -> float:
        """Estimate confidence from the richness of LLM output."""
        if not raw:
            return 0.1
        score = 0.3  # base
        import re
        if re.search(r'https?://', raw):
            score += 0.15  # has URLs
        if re.search(r'\b\d{4}\b', raw):
            score += 0.1   # has dates/years
        if re.search(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', raw):
            score += 0.1   # has proper names
        if len(raw) > 500:
            score += 0.1   # substantial content
        if re.search(r'(confirmed|verified|documented|recorded|registered|published)', raw, re.I):
            score += 0.05  # evidence language
        return min(score, 0.85)

    def _cross_reference(
        self,
        findings: list[Finding],
        prior_entities: list[dict],
        prior_relations: list[dict],
    ) -> list[dict]:
        """Cross-reference findings with each other and with prior graph data."""
        refs = []

        # Cross-reference new findings
        for i, f1 in enumerate(findings):
            for j, f2 in enumerate(findings):
                if j <= i:
                    continue
                words_a = set(w.lower() for w in f1.title.split() if w[0].isupper() or len(w) > 5)
                words_b = set(w.lower() for w in f2.title.split() if w[0].isupper() or len(w) > 5)
                overlap = words_a & words_b
                meaningful = {w for w in overlap if len(w) > 4}
                if len(meaningful) >= 2:
                    refs.append({
                        "type": "new_cross_ref",
                        "finding_a": f1.title,
                        "finding_b": f2.title,
                        "shared_terms": sorted(meaningful),
                        "confidence": min(f1.confidence, f2.confidence),
                    })

        # Cross-reference with prior graph data
        for prior in prior_entities:
            for f in findings:
                if prior["value"].lower() in f.title.lower():
                    refs.append({
                        "type": "graph_link",
                        "finding": f.title,
                        "prior_entity": prior["value"],
                        "prior_type": prior["type"],
                        "prior_cases": prior.get("case_ids", []),
                    })

        return refs

    def _generate_markdown(self, case: InvestigationCase, graph_context: dict) -> str:
        """Generate a Bellingcat-style investigation brief in markdown."""
        total_findings = len(case.findings)
        high_conf = sum(1 for f in case.findings if f.confidence >= 0.7)
        med_conf = sum(1 for f in case.findings if 0.4 <= f.confidence < 0.7)
        low_conf = sum(1 for f in case.findings if f.confidence < 0.4)

        lines = [
            f"# 🔍 Watson Investigation Brief",
            f"",
            f"**Case ID:** {case.id}",
            f"**Date:** {case.created_at[:10]}",
            f"**Target:** {case.query}",
            f"**Target Type:** {case.target_type}",
            f"**Angles Investigated:** {len(case.angles)}",
            f"**Findings:** {total_findings} ({high_conf} high, {med_conf} medium, {low_conf} low confidence)",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
        ]

        # Summary paragraph
        if high_conf > 0:
            lines.append(f"Investigation of **{case.query}** yielded {total_findings} findings across {len(case.angles)} angles, with {high_conf} high-confidence hits.")
        else:
            lines.append(f"Investigation of **{case.query}** across {len(case.angles)} angles produced {total_findings} findings. Further investigation recommended.")

        # Graph context
        prior_entities = graph_context.get("known_entities", [])
        if prior_entities:
            lines.append(f"\n⚠️ **Prior Knowledge:** {len(prior_entities)} related entities found in Watson's knowledge graph from {len(graph_context.get('relevant_cases', []))} previous cases.")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## Investigation Angles",
            f"",
        ])

        for i, angle in enumerate(case.angles, 1):
            angle_findings = [f for f in case.findings if angle.lower() in f.title.lower() or i == len(case.angles)]
            count = len(angle_findings) if angle_findings else 0
            lines.append(f"### {i}. {angle} ({count} findings)")
            lines.append(f"")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## Key Evidence",
            f"",
        ])

        for f in case.findings:
            conf_icon = "🟢" if f.confidence >= 0.7 else "🟡" if f.confidence >= 0.4 else "🔴"
            lines.append(f"- {conf_icon} **{f.title}** — {f.description[:200]}")
            if f.source_url:
                lines.append(f"  - Source: {f.source_url}")
            if f.evidence:
                for ev in f.evidence[:3]:
                    lines.append(f"  - Evidence: {ev}")

        # Cross-references
        if case.cross_references:
            lines.extend([
                f"",
                f"---",
                f"",
                f"## Cross-References",
                f"",
            ])
            for cr in case.cross_references[:10]:
                if cr["type"] == "graph_link":
                    lines.append(f"- 🔗 **Graph Link:** \"{cr['finding'][:80]}...\" connects to prior entity **{cr['prior_entity']}** ({cr['prior_type']}) from cases: {', '.join(cr.get('prior_cases', []))}")
                else:
                    lines.append(f"- 🔗 **Internal:** \"{cr['finding_a'][:60]}...\" ↔ \"{cr['finding_b'][:60]}...\" (terms: {', '.join(cr['shared_terms'][:5])})")

        # Graph updates
        lines.extend([
            f"",
            f"---",
            f"",
            f"## Knowledge Graph",
            f"",
            f"This case has been indexed in Watson's investigation graph.",
            f"Future investigations will auto-surface these connections.",
            f"",
        ])

        if prior_entities:
            lines.append(f"**Prior connections found:** {len(prior_entities)} entities from {len(graph_context.get('relevant_cases', []))} cases.")
            for pe in prior_entities[:5]:
                lines.append(f"- {pe['type']}: **{pe['value']}** (seen in {len(pe.get('case_ids', []))} cases)")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## Follow-up Questions",
            f"",
        ])

        if case.target_type == "domain":
            lines.extend([
                f"- Who registered this domain, and when?",
                f"- What other domains share the same infrastructure?",
                f"- Has the content changed significantly over time?",
                f"- Is the owner connected to any known entities in the graph?",
            ])
        elif case.target_type == "person":
            lines.extend([
                f"- What organizations is this person affiliated with?",
                f"- Are there any legal or regulatory actions involving them?",
                f"- What is their professional history and network?",
                f"- Do they appear in any data breaches or leaks?",
            ])
        elif case.target_type == "company":
            lines.extend([
                f"- Who are the beneficial owners and directors?",
                f"- Are there any sanctions or watchlist entries?",
                f"- What is the company's financial and legal history?",
                f"- What subsidiaries or related entities exist?",
            ])
        else:
            lines.extend([
                f"- What additional sources could provide more context?",
                f"- Are there related entities worth investigating?",
                f"- What timeline does the evidence suggest?",
            ])

        lines.extend([
            f"",
            f"---",
            f"",
            f"*Generated by Watson OSINT — Bellingcat-inspired investigation engine*",
            f"*{case.created_at[:19]}*",
            f"",
        ])

        return "\n".join(lines)

    def _update_graph(self, case: InvestigationCase) -> None:
        """Write investigation findings to the knowledge graph."""
        graph_updates = {"entities": 0, "relations": 0}

        # Extract entities from findings
        import re
        for finding in case.findings:
            # Extract domain-like patterns
            domains = re.findall(r'[\w.-]+\.(com|org|net|io|gov|edu|uk|de|fr|ru|ai|dev)\b', finding.title + " " + finding.description)
            for domain in domains:
                full_domain = re.search(rf'([\w.-]+\.{domain})', finding.title + " " + finding.description)
                if full_domain:
                    self.graph.upsert_entity("domain", full_domain.group(1), case.id)
                    graph_updates["entities"] += 1

            # Extract person names (capitalized first+last)
            names = re.findall(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', finding.title)
            for name in names[:3]:
                if name.lower() not in ("google safe", "wayback machine", "open source", "united states", "have been"):
                    self.graph.upsert_entity("person", name, case.id)
                    graph_updates["entities"] += 1

        case.graph_updates = graph_updates

    def _save_case(self, case: InvestigationCase) -> Path:
        """Save case markdown to the cases directory."""
        filename = f"{case.id}.md"
        filepath = self.cases_dir / filename
        filepath.write_text(case.markdown)
        return filepath

    def load_case(self, case_id: str) -> Optional[str]:
        """Load a case by ID."""
        filepath = self.cases_dir / f"{case_id}.md"
        if filepath.exists():
            return filepath.read_text()
        return None

    def list_cases(self) -> list[dict]:
        """List all cases."""
        cases = []
        for f in sorted(self.cases_dir.glob("CASE-*.md"), reverse=True):
            cases.append({
                "id": f.stem,
                "path": str(f),
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
        return cases
