"""
Enterprise-Grade Report Generator

Produces standardized investigation reports with:
  - Evidence confidence matrix (5 tiers)
  - Source classification (PRIMARY/SECONDARY/TERTIARY/UNVERIFIED)
  - Structured 10-section format
  - Verifiability scoring
  - Editorial compliance assessment

Every finding carries: {confidence, source_class, source_url, timestamp, replicable}
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Evidence Confidence Tiers ────────────────────────────────────

CONFIDENCE_TIERS = {
    "CONFIRMED":       (0.90, 1.00),
    "PROBABLE":        (0.70, 0.89),
    "POSSIBLE":        (0.40, 0.69),
    "UNLIKELY":        (0.10, 0.39),
    "UNSUBSTANTIATED": (0.00, 0.09),
}

SOURCE_CLASSES = {
    "PRIMARY":    "Court docs, SEC filings, certificate transparency logs, blockchain, official registries",
    "SECONDARY":  "News articles, academic papers, verified social media accounts, company websites",
    "TERTIARY":   "Public registries, encyclopedias, aggregated databases, Wikipedia",
    "UNVERIFIED": "Anonymous sources, unsourced claims, forum posts, unverified social media",
}


def tier_from_confidence(score: float) -> str:
    for tier, (lo, hi) in CONFIDENCE_TIERS.items():
        if lo <= score <= hi:
            return tier
    return "UNSUBSTANTIATED"


def source_class_from_type(source_type: str) -> str:
    # Direct source class labels (from protocol's SourceClass enum)
    if source_type in ("PRIMARY", "SECONDARY", "TERTIARY", "UNVERIFIED"):
        return source_type
    
    mapping = {
        # Direct infrastructure queries → PRIMARY
        "blockchain": "PRIMARY",
        "cert_transparency": "PRIMARY",
        "dns_record": "PRIMARY",
        "dns_lookup": "PRIMARY",
        "whois": "PRIMARY",
        "whois_lookup": "PRIMARY",
        "ssl_cert": "PRIMARY",
        "court_filing": "PRIMARY",
        "sec_filing": "PRIMARY",
        "official_registry": "PRIMARY",
        "reverse_dns": "PRIMARY",
        "ip_geolocation": "PRIMARY",
        # Agent-sourced infrastructure → PRIMARY
        "recon": "PRIMARY",
        # Corporate registries → SECONDARY (varied reliability)
        "company_registry": "SECONDARY",
        "corporate": "SECONDARY",
        # Breach data → SECONDARY
        "breach_check": "SECONDARY",
        "breach": "SECONDARY",
        "dark": "SECONDARY",
        # Social / user enumeration
        "social": "SECONDARY",
        "username_enum": "SECONDARY",
        "verified_social": "SECONDARY",
        # News / web / API
        "news": "SECONDARY",
        "academic": "SECONDARY",
        "api": "SECONDARY",
        "web_search": "SECONDARY",
        # Lower reliability
        "wikipedia": "TERTIARY",
        "public_db": "TERTIARY",
        "wayback": "TERTIARY",
    }
    return mapping.get(source_type, "UNVERIFIED")


# ── Report data model ────────────────────────────────────────────

@dataclass
class Finding:
    title: str
    description: str
    source_type: str = ""
    source_url: str = ""
    confidence: float = 0.5
    entities: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def tier(self) -> str:
        return tier_from_confidence(self.confidence)

    @property
    def source_class(self) -> str:
        return source_class_from_type(self.source_type)


@dataclass
class InvestigationReport:
    case_id: str
    query: str
    target_type: str = "unknown"
    angles: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    entities: list[dict] = field(default_factory=list)
    relations: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    methodology_notes: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def generate_markdown(self) -> str:
        """Generate an enterprise-grade markdown report with editorial compliance."""
        
        # ── Run ethical pre-publication assessment ──
        try:
            from src.watson.ethics import (
                EditorialFramework, generate_compliance_header,
                BELLINGCAT_DATA_ETHICS_APPENDIX,
            )
        except ImportError:
            from watson.ethics import (
                EditorialFramework, generate_compliance_header,
                BELLINGCAT_DATA_ETHICS_APPENDIX,
            )
        framework = EditorialFramework()
        
        findings_dicts = [
            {
                "title": f.title,
                "description": f.description,
                "source_type": f.source_type,
                "source_url": f.source_url,
                "confidence": f.confidence,
                "entities": f.entities,
            }
            for f in self.findings
        ]
        
        # Check if AI was used (LLM analyzed findings = AI used in research)
        ai_used = any(
            f.source_type in ("web_search", "news", "social", "academic", "api")
            for f in self.findings
        )
        
        full_narrative = self._build_narrative(
            [f for f in self.findings if f.tier == "CONFIRMED"],
            [f for f in self.findings if f.tier == "PROBABLE"],
            [f for f in self.findings if f.tier == "POSSIBLE"],
        )
        
        assessment = framework.assess(
            query=self.query,
            findings=findings_dicts,
            narrative=full_narrative,
            ai_used=ai_used,
        )
        
        # ── Build compliance header ──
        compliance_header = generate_compliance_header(assessment)
        
        # ── Build report body ──
        findings_sorted = sorted(self.findings, key=lambda f: -f.confidence)
        
        # Split: real intelligence vs tool errors/limitations
        intelligence = []
        tool_errors = []
        for f in findings_sorted:
            title_lower = f.title.lower()
            is_error = (
                f.source_type == "error" or
                "⚠️" in f.title or
                "could not read" in title_lower or
                "failed" in title_lower or
                "api key required" in title_lower or
                "authentication failed" in title_lower or
                "bot detection" in title_lower or
                "rate limited" in title_lower or
                "timeout" in title_lower or
                "no module named" in title_lower or
                f.confidence < 0.15
            )
            if is_error:
                tool_errors.append(f)
            else:
                intelligence.append(f)
        
        confirmed = [f for f in intelligence if f.tier == "CONFIRMED"]
        probable = [f for f in intelligence if f.tier == "PROBABLE"]
        possible = [f for f in intelligence if f.tier == "POSSIBLE"]
        low_conf = [f for f in intelligence if f.tier in ("UNLIKELY", "UNSUBSTANTIATED")]

        parts = []

        # ── 1. Executive Summary ─────────────────────────────
        parts.append(f"# Investigation Report: {self.query}")
        parts.append(f"**Case ID:** {self.case_id}")
        parts.append(f"**Date:** {self.created_at[:10]}")
        parts.append("")
        parts.append("## 1. Executive Summary")
        parts.append("")
        total = len(intelligence)
        high = len(confirmed)
        parts.append(
            f"This investigation examined **{self.query}** across "
            f"{len(self.angles)} angles. "
            f"**{total} findings** were produced: "
            f"**{high} CONFIRMED**, "
            f"**{len(probable)} PROBABLE**, "
            f"**{len(possible)} POSSIBLE**."
        )
        if tool_errors:
            parts.append(f"\n**{len(tool_errors)} tool errors/limitations** were encountered and are listed separately.")
        if confirmed:
            parts.append(f"\n**Key confirmed finding:** {confirmed[0].title}")
        
        # ── Narrative summary ──
        parts.append(f"\n### Narrative")
        narrative = self._build_narrative(confirmed, probable, possible)
        parts.append(narrative)
        parts.append("")

        # ── 2. Key Findings ──────────────────────────────────
        parts.append("## 2. Key Findings (Confidence-Ranked)")
        parts.append("")

        for i, f in enumerate(intelligence[:20], 1):
            emoji = {"CONFIRMED": "🟢", "PROBABLE": "🟡", "POSSIBLE": "🟠", "UNLIKELY": "🔴", "UNSUBSTANTIATED": "⚪"}[f.tier]
            parts.append(f"### {i}. [{f.tier}] {f.title}")
            parts.append(f"{emoji} **Confidence:** {f.confidence:.0%} | **Source class:** {f.source_class}")
            parts.append(f"\n{f.description}")
            if f.source_url:
                parts.append(f"\n**Source:** {f.source_url}")
            if f.evidence:
                parts.append("\n**Evidence:**")
                for e in f.evidence:
                    parts.append(f"  - {e}")
            parts.append("")

        # ── 3. Methodology ───────────────────────────────────
        parts.append("## 3. Methodology")
        parts.append("")
        parts.append(f"**Target type:** {self.target_type}")
        parts.append(f"**Investigation angles ({len(self.angles)}):**")
        for a in self.angles:
            parts.append(f"  - {a}")
        if self.methodology_notes:
            parts.append("\n**Tools & techniques:**")
            for note in self.methodology_notes:
                parts.append(f"  - {note}")
        parts.append("")

        # ── 4. Detailed Evidence ─────────────────────────────
        parts.append("## 4. Detailed Evidence")
        parts.append("")
        by_source = {}
        for f in intelligence:
            cls = f.source_class
            by_source.setdefault(cls, []).append(f)

        for cls_name in ["PRIMARY", "SECONDARY", "TERTIARY", "UNVERIFIED"]:
            items = by_source.get(cls_name, [])
            if items:
                parts.append(f"### {cls_name} Sources")
                parts.append(f"_{SOURCE_CLASSES[cls_name]}_")
                parts.append("")
                for f in items:
                    parts.append(f"- **{f.title}** (confidence: {f.confidence:.0%})")
                    if f.source_url:
                        parts.append(f"  {f.source_url}")
                parts.append("")

        # ── 5. Entity Map ────────────────────────────────────
        parts.append("## 5. Entity Map")
        parts.append("")
        if self.entities:
            parts.append("| Entity | Type | Confidence | Sources |")
            parts.append("|--------|------|------------|---------|")
            for e in self.entities[:30]:
                parts.append(
                    f"| {e.get('name', '?')} | {e.get('type', '?')} | "
                    f"{e.get('confidence', 0):.0%} | {e.get('source_count', 0)} |"
                )
            parts.append("")

        if self.relations:
            parts.append("**Relationships:**")
            for r in self.relations[:20]:
                parts.append(
                    f"  - {r.get('source', '?')} → [{r.get('type', '?')}] → "
                    f"{r.get('target', '?')} (Case {r.get('case_id', '?')})"
                )
        parts.append("")

        # ── 6. Timeline ──────────────────────────────────────
        parts.append("## 6. Timeline")
        parts.append("")
        if self.timeline:
            for t in sorted(self.timeline, key=lambda x: x.get("date", "")):
                parts.append(f"- **{t.get('date', '?')}**: {t.get('event', '?')}")
        else:
            parts.append("(No chronological events identified)")
        parts.append("")

        # ── 7. Source Appendix ───────────────────────────────
        parts.append("## 7. Source Appendix")
        parts.append("")
        seen = set()
        for f in intelligence + tool_errors:
            if f.source_url and f.source_url not in seen:
                seen.add(f.source_url)
                parts.append(f"- [{f.tier}] {f.source_url}")
        parts.append("")

        # ── 8. Limitations & Gaps ────────────────────────────
        parts.append("## 8. Limitations & Gaps")
        parts.append("")
        
        if tool_errors:
            parts.append(f"### Tool Errors ({len(tool_errors)})")
            parts.append("")
            parts.append("These are infrastructure/API limitations, not intelligence findings:")
            parts.append("")
            for f in tool_errors:
                parts.append(f"- **{f.title}** — {f.description[:200]}")
            parts.append("")
        
        if low_conf:
            parts.append(f"### Low-Confidence Findings ({len(low_conf)})")
            parts.append("")
            parts.append("Findings below confidence thresholds that require further verification:")
            parts.append("")
            for f in low_conf[:5]:
                parts.append(f"  - {f.title}")
        elif not tool_errors:
            parts.append("(No significant gaps identified — all findings met confidence thresholds)")
        parts.append("")

        # ── 9. Recommendations ───────────────────────────────
        parts.append("## 9. Recommendations for Further Investigation")
        parts.append("")
        if low_conf:
            for f in low_conf[:3]:
                parts.append(f"- Verify: \"{f.title}\" — current evidence is weak")
        parts.append(f"- Deep-dive on any entities with >2 connections in the entity map")
        parts.append(f"- Set up scheduled monitoring for this target")
        parts.append("")

        # ── 10. Verifiability Score ──────────────────────────
        parts.append("## 10. Verifiability Score")
        parts.append("")
        primary_count = sum(1 for f in intelligence if f.source_class == "PRIMARY")
        has_urls = sum(1 for f in intelligence if f.source_url)
        verifiability = 0.0
        if total > 0:
            verifiability = (
                0.4 * (primary_count / total) +
                0.4 * (has_urls / total) +
                0.2 * (high / total)
            )
        parts.append(f"**Score: {verifiability:.0%}**")
        parts.append(f"  - {primary_count}/{total} findings from PRIMARY sources")
        parts.append(f"  - {has_urls}/{total} findings have public URLs")
        parts.append(f"  - {high}/{total} findings CONFIRMED")
        parts.append("")
        if verifiability >= 0.7:
            parts.append("✅ **This investigation is independently verifiable.**")
        elif verifiability >= 0.4:
            parts.append("⚠️ **Partially verifiable — some findings lack primary sources.**")
        else:
            parts.append("❌ **Low verifiability — most findings cannot be independently confirmed.**")
        
        parts.append("")
        parts.append(BELLINGCAT_DATA_ETHICS_APPENDIX)

        # Prepend compliance header, append ethics appendix
        return compliance_header + "\n".join(parts)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "query": self.query,
            "target_type": self.target_type,
            "findings_count": len(self.findings),
            "confirmed": sum(1 for f in self.findings if f.tier == "CONFIRMED"),
            "probable": sum(1 for f in self.findings if f.tier == "PROBABLE"),
            "possible": sum(1 for f in self.findings if f.tier == "POSSIBLE"),
            "verifiability_score": self._verifiability(),
            "created_at": self.created_at,
            "markdown": self.generate_markdown(),
        }

    def _verifiability(self) -> float:
        total = len(self.findings)
        if total == 0:
            return 0.0
        primary = sum(1 for f in self.findings if f.source_class == "PRIMARY")
        has_urls = sum(1 for f in self.findings if f.source_url)
        high = sum(1 for f in self.findings if f.tier == "CONFIRMED")
        return 0.4 * (primary / total) + 0.4 * (has_urls / total) + 0.2 * (high / total)

    def _build_narrative(self, confirmed: list, probable: list, possible: list) -> str:
        """Build a narrative summary connecting the dots."""
        import re
        lines = []
        
        # Infrastructure findings
        infra = [f for f in confirmed + probable if any(kw in f.title.lower() for kw in 
                  ("dns", "ip resol", "whois", "ssl", "certificate", "registrar"))]
        if infra:
            ip_info = ""
            geo_info = ""
            registrar_info = ""
            for f in infra:
                desc = f.description
                if "resolves to" in desc.lower():
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", desc)
                    if ip_match:
                        ip_info = f" at IP {ip_match.group(1)}"
                    if "Location:" in desc:
                        geo_match = re.search(r"Location:\s*(.+)", desc)
                        if geo_match:
                            geo_info = f" — geolocated to {geo_match.group(1)}"
                    if "Organization:" in desc:
                        org_match = re.search(r"Organization:\s*(.+)", desc)
                        if org_match:
                            geo_info += f" ({org_match.group(1)})"
                if "registrar:" in desc.lower():
                    reg_match = re.search(r"registrar:\s*(.+)", desc, re.IGNORECASE)
                    if reg_match:
                        registrar_info = f" Registered through {reg_match.group(1)}."
            
            domain = self.query
            lines.append(
                f"The target's primary domain {domain}{ip_info}{geo_info}."
                f"{registrar_info}"
            )
        
        # Registrar intelligence — flag sanction-relevant registrars
        SENSITIVE_REGISTRARS = {
            "ru-center": "Russia (RU-CENTER is a Moscow-based state-adjacent registrar)",
            "nic.ru": "Russia (Russian national NIC)",
            "r01.ru": "Russia",
            "reg.ru": "Russia",
            "beget": "Russia",
        }
        for f in confirmed + probable:
            desc = f.description.lower()
            for key, note in SENSITIVE_REGISTRARS.items():
                if key in desc:
                    lines.append(
                        f"\n⚠️ **Registrar intelligence:** The domain registrar is {note}. "
                        f"For sanctioned entities, registrar jurisdiction is a key investigative lead."
                    )
                    break
        
        # People findings
        people = [f for f in confirmed + probable if any(kw in f.title.lower() for kw in 
                  ("username", "social", "profile", "breach", "email", "ceo", "founder"))]
        if people:
            lines.append(f"\nSocial and people intelligence identified {len(people)} leads, "
                        f"including online presence and breach exposure data.")
        
        # Gaps
        gaps = []
        if not any("breach" in f.title.lower() or "pwned" in f.title.lower() for f in confirmed + probable):
            gaps.append("no breach database hits were found")
        if not any("corporate" in f.title.lower() or "opencorporates" in f.title.lower() for f in confirmed + probable):
            gaps.append("corporate registry data was not available")
        
        if gaps:
            lines.append(f"\nInvestigation gaps: {', '.join(gaps)}. These vectors should be pursued in follow-up investigation.")
        
        return "\n".join(lines)

    def save(self, output_dir: str | Path = "cases") -> Path:
        """Save the report as a markdown file."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{self.case_id}_{self.query[:40].replace(' ', '_').replace('/', '_')}.md"
        path = output_dir / filename
        path.write_text(self.generate_markdown())
        return path


# ── Builder for converting agent findings ────────────────────────

def from_agent_findings(
    query: str,
    findings: list[dict],
    target_type: str = "unknown",
    angles: list[str] | None = None,
    entities: list[dict] | None = None,
    relations: list[dict] | None = None,
    methodology_notes: list[str] | None = None,
) -> InvestigationReport:
    """Create an enterprise-grade report from agent investigation output."""
    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"

    report_findings = []
    for f in findings:
        report_findings.append(Finding(
            title=f.get("title", "Untitled finding"),
            description=f.get("description", ""),
            source_type=f.get("source_type", f.get("source", "web_search")),
            source_url=f.get("source_url", f.get("url", "")),
            confidence=float(f.get("confidence", 0.5)),
            entities=f.get("entities", []),
            evidence=f.get("evidence", []),
        ))

    return InvestigationReport(
        case_id=case_id,
        query=query,
        target_type=target_type,
        angles=angles or [],
        findings=report_findings,
        entities=entities or [],
        relations=relations or [],
        methodology_notes=methodology_notes or [],
    )
