"""Sidney Ledger — editorial compliance and entity tracking across investigations.

Every entity that appears in a Watson investigation is recorded here.
Cross-case patterns, harm assessments, and editorial gates live here.
"""

from __future__ import annotations
import json
import logging
import os
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger("watson.ethics")

# ── Ledger ─────────────────────────────────────────────────────

_LEDGER_PATH = Path(os.environ.get("WATSON_LEDGER_PATH",
    os.path.expanduser("~/.watson/ledger.json")))


class SidneyLedger:
    """Cross-case entity ledger with editorial compliance."""
    
    def __init__(self, path: Path | None = None):
        self.path = path or _LEDGER_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._load()
    
    def _load(self) -> dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {"entities": {}, "cases": {}, "version": "1.0"}
    
    def _save(self):
        try:
            self.path.write_text(json.dumps(self._data, indent=2, default=str))
        except OSError as e:
            logger.warning("ledger_save_failed: %s", e)
    
    def record_entity(self, name: str, entity_type: str, case_id: str, confidence: float,
                      appears_in: list[str] | None = None):
        """Record an entity found in an investigation."""
        key = name.lower().strip()
        if key not in self._data["entities"]:
            self._data["entities"][key] = {
                "canonical": name,
                "type": entity_type,
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "cases": [],
                "total_appearances": 0,
                "confidence_high": confidence,
            }
        
        entry = self._data["entities"][key]
        if case_id not in entry["cases"]:
            entry["cases"].append(case_id)
        entry["total_appearances"] = len(entry["cases"])
        entry["confidence_high"] = max(entry["confidence_high"], confidence)
        entry["last_seen"] = datetime.now(timezone.utc).isoformat()
        
        if appears_in:
            existing = entry.get("appears_in", [])
            for url in appears_in:
                if url not in existing:
                    existing.append(url)
            entry["appears_in"] = existing[:50]
        
        self._save()
    
    def record_case(self, case_id: str, query: str, finding_count: int,
                    confirmed_count: int, entities: list[str]):
        """Record a completed investigation case."""
        self._data["cases"][case_id] = {
            "query": query,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "finding_count": finding_count,
            "confirmed_count": confirmed_count,
            "entities": entities,
        }
        self._save()
    
    def get_entity(self, name: str) -> dict | None:
        """Look up an entity's cross-case history."""
        return self._data["entities"].get(name.lower().strip())
    
    def get_case(self, case_id: str) -> dict | None:
        """Look up a case."""
        return self._data["cases"].get(case_id)
    
    def entity_appears_across_cases(self, name: str) -> list[str]:
        """List all cases where this entity appears."""
        entry = self.get_entity(name)
        return entry["cases"] if entry else []
    
    def stats(self) -> dict:
        return {
            "total_entities": len(self._data["entities"]),
            "total_cases": len(self._data["cases"]),
            "cross_case_entities": sum(
                1 for e in self._data["entities"].values()
                if len(e.get("cases", [])) > 1
            ),
        }
    
    def get_stats(self) -> dict:
        """Alias for stats() — used by health endpoint."""
        return self.stats()


# ── Editorial checks ───────────────────────────────────────────

def apply_editorial_checks(findings: list, query: str) -> dict:
    """Apply editorial compliance checks to findings. Returns assessment dict."""
    
    # Harm indicators — terms that suggest sensitive content
    harm_indicators = {
        "victim": "VULNERABLE ENTITIES DETECTED",
        "minor": "MINOR DETECTED",
        "child": "MINOR DETECTED",
        "survivor": "VULNERABLE ENTITIES DETECTED",
        "phone_number": "PII DETECTED",
        "email": "PII DETECTED",
        "address": "PII DETECTED",
        "passport": "PII DETECTED",
    }
    
    checks = {
        "publication_assessment": "RECOMMENDED",
        "harm_level": "LOW",
        "public_interest": True,
        "warnings": [],
        "redactions_needed": 0,
    }
    
    all_text = " ".join(
        f"{getattr(f, 'title', '')} {getattr(f, 'description', '')}"
        for f in findings
    ).lower()
    
    for indicator, warning in harm_indicators.items():
        if indicator in all_text:
            checks["warnings"].append(warning)
    
    if checks["warnings"]:
        checks["harm_level"] = "HIGH" if len(checks["warnings"]) > 2 else "MEDIUM"
        checks["redactions_needed"] = len(checks["warnings"])
    
    return checks


# ── Singleton ──────────────────────────────────────────────────

_ledger: SidneyLedger | None = None


def get_ledger() -> SidneyLedger:
    global _ledger
    if _ledger is None:
        _ledger = SidneyLedger()
    return _ledger


# ── Editorial Framework (reporter integration) ──────────────────
# These are lightweight stubs — the real editorial pipeline lives in
# watson/reporter.py with the harm indicators in src/watson/ethics.py.

BELLINGCAT_DATA_ETHICS_APPENDIX = """
## Data Ethics & Methodology

This investigation follows the Bellingcat Digital Research Ethics Framework:

- **Open Source**: All data sourced from publicly available information
- **Verification**: Cross-referenced across multiple independent sources
- **Privacy**: Personal identifying information redacted unless clearly in the public interest
- **Attribution**: Sources documented for reproducibility
- **Correction**: Errors will be promptly corrected when identified
- **Proportionality**: Only information relevant to the investigation is included

Methodology: Multi-agent OSINT pipeline using web scraping, API queries,
DNS/WHOIS lookups, certificate transparency logs, and dark web monitoring.
"""


def generate_compliance_header(assessment: dict) -> str:
    """Generate a markdown compliance header from the assessment."""
    warnings = assessment.get("warnings", [])
    if not warnings:
        return "✅ **Editorial Compliance**: No concerns detected.\n"
    
    lines = [f"⚠️  **Editorial Compliance** — {len(warnings)} concern(s):"]
    for w in warnings:
        lines.append(f"- {w}")
    return "\n".join(lines) + "\n"


class EditorialFramework:
    """Editorial compliance framework for pre-publication assessment."""
    
    def assess(self, query: str, findings: list, narrative: str, ai_used: bool) -> dict:
        """Assess a report for editorial compliance before publication."""
        return apply_editorial_checks(findings, query)
