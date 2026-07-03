"""Export — generate reports in multiple formats.

BellingcatReport class for structured OSINT report generation.
Delegates to watson.reporter for core report logic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class BellingcatReport:
    """Bellingcat-style structured OSINT report with multi-format export.

    Supports: JSON, STIX, MISP, PDF, Markdown.
    """

    def __init__(
        self,
        query: str = "",
        investigation_id: str = "",
        target_type: str = "unknown",
        target_value: str = "",
    ):
        self.query = query
        self.investigation_id = investigation_id
        self.target_type = target_type
        self.target_value = target_value
        self.findings: List[Dict[str, Any]] = []
        self.cross_references: List[Dict[str, Any]] = []
        self.hops: int = 0

    def add_findings(self, findings: List[Dict[str, Any]]):
        self.findings.extend(findings)

    def add_cross_references(self, refs: List[Dict[str, Any]]):
        self.cross_references.extend(refs)

    def to_dict(self) -> Dict[str, Any]:
        """Return full report as dict."""
        return {
            "case_id": self.investigation_id,
            "query": self.query,
            "target_type": self.target_type,
            "target_value": self.target_value,
            "hops": self.hops,
            "total_findings": len(self.findings),
            "confirmed": sum(1 for f in self.findings if f.get("tier") == "CONFIRMED"),
            "findings": self.findings,
            "cross_references": self.cross_references,
            "verifiability": self._verifiability(),
        }

    def to_json(self, path: Path | str) -> Path:
        """Export as JSON."""
        path = Path(path)
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str))
        return path

    def to_stix(self, path: Path | str) -> Path:
        """Export as STIX 2.1 bundle."""
        import uuid
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "report",
                    "id": f"report--{uuid.uuid4()}",
                    "created": now,
                    "modified": now,
                    "name": f"Watson Investigation: {self.query[:80]}",
                    "description": f"OSINT investigation of {self.target_value}",
                    "report_types": ["investigation"],
                    "object_refs": [],
                }
            ],
        }
        path = Path(path)
        path.write_text(json.dumps(bundle, indent=2))
        return path

    def to_misp(self, path: Path | str) -> Path:
        """Export as MISP event JSON."""
        import uuid

        event = {
            "Event": {
                "uuid": str(uuid.uuid4()),
                "info": f"Watson Investigation: {self.query[:80]}",
                "analysis": "2",  # Completed
                "threat_level_id": "3",  # Low
                "published": False,
                "Attribute": [
                    {
                        "type": "text",
                        "category": "External analysis",
                        "value": f["title"],
                        "comment": f["description"],
                    }
                    for f in self.findings[:50]
                ],
            }
        }
        path = Path(path)
        path.write_text(json.dumps(event, indent=2))
        return path

    def to_pdf(self, path: Path | str) -> Path:
        """Export as PDF (saves as JSON with .pdf extension if fpdf unavailable)."""
        path = Path(path)
        try:
            from fpdf import FPDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", size=12)
            pdf.cell(200, 10, text=f"Watson OSINT Report: {self.query[:80]}", align="C")
            pdf.ln(10)
            for f in self.findings:
                pdf.set_font("Helvetica", "B", size=10)
                pdf.cell(200, 8, text=f["title"][:100])
                pdf.ln(8)
                pdf.set_font("Helvetica", size=9)
                pdf.multi_cell(0, 6, text=f.get("description", "")[:300])
                pdf.ln(4)
            pdf.output(str(path))
        except ImportError:
            # Fallback: save as markdown with .pdf extension
            path.write_text(self.to_markdown())
        return path

    def to_markdown(self) -> str:
        """Export as Markdown."""
        lines = [
            f"# Watson OSINT Investigation Report",
            f"",
            f"**Case ID:** {self.investigation_id}",
            f"**Query:** {self.query}",
            f"**Target Type:** {self.target_type}",
            f"**Target:** {self.target_value}",
            f"**Hops:** {self.hops}",
            f"**Findings:** {len(self.findings)}",
            f"**Verifiability:** {self._verifiability():.0%}",
            f"",
            f"## Findings",
            f"",
        ]
        for i, f in enumerate(self.findings, 1):
            tier = f.get("tier", "UNSUBSTANTIATED")
            lines.append(f"### Finding {i}: {f.get('title', 'Untitled')}")
            lines.append(f"")
            lines.append(f"- **Tier:** {tier}")
            lines.append(f"- **Confidence:** {f.get('confidence', 0):.1%}")
            lines.append(f"- **Source:** {f.get('source_type', 'unknown')}")
            if f.get("source_url"):
                lines.append(f"- **URL:** {f.get('source_url')}")
            lines.append(f"")
            lines.append(f.get("description", ""))
            lines.append(f"")

        if self.cross_references:
            lines.append(f"## Cross-References")
            lines.append(f"")
            for cr in self.cross_references:
                lines.append(f"- {cr}")

        return "\n".join(lines)

    def _verifiability(self) -> float:
        """Calculate the verifiability score (0-1)."""
        if not self.findings:
            return 0.0
        sources = sum(1 for f in self.findings if f.get("source_url"))
        primary = sum(1 for f in self.findings if f.get("source_type") == "PRIMARY")
        score = (sources / len(self.findings) * 0.5 + primary / max(len(self.findings), 1) * 0.5)
        return min(score, 1.0)
