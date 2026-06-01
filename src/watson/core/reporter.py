"""Reporter — synthesizes findings into a structured report."""

from __future__ import annotations

from datetime import datetime

from .dispatcher import FindingSource
from .models import Finding, Report


class Reporter:
    """Synthesizes investigation findings into a structured report."""

    def __init__(self, cross_reference: bool = True):
        self.cross_reference = cross_reference

    def generate(self, query: str, findings: list[Finding]) -> Report:
        """Generate a report from raw findings.

        Args:
            query: Original investigation query
            findings: Raw findings from all tools

        Returns:
            Structured Report object
        """
        # Build tool stats
        tool_stats: dict[str, int] = {}
        for f in findings:
            tool_stats[f.tool] = tool_stats.get(f.tool, 0) + 1

        # Sort findings by confidence (highest first)
        sorted_findings = sorted(findings, key=lambda f: f.confidence, reverse=True)

        # Cross-reference findings
        cross_refs: list[Finding] = []
        if self.cross_reference and len(findings) > 1:
            cross_refs = self._cross_reference(findings)

        # Generate summary
        summary = self._summarize(query, sorted_findings, cross_refs)

        return Report(
            query=query,
            generated_at=datetime.now(),
            findings=sorted_findings,
            cross_references=cross_refs,
            summary=summary,
            tool_stats=tool_stats,
        )

    def _cross_reference(self, findings: list[Finding]) -> list[Finding]:
        """Cross-reference findings from different sources to find connections."""
        refs: list[Finding] = []

        # Group findings by source
        by_source: dict[str, list[Finding]] = {}
        for f in findings:
            by_source.setdefault(f.source.value, []).append(f)

        # Find overlapping entities across sources
        for source_a, fa_list in by_source.items():
            for source_b, fb_list in by_source.items():
                if source_a >= source_b:
                    continue

                for fa in fa_list:
                    for fb in fb_list:
                        # Simple overlap: shared words in titles
                        words_a = set(fa.title.lower().split())
                        words_b = set(fb.title.lower().split())
                        overlap = words_a & words_b
                        meaningful = {w for w in overlap if len(w) > 3}

                        if len(meaningful) >= 2:
                            refs.append(
                                Finding(
                                    id=f"xref-{source_a}-{source_b}-{len(refs)}",
                                    source=FindingSource.CROSS_REF,
                                    tool="cross-reference",
                                    title=f"Link: {fa.title} ↔ {fb.title}",
                                    description=(
                                        f"Findings from {source_a} and {source_b} share "
                                        f"common elements: {', '.join(sorted(meaningful))}"
                                    ),
                                    evidence=fa.evidence[:1] + fb.evidence[:1],
                                    confidence=min(fa.confidence, fb.confidence),
                                )
                            )

        return refs

    def _summarize(
        self, query: str, findings: list[Finding], cross_refs: list[Finding]
    ) -> str:
        """Generate a human-readable summary."""
        total = len(findings) + len(cross_refs)
        sources = len({f.source.value for f in findings})
        high_conf = sum(1 for f in findings if f.confidence >= 0.7)

        lines = [
            f"## Investigation Summary",
            f"",
            f"**Query:** {query}",
            f"**Findings:** {total} ({len(findings)} direct, {len(cross_refs)} cross-referenced)",
            f"**Sources:** {sources} tool categories",
            f"**High-confidence findings:** {high_conf}",
            f"",
        ]

        # Top findings
        if findings:
            lines.append("### Top Findings")
            for f in findings[:5]:
                conf = "🟢" if f.confidence >= 0.7 else "🟡" if f.confidence >= 0.4 else "🔴"
                lines.append(f"- {conf} **{f.title}** ({f.source.value}) — {f.description[:120]}")

        # Cross-references
        if cross_refs:
            lines.append("")
            lines.append("### Cross-References")
            for cr in cross_refs[:3]:
                lines.append(f"- 🔗 {cr.title}")

        return "\n".join(lines)
