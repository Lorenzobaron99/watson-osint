"""Tests for intelligence synthesis."""

import sys, os, asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from watson.agents.protocol import Finding, AgentRole, SourceClass
from watson.orchestration.synthesis import (
    synthesize_brief, brief_to_markdown, _fallback_brief, _findings_block,
)


def _f(title, desc, conf=0.6):
    return Finding(title=title, description=desc, agent=AgentRole.ORCHESTRATOR,
                   confidence=conf, source_class=SourceClass.PRIMARY)


def test_findings_block_truncates():
    fs = [_f(f"Title {i}", "x" * 2000) for i in range(20)]
    block = _findings_block(fs, max_chars=3000)
    assert len(block) <= 3500
    assert "[1]" in block


def test_fallback_brief_structure():
    fs = [_f("FTC case", "Amazon antitrust https://ftc.gov/case"),
          _f("Tax bill", "€250M https://example.com/tax")]
    b = _fallback_brief("Amazon", fs)
    assert "executive_summary" in b
    assert b["_synthesized"] is False
    # sources extracted from descriptions → next steps reference them
    assert b["recommended_next_steps"]
    assert any("ftc.gov" in s for s in b["_sources"])


def test_brief_to_markdown():
    brief = {
        "executive_summary": "Amazon faces antitrust scrutiny.",
        "risk_themes": [{"theme": "Antitrust", "severity": "HIGH",
                         "summary": "FTC suit", "source_titles": ["FTC"]}],
        "notable_entities": [{"name": "Lina Khan", "role": "regulator", "context": "FTC chair"}],
        "evidence_gaps": ["No 2025 data"],
        "recommended_next_steps": ["Check EU DSA"],
    }
    md = brief_to_markdown(brief, "Amazon")
    assert "# Intelligence Brief: Amazon" in md
    assert "🔴" in md and "Antitrust" in md
    assert "Lina Khan" in md
    assert "Evidence Gaps" in md


def test_synthesize_with_mock_llm():
    async def mock_llm(prompt, timeout=40):
        return ('{"executive_summary":"Test summary",'
                '"risk_themes":[{"theme":"Labor","severity":"MEDIUM","summary":"warehouse issues","source_titles":["Amnesty"]}],'
                '"notable_entities":[],"evidence_gaps":[],"recommended_next_steps":[]}')
    fs = [_f("Amnesty report", "Saudi warehouse labor abuse")]
    brief = asyncio.run(synthesize_brief("Amazon", "labor", fs, mock_llm))
    assert brief["executive_summary"] == "Test summary"
    assert brief["risk_themes"][0]["theme"] == "Labor"
    assert brief["_synthesized"] is True


def test_synthesize_falls_back_on_no_llm():
    async def dead_llm(prompt, timeout=40):
        return None
    fs = [_f("Some source", "content")]
    brief = asyncio.run(synthesize_brief("X", "y", fs, dead_llm))
    assert brief["_synthesized"] is False


def test_synthesize_empty_findings_returns_none():
    async def llm(prompt, timeout=40):
        return "{}"
    assert asyncio.run(synthesize_brief("X", "y", [], llm)) is None
