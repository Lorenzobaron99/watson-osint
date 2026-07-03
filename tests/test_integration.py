"""
Integration tests: v1 OrchestrationEngine, classification, cross-reference.

Tests the 7-phase sequential pipeline with mocked LLM calls.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from watson.agents.protocol import Finding, AgentRole, SourceClass, classify_target, select_agents
from watson.orchestration import get_engine, cross_reference_advanced


# ═══════════════════════════════════════════════════════════════
# Classification & Selection
# ═══════════════════════════════════════════════════════════════

class TestClassification:
    def test_domain(self):
        t, v = classify_target("example.com")
        assert t == "domain"
        assert v == "example.com"

    def test_email(self):
        t, v = classify_target("user@example.com")
        assert t == "email"

    def test_ip(self):
        t, v = classify_target("8.8.8.8")
        assert t == "ip"

    def test_crypto(self):
        t, v = classify_target("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb3")
        assert t == "crypto"

    def test_onion(self):
        t, v = classify_target("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
        assert t == "onion"

    def test_gps(self):
        t, v = classify_target("48.8566, 2.3522")
        assert t == "gps"

    def test_flight(self):
        t, v = classify_target("BA249")
        assert t == "flight"

    def test_image(self):
        t, v = classify_target("photo.jpg")
        assert t == "image"

    def test_breach(self):
        t, v = classify_target("data breach and leaked passwords")
        assert t == "breach"

    def test_company(self):
        t, v = classify_target("Acme Inc")
        assert t == "company"

    def test_person(self):
        t, v = classify_target("John Smith")
        assert t == "person"

    def test_selection_dispatches_correct_agents(self):
        roles = select_agents("domain")
        role_values = [r.value for r in roles]
        assert "recon" in role_values

        roles = select_agents("crypto")
        role_values = [r.value for r in roles]
        assert "crypto" in role_values

        roles = select_agents("gps")
        role_values = [r.value for r in roles]
        assert "geo" in role_values


# ═══════════════════════════════════════════════════════════════
# Finding factory
# ═══════════════════════════════════════════════════════════════

def make_finding(title, agent=AgentRole.RECON, confidence=0.90):
    return Finding(
        title=title,
        description=f"Mock finding: {title}",
        agent=agent,
        source_url="mock://test",
        source_class=SourceClass.PRIMARY,
        confidence=confidence,
    )


# ═══════════════════════════════════════════════════════════════
# Cross-Reference
# ═══════════════════════════════════════════════════════════════

class TestCrossReference:
    def test_empty_findings(self):
        patterns = cross_reference_advanced([])
        assert isinstance(patterns, list)

    def test_single_finding(self):
        f = make_finding("Single")
        patterns = cross_reference_advanced([f])
        assert len(patterns) >= 1  # At least confidence summary

    def test_entity_corroboration(self):
        f1 = make_finding("From Recon", AgentRole.RECON)
        f1.entities = [{"name": "Acme Corp", "type": "company"}]

        f2 = make_finding("From Corporate", AgentRole.CORPORATE)
        f2.entities = [{"name": "Acme Corp", "type": "company"}]

        patterns = cross_reference_advanced([f1, f2])
        corroborations = [p for p in patterns if p["type"] == "entity_corroboration"]
        assert len(corroborations) >= 1

    def test_blocked_vector_intelligence(self):
        blocked = [
            {"agent": "whois", "failure_reason": "WHOIS_REDACTED",
             "is_intelligence": True, "alternatives": ["crt.sh"]},
        ]
        patterns = cross_reference_advanced([], blocked)
        adversarial = [p for p in patterns if p["type"] == "adversarial_posture"]
        assert len(adversarial) >= 1

    def test_confidence_summary(self):
        findings = [
            make_finding("High", AgentRole.RECON, 0.95),
            make_finding("Mid", AgentRole.SOCIAL, 0.60),
            make_finding("Low", AgentRole.CRYPTO, 0.30),
        ]
        patterns = cross_reference_advanced(findings)
        summary = [p for p in patterns if p["type"] == "confidence_summary"]
        assert len(summary) == 1
        assert summary[0]["total_findings"] == 3
        assert summary[0]["high_confidence_count"] == 1


# ═══════════════════════════════════════════════════════════════
# Engine with mocked LLM
# ═══════════════════════════════════════════════════════════════

class TestEngine:
    """Tests for the v1 OrchestrationEngine 7-phase pipeline."""

    @pytest.mark.asyncio
    async def test_engine_returns_dict(self):
        """Engine.investigate() returns a dict with expected keys."""
        engine = get_engine()

        # Mock the LLM to return structured findings
        mock_response = """FINDING: Test finding
SOURCE: https://example.com/test
DATA: Test intelligence data
CONFIDENCE: HIGH"""

        with patch.object(engine, '_call_llm',
                          new_callable=AsyncMock,
                          return_value=mock_response):
            result = await engine.investigate("test.com")

            assert isinstance(result, dict)
            assert "case_id" in result
            assert "query" in result
            assert "findings" in result
            assert "markdown" in result
            assert result["query"] == "test.com"

    @pytest.mark.asyncio
    async def test_engine_handles_no_llm(self):
        """Engine completes gracefully when LLM is unavailable."""
        engine = get_engine()

        with patch.object(engine, '_call_llm',
                          new_callable=AsyncMock,
                          return_value=""):
            result = await engine.investigate("test.com")
            assert isinstance(result, dict)
            assert "case_id" in result

    @pytest.mark.asyncio
    async def test_engine_parses_structured_findings(self):
        """Engine correctly parses FINDING:/SOURCE:/DATA: blocks."""
        engine = get_engine()

        mock_response = """FINDING: Domain registered to Example Corp
SOURCE: https://whois.example.com/test.com
TIER: SECONDARY
DATA: Registrant: Example Corp, registered 2015-03-12
CONFIDENCE: HIGH

FINDING: 14 subdomains discovered
SOURCE: https://crt.sh/?q=test.com
TIER: TERTIARY
DATA: Subdomains include api.test.com, dev.test.com, staging.test.com
CONFIDENCE: MEDIUM"""

        with patch.object(engine, '_call_llm',
                          new_callable=AsyncMock,
                          return_value=mock_response):
            result = await engine.investigate("example.com")
            assert len(result["findings"]) >= 2


# ═══════════════════════════════════════════════════════════════
# Async test config
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
