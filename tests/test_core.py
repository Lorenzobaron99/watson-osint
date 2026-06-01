"""Tests for Watson OSINT agent."""

import pytest

from watson import __version__
from watson.core.models import Finding, FindingSeverity, FindingSource, InvestigationRequest, Report
from watson.tools.base import OSINTTool
from watson.tools.registry import registry
from watson.utils.helpers import extract_domain, clean_username, is_email, is_url


def test_version():
    assert __version__ == "0.1.0"


class TestModels:
    def test_finding_defaults(self):
        f = Finding(
            id="test-1",
            source=FindingSource.WEBSITES,
            tool="test-tool",
            title="Test finding",
            description="Test description",
        )
        assert f.severity == FindingSeverity.INFO
        assert f.confidence == 0.5
        assert f.evidence == []

    def test_report_stats(self):
        f1 = Finding(
            id="1", source=FindingSource.WEBSITES, tool="w", title="A", description="A",
            severity=FindingSeverity.HIGH
        )
        f2 = Finding(
            id="2", source=FindingSource.PEOPLE, tool="p", title="B", description="B",
            severity=FindingSeverity.MEDIUM
        )
        report = Report(query="test", findings=[f1, f2])
        assert report.total_findings == 2
        assert report.by_severity == {"high": 1, "medium": 1}
        assert report.by_source == {"websites": 1, "people": 1}


class TestHelpers:
    def test_extract_domain(self):
        assert extract_domain("https://www.example.com/path") == "example.com"
        assert extract_domain("www.example.com") == "example.com"
        assert extract_domain("example.com") == "example.com"

    def test_clean_username(self):
        assert clean_username("@john_doe") == "john_doe"
        assert clean_username("john_doe") == "john_doe"
        assert clean_username("https://twitter.com/john_doe") == "john_doe"

    def test_is_email(self):
        assert is_email("user@example.com") is True
        assert is_email("not-an-email") is False

    def test_is_url(self):
        assert is_url("https://example.com") is True
        assert is_url("example.com") is False


class TestRegistry:
    def test_registry_has_tools(self):
        """All 8 tool categories should have registered tools."""
        categories = registry.list_categories()
        assert len(categories) > 0
        assert registry.tool_count >= 8

    def test_registry_get_by_category(self):
        tools = registry.get_for_category(FindingSource.WEBSITES)
        assert len(tools) > 0
        assert tools[0].category == FindingSource.WEBSITES


class TestToolBase:
    def test_make_finding(self):
        class FakeTool(OSINTTool):
            category = FindingSource.PEOPLE
            name = "fake"
            description = "fake tool"

            async def investigate(self, query, context=""):
                return [self._make_finding(title="Test", description="Desc")]

        tool = FakeTool()
        findings = tool._make_finding(title="Hello", description="World")
        assert findings.source == FindingSource.PEOPLE
        assert findings.tool == "fake"
        assert findings.title == "Hello"
