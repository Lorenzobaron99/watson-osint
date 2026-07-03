"""
Agent adapter — abstract interface for pluggable agent backends.
Watson is agent-agnostic: Hermes, OpenClaw, OpenHuman, or direct LLM.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str = ""
    source: str = ""


@dataclass
class BrowseResult:
    url: str
    content: str
    title: str = ""


@dataclass
class VisionResult:
    description: str
    objects: list[str] = field(default_factory=list)
    text: str = ""


@dataclass
class TerminalResult:
    output: str
    exit_code: int = 0


@dataclass
class InvestigationResult:
    """Structured result from an investigation angle."""
    angle: str
    findings: list[dict] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    confidence: float = 0.0
    raw: str = ""


class AgentAdapter(ABC):
    """Pluggable agent backend for Watson.

    Watson's engine calls these abstract methods. Each adapter
    implements them for its specific agent. Watson's methodology,
    dispatch logic, graph, and reporting are independent of this layer.
    """

    name: str = "base"
    description: str = ""

    @abstractmethod
    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Web search."""
        ...

    @abstractmethod
    async def browse(self, url: str) -> BrowseResult:
        """Navigate to and extract content from a URL."""
        ...

    @abstractmethod
    async def vision(self, image_path: str, question: str = "Describe this image in detail.") -> VisionResult:
        """Analyze an image."""
        ...

    @abstractmethod
    async def terminal(self, command: str, timeout: int = 30) -> TerminalResult:
        """Execute a shell command."""
        ...

    async def investigate_angle(self, angle: str, query: str) -> InvestigationResult:
        """Run a single investigation angle. Default: search + browse top results.

        Adapters can override this for richer investigation (multi-tool dispatch).
        """
        results = await self.search(query, num_results=5)
        sources = [r.url for r in results if r.url]
        findings = [
            {"title": r.title, "url": r.url, "snippet": r.snippet}
            for r in results
        ]

        return InvestigationResult(
            angle=angle,
            findings=findings,
            sources=sources,
            confidence=0.5,
        )

    async def health_check(self) -> bool:
        """Check if the agent backend is reachable."""
        return True
