"""Abstract base class for OSINT tools. Every tool inherits from this."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import Finding, FindingSource


class OSINTTool(ABC):
    """Base class for all OSINT investigation tools.

    To add a new tool:
    1. Inherit from OSINTTool
    2. Set `category`, `name`, `description`
    3. Implement `async investigate(query, context) -> list[Finding]`
    4. Register in tools/__init__.py
    """

    category: FindingSource
    name: str
    description: str
    requires_api_key: bool = False
    free_tier_available: bool = True
    rate_limit_rps: float = 1.0  # requests per second

    @abstractmethod
    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        """Run investigation and return findings.

        Args:
            query: The search query or target
            context: Additional context from the parent investigation

        Returns:
            List of Finding objects
        """
        ...

    def _make_finding(
        self,
        title: str,
        description: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
        **metadata,
    ) -> Finding:
        """Helper to create a Finding with source pre-filled."""
        import uuid

        return Finding(
            id=f"{self.category.value}-{uuid.uuid4().hex[:8]}",
            source=self.category,
            tool=self.name,
            title=title,
            description=description,
            evidence=evidence or [],
            confidence=confidence,
            metadata=metadata,
        )

    def __repr__(self) -> str:
        return f"<OSINTTool {self.name} ({self.category.value})>"
