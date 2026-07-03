"""Abstract base class for OSINT tools. Every tool inherits from this."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import Finding, FindingSeverity, FindingSource


class OSINTTool(ABC):
    """Base class for all OSINT investigation tools.

    To add a new tool:
    1. Inherit from OSINTTool
    2. Set `category`, `name`, `description`
    3. Set API key metadata if the tool needs one
    4. Implement `async investigate(query, context) -> list[Finding]`
    5. Register in tools/__init__.py

    API Key awareness:
    - If requires_api_key=True, the dispatcher checks config BEFORE running
    - If the key is missing, the tool is SKIPPED with a clear message and setup instructions
    - Watson never runs a tool it knows will fail due to missing credentials
    """

    category: FindingSource
    name: str
    description: str

    # ── API Key Metadata ─────────────────────────────────────────
    requires_api_key: bool = False
    # Config key name in [watson.api_keys] (e.g., "tineye", "azure", "newscatcher")
    api_key_name: str = ""
    # If True, tool CANNOT function without this key (vs optional enhancement)
    api_key_required: bool = False
    # Terminal command to set the key (e.g., "run: set_api_key tineye YOUR_KEY")
    api_key_setup_command: str = ""
    # Where to get the API key
    api_key_url: str = ""
    # Human-readable reason why the key is needed and what it unlocks
    api_key_description: str = ""
    # Alternative tools that can work WITHOUT this key
    workarounds: list[str] = []
    # If no public API exists at all, explain why
    unavailable_reason: str = ""

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
        severity: FindingSeverity | None = None,
        **metadata,
    ) -> Finding:
        """Helper to create a Finding with source pre-filled.

        All extra kwargs go into Finding.metadata, except keys that collide
        with Finding's own fields (which are silently dropped from metadata).
        """
        import uuid

        # Strip any kwargs that collide with Finding model fields
        _finding_fields = {"id", "source", "tool", "title", "description",
                          "evidence", "severity", "confidence", "timestamp", "metadata"}
        safe_metadata = {k: v for k, v in metadata.items() if k not in _finding_fields}

        return Finding(
            id=f"{self.category.value}-{uuid.uuid4().hex[:8]}",
            source=self.category,
            tool=self.name,
            title=title,
            description=description,
            evidence=evidence or [],
            confidence=confidence,
            severity=severity or FindingSeverity.INFO,
            metadata=safe_metadata,
        )

    def __repr__(self) -> str:
        return f"<OSINTTool {self.name} ({self.category.value})>"
