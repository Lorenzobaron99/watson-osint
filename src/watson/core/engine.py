"""Investigation engine — top-level orchestrator for Watson."""

from __future__ import annotations

import asyncio
from typing import Optional

from .dispatcher import Dispatcher
from .models import Finding, InvestigationRequest, Report
from .reporter import Reporter


class Engine:
    """Top-level investigation engine.

    Usage:
        engine = Engine()
        report = await engine.investigate("who owns shady-domain.com?")
    """

    def __init__(self, max_concurrent: int = 5, cross_reference: bool = True):
        self.dispatcher = Dispatcher(max_concurrent=max_concurrent)
        self.reporter = Reporter(cross_reference=cross_reference)

    async def investigate(self, query: str, tools: Optional[list[str]] = None) -> Report:
        """Run a full investigation.

        Args:
            query: Natural language investigation query
            tools: Optional list of tool categories to use (default: auto-detect)

        Returns:
            Structured Report with findings and cross-references
        """
        request = InvestigationRequest(query=query)

        # If specific tools requested, map them
        if tools:
            from .models import FindingSource

            request.tools = []
            for t in tools:
                try:
                    request.tools.append(FindingSource(t.lower()))
                except ValueError:
                    pass

        # Dispatch parallel investigation
        findings = await self.dispatcher.dispatch(request)

        # Generate report
        report = self.reporter.generate(query, findings)

        return report

    def investigate_sync(self, query: str, tools: Optional[list[str]] = None) -> Report:
        """Synchronous wrapper for investigate."""
        return asyncio.run(self.investigate(query, tools))
