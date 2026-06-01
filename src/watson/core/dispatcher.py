"""Parallel dispatcher — maps queries to tools and runs them concurrently."""

from __future__ import annotations

import asyncio
from typing import Optional

from .models import Finding, FindingSource, InvestigationRequest, InvestigationTask
from ..tools.registry import registry


# Mapping from investigation intent keywords to tool categories
INTENT_MAP: dict[str, list[FindingSource]] = {
    "who": [FindingSource.PEOPLE, FindingSource.SOCIAL_MEDIA, FindingSource.CORPORATE],
    "what": [FindingSource.WEBSITES, FindingSource.CORPORATE, FindingSource.IMAGE_VIDEO],
    "where": [FindingSource.GEOLOCATION, FindingSource.SATELLITE, FindingSource.CONFLICT],
    "when": [FindingSource.WEBSITES, FindingSource.SATELLITE, FindingSource.CONFLICT],
    "domain": [FindingSource.WEBSITES, FindingSource.CORPORATE, FindingSource.PEOPLE],
    "company": [FindingSource.CORPORATE, FindingSource.WEBSITES, FindingSource.SOCIAL_MEDIA],
    "person": [FindingSource.PEOPLE, FindingSource.SOCIAL_MEDIA, FindingSource.WEBSITES],
    "image": [FindingSource.IMAGE_VIDEO, FindingSource.GEOLOCATION, FindingSource.SOCIAL_MEDIA],
    "location": [FindingSource.GEOLOCATION, FindingSource.SATELLITE, FindingSource.CONFLICT],
    "satellite": [FindingSource.SATELLITE, FindingSource.GEOLOCATION],
    "social": [FindingSource.SOCIAL_MEDIA, FindingSource.PEOPLE, FindingSource.WEBSITES],
    "conflict": [FindingSource.CONFLICT, FindingSource.SATELLITE, FindingSource.GEOLOCATION],
    "owner": [FindingSource.WEBSITES, FindingSource.CORPORATE, FindingSource.PEOPLE],
}

# Fallback categories when no intent is matched
DEFAULT_CATEGORIES: list[FindingSource] = [
    FindingSource.WEBSITES,
    FindingSource.PEOPLE,
    FindingSource.SOCIAL_MEDIA,
    FindingSource.CORPORATE,
]


class Dispatcher:
    """Decomposes queries and dispatches parallel investigations."""

    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

    def _detect_intent(self, query: str) -> list[FindingSource]:
        """Detect which tool categories are relevant based on query keywords."""
        query_lower = query.lower()
        matched: set[FindingSource] = set()

        for keyword, categories in INTENT_MAP.items():
            if keyword in query_lower:
                matched.update(categories)

        # If nothing matched, use defaults
        if not matched:
            matched.update(DEFAULT_CATEGORIES)

        return list(matched)

    def _decompose(
        self, request: InvestigationRequest
    ) -> list[InvestigationTask]:
        """Decompose the investigation request into individual tool tasks."""
        # Use explicit tools if provided, otherwise auto-detect from query
        if request.tools is not None:
            categories = request.tools
        else:
            categories = self._detect_intent(request.query)
        tasks: list[InvestigationTask] = []

        for i, cat in enumerate(categories):
            tools = registry.get_for_category(cat)
            if not tools:
                continue

            for tool in tools:
                tasks.append(
                    InvestigationTask(
                        id=f"{cat.value}-{i}",
                        tool_category=cat,
                        query=request.query,
                        context=request.query,
                        priority=1,
                    )
                )

        return tasks

    async def _run_tool(
        self,
        task: InvestigationTask,
        timeout: float = 25.0,
    ) -> list[Finding]:
        """Run a single tool investigation with concurrency control."""
        tool = registry.get(task.tool_category.value) or next(
            iter(registry.get_for_category(task.tool_category)), None
        )
        if tool is None:
            return []

        async with self._semaphore:
            try:
                findings = await asyncio.wait_for(
                    tool.investigate(task.query, task.context),
                    timeout=timeout,
                )
                return findings
            except asyncio.TimeoutError:
                return [
                    Finding(
                        id=f"timeout-{task.tool_category.value}",
                        source=task.tool_category,
                        tool=tool.name if tool else "unknown",
                        title=f"Timeout in {task.tool_category.value} tool",
                        description=f"Investigation timed out after {timeout}s",
                        confidence=0.0,
                    )
                ]
            except Exception as e:
                return [
                    Finding(
                        id=f"error-{task.tool_category.value}",
                        source=task.tool_category,
                        tool=tool.name if tool else "unknown",
                        title=f"Error in {task.tool_category.value} tool",
                        description=f"Investigation failed: {str(e)}",
                        confidence=0.0,
                    )
                ]

    async def dispatch(
        self, request: InvestigationRequest
    ) -> list[Finding]:
        """Dispatch investigation across all relevant tools in parallel.

        Args:
            request: The investigation request

        Returns:
            Combined list of findings from all tools
        """
        tasks = self._decompose(request)

        if not tasks:
            return []

        # Run all tool investigations in parallel
        results = await asyncio.gather(
            *[self._run_tool(task) for task in tasks],
            return_exceptions=True,
        )

        # Flatten results, filtering out exceptions
        findings: list[Finding] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result[: request.max_findings_per_tool])

        return findings
