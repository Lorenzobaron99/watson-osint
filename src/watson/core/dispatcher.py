"""Parallel dispatcher — maps queries to tools and runs them concurrently.

Upgraded with LLM-powered semantic reasoning: before dispatching tools,
the ReasoningEngine analyzes the query to understand entities, search
targets, and investigation angles — not just regex keyword matching.

Fallback: when no LLM is available, falls back to the keyword-based
INTENT_MAP for basic tool selection.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from .models import Finding, FindingSource, InvestigationRequest, InvestigationTask
from .reasoning import ReasoningEngine, ReasoningResult
from ..tools.registry import registry


# ── Fallback intent map (keyword → tool categories) ────────────────
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
    "linkedin": [FindingSource.SOCIAL_MEDIA, FindingSource.PEOPLE],
    "github": [FindingSource.SOCIAL_MEDIA, FindingSource.PEOPLE, FindingSource.WEBSITES],
    "twitter": [FindingSource.SOCIAL_MEDIA],
    "instagram": [FindingSource.SOCIAL_MEDIA],
    "substack": [FindingSource.SOCIAL_MEDIA, FindingSource.WEBSITES],
    "tiktok": [FindingSource.SOCIAL_MEDIA],
    "youtube": [FindingSource.SOCIAL_MEDIA],
    "email": [FindingSource.PEOPLE],
    "captcha": [FindingSource.IMAGE_VIDEO],
    "solve": [FindingSource.IMAGE_VIDEO],
    "osint": [FindingSource.BELLINGCAT, FindingSource.WEBSITES, FindingSource.PEOPLE,
              FindingSource.CORPORATE, FindingSource.SOCIAL_MEDIA],
    "bellingcat": [FindingSource.BELLINGCAT],
    "all tools": [FindingSource.BELLINGCAT],
    "full investigation": [FindingSource.BELLINGCAT],
    "investigate": [FindingSource.BELLINGCAT],
}

DEFAULT_CATEGORIES: list[FindingSource] = [
    FindingSource.BELLINGCAT,
    FindingSource.WEBSITES,
    FindingSource.PEOPLE,
    FindingSource.SOCIAL_MEDIA,
    FindingSource.CORPORATE,
]


class Dispatcher:
    """Decomposes queries and dispatches parallel investigations.

    LLM-POWERED REASONING (NEW):
    Before tool dispatch, the ReasoningEngine semantically analyzes
    the query — identifying entities, search targets, and investigation
    angles. This replaces the naive keyword-matching from v1.

    API KEY AWARENESS:
    Before running any tool, checks if the tool requires an API key.
    If missing, returns a clear "skipped" finding with setup instructions.
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        api_keys: dict | None = None,
        reasoning_engine: ReasoningEngine | None = None,
        on_reasoning: Callable[[ReasoningResult], None] | None = None,
    ):
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._api_keys = api_keys or {}
        self._reasoning = reasoning_engine or ReasoningEngine()
        self._on_reasoning = on_reasoning
        self.last_reasoning: ReasoningResult | None = None

    def _detect_intent(self, query: str) -> list[FindingSource]:
        """Fallback keyword-based intent detection (no LLM)."""
        query_lower = query.lower()
        matched: set[FindingSource] = set()

        for keyword, categories in INTENT_MAP.items():
            if keyword in query_lower:
                matched.update(categories)

        if not matched:
            matched.update(DEFAULT_CATEGORIES)

        return list(matched)

    def _decompose(
        self, request: InvestigationRequest
    ) -> list[InvestigationTask]:
        """Decompose the investigation request into individual tool tasks.

        Now uses LLM-powered reasoning FIRST, then falls back to
        keyword matching if reasoning is unavailable.
        """
        # ── Step 0: Semantic reasoning ─────────────────────────
        reasoning = None
        if self._reasoning.available:
            reasoning = self._reasoning.reason(request.query)
            if reasoning and reasoning.confidence > 0:
                self.last_reasoning = reasoning
                if self._on_reasoning:
                    self._on_reasoning(reasoning)

        # ── Step 1: Determine tool categories ──────────────────
        if request.tools is not None:
            categories = request.tools
        elif reasoning and reasoning.key_entities:
            categories = self._categories_from_reasoning(reasoning)
        else:
            categories = self._detect_intent(request.query)

        # ── Step 2: Create tool tasks ──────────────────────────
        tasks: list[InvestigationTask] = []

        for i, cat in enumerate(categories):
            tools = registry.get_for_category(cat)
            if not tools:
                continue

            for tool in tools:
                tasks.append(
                    InvestigationTask(
                        id=f"{cat.value}-{tool.name}",
                        tool_category=cat,
                        tool_name=tool.name,
                        query=request.query,
                        context=request.query,
                        priority=1,
                    )
                )

        # ── Step 3: Seed extra tasks from reasoning ─────────────
        # Only spawn tasks for GENUINELY new targets not already covered.
        # One tool per target, cap at 12 total.
        if reasoning and len(tasks) < 12:
            primary_queries = {t.query.lower() for t in tasks}
            for st in reasoning.search_targets:
                target = st.get("target", "").strip()
                if not target or len(target) < 3:
                    continue
                if target.lower() in primary_queries:
                    continue

                toolkit = st.get("toolkit", "socmint")
                
                # Skip bellingcat reasoning targets if primary dispatch already
                # has bellingcat — it already does a full investigation.
                # Reasoning search angles are refinements, not new targets.
                if toolkit == "bellingcat":
                    has_primary_bellingcat = any(
                        t.tool_category == FindingSource.BELLINGCAT
                        for t in tasks
                    )
                    if has_primary_bellingcat:
                        continue
                    cat = FindingSource.BELLINGCAT
                elif toolkit == "socmint":
                    cat = FindingSource.SOCIAL_MEDIA
                else:
                    continue

                tools = registry.get_for_category(cat)
                if tools:
                    tool = tools[0]
                    task_id = f"reasoning-{cat.value}-{tool.name}-{len(tasks)}"
                    if not any(t.id == task_id for t in tasks):
                        tasks.append(
                            InvestigationTask(
                                id=task_id,
                                tool_category=cat,
                                tool_name=tool.name,
                                query=target,
                                context=st.get("reason", ""),
                                priority=2,
                            )
                        )

        return tasks

    def _categories_from_reasoning(
        self, reasoning: ReasoningResult
    ) -> list[FindingSource]:
        """Derive tool categories from semantic reasoning."""
        target_type = reasoning.target_type
        categories: set[FindingSource] = set()

        # Start with defaults
        categories.update(DEFAULT_CATEGORIES)

        # Refine based on target type
        type_map = {
            "person": [FindingSource.PEOPLE, FindingSource.SOCIAL_MEDIA, FindingSource.WEBSITES, FindingSource.BELLINGCAT],
            "domain": [FindingSource.WEBSITES, FindingSource.CORPORATE, FindingSource.BELLINGCAT],
            "company": [FindingSource.CORPORATE, FindingSource.WEBSITES, FindingSource.SOCIAL_MEDIA, FindingSource.BELLINGCAT],
            "email": [FindingSource.PEOPLE, FindingSource.SOCIAL_MEDIA, FindingSource.BELLINGCAT],
            "image": [FindingSource.IMAGE_VIDEO, FindingSource.GEOLOCATION, FindingSource.SOCIAL_MEDIA],
            "location": [FindingSource.GEOLOCATION, FindingSource.SATELLITE, FindingSource.CONFLICT],
            "topic": [FindingSource.BELLINGCAT, FindingSource.WEBSITES, FindingSource.PEOPLE, FindingSource.SOCIAL_MEDIA],
        }

        if target_type in type_map:
            categories = set(type_map[target_type])

        return list(categories)

    async def _run_tool(
        self,
        task: InvestigationTask,
        timeout: float = 120.0,
    ) -> list[Finding]:
        """Run a single tool investigation with concurrency control."""
        tool = registry.get(task.tool_name) if task.tool_name else None
        if tool is None:
            tool = next(iter(registry.get_for_category(task.tool_category)), None)
        if tool is None:
            return []

        # ── API Key Gate ────────────────────────────────────────
        if getattr(tool, "requires_api_key", False):
            key_name = getattr(tool, "api_key_name", "")
            key_required = getattr(tool, "api_key_required", False)
            setup_cmd = getattr(tool, "api_key_setup_command", "")
            key_url = getattr(tool, "api_key_url", "")
            key_desc = getattr(tool, "api_key_description", "")
            workarounds = getattr(tool, "workarounds", [])
            unavailable = getattr(tool, "unavailable_reason", "")

            key_value = self._api_keys.get(key_name, "") if key_name else ""

            if unavailable:
                return [
                    Finding(
                        id=f"unavailable-{tool.name}",
                        source=task.tool_category,
                        tool=tool.name,
                        title=f"⊘ {tool.name}: Unavailable — {unavailable}",
                        description=f"This tool cannot be automated. {unavailable}",
                        confidence=0.0,
                        metadata={"skipped": True, "unavailable": True},
                    )
                ]

            if key_required and not key_value:
                alt_msg = ""
                if workarounds:
                    alt_msg = f"\nAlternatives: {', '.join(workarounds)}"
                return [
                    Finding(
                        id=f"no-key-{tool.name}",
                        source=task.tool_category,
                        tool=tool.name,
                        title=f"🔑 {tool.name}: API key needed",
                        description=(
                            f"{key_desc or 'This tool requires an API key.'}\n"
                            f"To enable: run this command in the terminal → {setup_cmd}\n"
                            f"Get a key at: {key_url or 'see documentation'}"
                            f"{alt_msg}"
                        ),
                        confidence=0.0,
                        metadata={
                            "skipped": True,
                            "needs_api_key": key_name,
                            "setup_command": setup_cmd,
                            "key_url": key_url,
                            "workarounds": workarounds,
                        },
                    )
                ]

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
        """Dispatch investigation across all relevant tools in parallel."""
        tasks = self._decompose(request)

        if not tasks:
            return []

        results = await asyncio.gather(
            *[self._run_tool(task) for task in tasks],
            return_exceptions=True,
        )

        findings: list[Finding] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result[: request.max_findings_per_tool])

        return findings
