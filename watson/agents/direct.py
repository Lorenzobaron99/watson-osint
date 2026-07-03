"""
Direct LLM adapter — any OpenAI-compatible API.
Uses DuckDuckGo via duckduckgo_search library for real web search.
"""

from __future__ import annotations

import asyncio
import json
import os
import re

import aiohttp

from .base import (
    AgentAdapter,
    BrowseResult,
    InvestigationResult,
    SearchResult,
    TerminalResult,
    VisionResult,
)

DEFAULT_API_BASE = "https://api.openai.com/v1"


class DirectAdapter(AgentAdapter):
    """LLM-agnostic adapter — any OpenAI-compatible API + DuckDuckGo search."""

    name = "direct"
    description = "Any OpenAI-compatible API + DuckDuckGo search"

    def __init__(
        self,
        api_key: str = "",
        model: str = "gpt-4o",
        api_base: str | None = None,
    ):
        self.api_key = api_key or os.environ.get("WATSON_API_KEY", "")
        self.model = model or os.environ.get("WATSON_MODEL", "gpt-4o")
        self.api_base = (
            api_base
            or os.environ.get("WATSON_API_BASE")
            or DEFAULT_API_BASE
        )
        self._ddgs = None

    @property
    def ddgs(self):
        """Lazy-load DuckDuckGo search client."""
        if self._ddgs is None:
            from ddgs import DDGS
            self._ddgs = DDGS()
        return self._ddgs

    async def _call_llm(
        self, prompt: str, system: str = "", max_tokens: int = 4000
    ) -> str:
        """Call the LLM API."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.api_base}/chat/completions",
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0.4,
                    "max_tokens": max_tokens,
                },
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"LLM API error ({resp.status}): {text}")
                data = await resp.json()
                return data["choices"][0]["message"]["content"]

    async def _ddg_search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Real web search via DuckDuckGo."""
        results: list[SearchResult] = []
        try:
            loop = asyncio.get_running_loop()
            raw_results = await loop.run_in_executor(
                None,
                lambda: list(self.ddgs.text(query, max_results=num_results))
            )
            for r in raw_results:
                results.append(SearchResult(
                    title=r.get("title", ""),
                    url=r.get("href", r.get("url", "")),
                    snippet=r.get("body", r.get("snippet", "")),
                    source="duckduckgo",
                ))
        except Exception:
            pass
        return results

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Web search via DuckDuckGo only. No LLM fallback — only real data."""
        return await self._ddg_search(query, num_results)

    async def browse(self, url: str) -> BrowseResult:
        """Fetch URL content via HTTP."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; Watson-OSINT/1.0)"},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    text = await resp.text()
                    # Strip HTML tags for plain text
                    clean = re.sub(r"<[^>]+>", " ", text)
                    clean = re.sub(r"\s+", " ", clean)
                    return BrowseResult(
                        url=url,
                        content=clean[:5000],
                        title=url,
                    )
        except Exception:
            return BrowseResult(url=url, content=f"[Could not fetch {url}]", title=url)

    async def vision(self, image_path: str, question: str = "Describe this image in detail.") -> VisionResult:
        """LLM cannot analyze images."""
        return VisionResult(
            description=f"[Direct adapter cannot analyze images. Use Hermes for vision.]",
        )

    async def terminal(self, command: str, timeout: int = 30) -> TerminalResult:
        """Execute commands via subprocess (available in Direct mode too)."""
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode("utf-8", errors="replace")
            if stderr:
                output += "\n" + stderr.decode("utf-8", errors="replace")
            return TerminalResult(
                output=output.strip() or "(no output)",
                exit_code=proc.returncode or 0,
            )
        except asyncio.TimeoutError:
            return TerminalResult(output="Command timed out", exit_code=1)
        except Exception as e:
            return TerminalResult(output=str(e), exit_code=1)

    async def investigate_angle(self, angle: str, query: str) -> InvestigationResult:
        """Analyze real search results for investigation findings.

        Always performs DDG web search (no API key needed).
        With LLM API key: enriches results with AI analysis.
        Without: returns raw DDG results directly — never returns empty.
        """
        # Get real search results (no API key needed)
        search_results = await self._ddg_search(query, num_results=5)
        if not search_results:
            return InvestigationResult(
                angle=angle, confidence=0.0,
                raw="No search results available for this angle."
            )

        # Without LLM, return raw DDG results as findings
        if not self.api_key:
            raw = "\n".join(
                f"• {r.title}\n  {r.snippet[:200]}\n  {r.url}"
                for r in search_results
            )
            return InvestigationResult(
                angle=angle,
                raw=raw,
                findings=[
                    {"title": r.title, "snippet": r.snippet, "url": r.url}
                    for r in search_results
                ],
                sources=[r.url for r in search_results if r.url],
                confidence=0.4,
            )

        # With LLM: enrich with AI analysis
        context = "\n".join(
            f"- {r.title}: {r.snippet} ({r.url})"
            for r in search_results
        )

        try:
            response = await self._call_llm(
                prompt=(
                    f"ANALYZE these search results for an OSINT investigation.\n\n"
                    f"Angle: {angle}\n"
                    f"Query: {query}\n\n"
                    f"SEARCH RESULTS:\n{context}\n\n"
                    f"Extract the key facts from these results. Return:\n"
                    f"1. A 1-sentence summary of what was found\n"
                    f"2. 3-5 specific findings, each with the source URL\n"
                    f"3. Names, dates, and key facts mentioned\n"
                    f"4. What's missing or needs deeper investigation\n\n"
                    f"Be concise. Use ONLY information from the search results above."
                ),
                system=(
                    "You analyze search results for OSINT investigations. "
                    "Extract facts from provided results only. Do not invent or plan — analyze."
                ),
                max_tokens=2000,
            )

            urls = [r.url for r in search_results if r.url]
            return InvestigationResult(
                angle=angle,
                raw=response,
                sources=urls,
                confidence=0.5 if len(response) > 200 else 0.3,
            )
        except Exception as e:
            return InvestigationResult(angle=angle, confidence=0.0, raw=str(e))
