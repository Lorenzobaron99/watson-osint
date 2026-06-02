"""
Direct LLM adapter — no agent engine required. Calls an LLM API directly.
Best for quick start when Hermes/OpenClaw aren't installed.
Uses DuckDuckGo for real web search (free, no API key needed).
Limited to web search and basic reasoning — no browser, vision, or terminal.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from urllib.parse import quote

import aiohttp

from .base import (
    AgentAdapter,
    BrowseResult,
    InvestigationResult,
    SearchResult,
    TerminalResult,
    VisionResult,
)

DEFAULT_API_BASE = "https://api.deepseek.com/v1"
DUCKDUCKGO_HTML = "https://html.duckduckgo.com/html/"


class DirectAdapter(AgentAdapter):
    """Adapter that calls an LLM API directly (no agent engine)."""

    name = "direct"
    description = "Direct LLM + DuckDuckGo — API key only, no local agent install"

    def __init__(
        self,
        api_key: str = "",
        model: str = "deepseek-chat",
        api_base: str | None = None,
    ):
        self.api_key = api_key or os.environ.get(
            "WATSON_API_KEY",
            os.environ.get("DEEPSEEK_API_KEY", ""),
        )
        self.model = model
        self.api_base = api_base or os.environ.get(
            "DEEPSEEK_API_BASE", DEFAULT_API_BASE
        )

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
        """Real web search via DuckDuckGo HTML endpoint (free, no API key)."""
        results: list[SearchResult] = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    DUCKDUCKGO_HTML,
                    data={"q": query, "b": ""},
                    headers={
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    html = await resp.text()

            # Parse DuckDuckGo HTML results
            # Results are in <a class="result__a" href="...">Title</a>
            # and <a class="result__snippet">Snippet</a>

            # Find result blocks: each result has class="result__body"
            blocks = re.split(r'class="result__body"', html)[1:]  # skip before first

            for block in blocks[:num_results]:
                # Extract URL and title
                link_match = re.search(
                    r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                    block,
                    re.DOTALL,
                )
                # Extract snippet
                snippet_match = re.search(
                    r'class="result__snippet"[^>]*>(.*?)</a>',
                    block,
                    re.DOTALL,
                )

                if link_match:
                    url = link_match.group(1)
                    title = re.sub(r"<[^>]+>", "", link_match.group(2)).strip()
                    snippet = ""
                    if snippet_match:
                        snippet = re.sub(r"<[^>]+>", "", snippet_match.group(1)).strip()

                    results.append(SearchResult(
                        title=title or query,
                        url=url,
                        snippet=snippet,
                        source="duckduckgo",
                    ))

        except Exception:
            pass

        return results

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Web search via DuckDuckGo. Falls back to LLM if DDG fails."""
        # Try real search first
        results = await self._ddg_search(query, num_results)
        if results:
            return results

        # Fallback: LLM-powered search context
        if not self.api_key:
            return []

        try:
            response = await self._call_llm(
                prompt=(
                    f"You are a search engine. For the query below, return 5-10 relevant web results.\n"
                    f"Query: {query}\n\n"
                    f"Return a JSON array of objects with 'title', 'url', and 'snippet' fields.\n"
                    f"Use real URLs from well-known sources. Only return the JSON array, nothing else."
                ),
                system="You are a search engine. Return real, relevant web results.",
                max_tokens=2000,
            )

            try:
                data = json.loads(response)
                if isinstance(data, list):
                    return [
                        SearchResult(
                            title=r.get("title", ""),
                            url=r.get("url", ""),
                            snippet=r.get("snippet", ""),
                            source="llm-fallback",
                        )
                        for r in data[:num_results]
                    ]
            except json.JSONDecodeError:
                match = re.search(r"\[.*\]", response, re.DOTALL)
                if match:
                    data = json.loads(match.group(0))
                    return [
                        SearchResult(
                            title=r.get("title", ""),
                            url=r.get("url", ""),
                            snippet=r.get("snippet", ""),
                            source="llm-fallback",
                        )
                        for r in data[:num_results]
                    ]

            return []
        except Exception:
            return results  # Return whatever DDG gave us, even if empty

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
        """LLM-powered investigation angle with real search results as context."""
        if not self.api_key:
            return InvestigationResult(angle=angle, confidence=0.0)

        # First, get real search results
        search_results = await self._ddg_search(query, num_results=5)
        context = "\n".join(
            f"- {r.title}: {r.snippet} ({r.url})"
            for r in search_results
        ) if search_results else "(no search results available)"

        try:
            response = await self._call_llm(
                prompt=(
                    f"You are Watson, an OSINT investigator using the Bellingcat methodology.\n\n"
                    f"INVESTIGATION ANGLE: {angle}\n"
                    f"SEARCH QUERY: {query}\n\n"
                    f"REAL SEARCH RESULTS (use these as sources):\n{context}\n\n"
                    f"Research this angle using the search results above.\n"
                    f"Return a structured investigation report with:\n"
                    f"- Key findings (at least 3) with citations from the URLs above\n"
                    f"- Source URLs for each finding\n"
                    f"- Names, dates, and key facts discovered\n"
                    f"- Confidence assessment for each finding"
                ),
                system=(
                    "You are Watson, an OSINT investigator. You use open-source intelligence "
                    "methods inspired by Bellingcat. Be thorough, cite real sources, and "
                    "distinguish between confirmed facts and speculation."
                ),
                max_tokens=3000,
            )

            urls = [r.url for r in search_results if r.url]
            return InvestigationResult(
                angle=angle,
                raw=response,
                sources=urls,
                confidence=0.6 if len(response) > 300 else 0.4,
            )
        except Exception as e:
            return InvestigationResult(angle=angle, confidence=0.0, raw=str(e))
