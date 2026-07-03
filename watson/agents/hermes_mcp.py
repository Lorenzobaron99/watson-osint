"""HermesMCPAdapter — connects Watson to Hermes via MCP protocol.

Uses Hermes as an MCP client connected to Watson's MCP server.
Hermes auto-discovers Watson's OSINT tools (watson_search, watson_traverse, etc.)
and uses them for investigations.

Survives most Hermes CLI flag changes — only depends on `hermes chat` core flags
(-q, --yolo, --max-turns) which are stable. Toolset names and output format
changes are handled by MCP protocol auto-discovery.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile

from .base import (
    AgentAdapter,
    BrowseResult,
    InvestigationResult,
    SearchResult,
    TerminalResult,
    VisionResult,
)
# Reuse CLI adapter's response extraction (import function, not class)
from .hermes import _extract_response as _hermes_extract_response

HERMES_BIN = shutil.which("hermes") or "hermes"


class HermesMCPAdapter(AgentAdapter):
    """Adapter that delegates to Hermes via MCP protocol.

    Hermes connects to Watson's MCP server (port 8700) as an MCP client.
    Watson's OSINT tools (watson_search, watson_traverse, etc.) are auto-discovered
    by Hermes and used for investigations.

    This adapter survives Hermes CLI flag changes — it only depends on:
    - `hermes` binary existing
    - `hermes chat -q --yolo --max-turns` core flags (rarely change)
    - Hermes MCP client support (built-in)
    """

    name = "hermes-mcp"
    description = (
        "Hermes via MCP — stable protocol, survives CLI updates, "
        "auto-discovers Watson tools"
    )

    def __init__(
        self,
        hermes_bin: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        mcp_url: str = "http://localhost:8700",
        timeout: int = 300,
    ):
        self.hermes_bin = hermes_bin or HERMES_BIN
        self.model = model
        self.provider = provider
        self.mcp_url = mcp_url
        self.timeout = timeout

    async def _hermes_mcp_chat(
        self,
        query: str,
        max_turns: int = 15,
        timeout: int | None = None,
    ) -> str:
        """Run Hermes in MCP mode connected to Watson's MCP server.

        Hermes auto-discovers Watson's OSINT tools from the MCP server.
        A temp config file is used so we don't pollute the user's config.
        """
        config_yaml = (
            f"mcp_servers:\n"
            f"  watson:\n"
            f"    url: \"{self.mcp_url}\"\n"
            f"    timeout: 120\n"
        )

        config_path = None
        try:
            # Write temp config — yaml not required, simple string works
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False, prefix="watson_mcp_"
            ) as f:
                f.write(config_yaml)
                config_path = f.name

            args = [
                self.hermes_bin, "chat",
                "-q", query,
                "--yolo",
                "--max-turns", str(max_turns),
                "--config", config_path,
            ]
            if self.model:
                args.extend(["-m", self.model])
            if self.provider:
                args.extend(["--provider", self.provider])

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "NO_COLOR": "1"},
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout or self.timeout,
            )
            output = stdout.decode("utf-8", errors="replace")

            # Reuse CLI adapter's response extraction
            return _hermes_extract_response(output)

        except asyncio.TimeoutError:
            return ""
        except FileNotFoundError:
            return (
                "[Hermes not found. "
                "Install Hermes: https://hermes-agent.nousresearch.com]"
            )
        except Exception as e:
            return f"[Hermes MCP error: {e}]"
        finally:
            if config_path:
                try:
                    os.unlink(config_path)
                except OSError:
                    pass

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Web search via Hermes MCP (uses watson_search or web_search tools)."""
        response = await self._hermes_mcp_chat(
            f"Search for: {query}\n\n"
            f"Use available search tools. Return {num_results} results "
            f"with title and URL for each. Be concise.",
            max_turns=3,
        )
        if not response:
            return []

        results: list[SearchResult] = []
        for line in response.split("\n"):
            line = line.strip()
            if not line:
                continue
            url_match = re.search(r"(https?://[^\s)\]]+)", line)
            if url_match:
                url = url_match.group(1).rstrip(".)")
                title = re.sub(
                    r"^\d+[\.\)]\s*", "", line[: url_match.start()]
                ).strip()
                title = re.sub(r"[-–—]\s*$", "", title).strip()
                results.append(
                    SearchResult(
                        title=title or query,
                        url=url,
                        snippet=line,
                        source="hermes-mcp",
                    )
                )
        return results[:num_results]

    async def browse(self, url: str) -> BrowseResult:
        """Browse a URL via Hermes MCP browser."""
        response = await self._hermes_mcp_chat(
            f"Navigate to this URL and extract the main content: {url}\n\n"
            f"Return the page title and a summary of what's on the page.",
            max_turns=5,
        )
        title = ""
        for line in response.split("\n"):
            if line.startswith("#") or "title" in line.lower():
                title = line.lstrip("# ").strip()
                break
        return BrowseResult(url=url, content=response, title=title or url)

    async def vision(
        self, image_path: str, question: str = ""
    ) -> VisionResult:
        """Analyze image via Hermes MCP vision. Falls back to CLI --image flag."""
        try:
            args = [
                self.hermes_bin,
                "chat",
                "-q",
                question or "Describe this image in detail.",
                "--image",
                image_path,
                "--yolo",
                "--max-turns",
                "3",
            ]
            if self.model:
                args.extend(["-m", self.model])

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode("utf-8", errors="replace")
            return VisionResult(
                description=_hermes_extract_response(output)
            )
        except Exception:
            return VisionResult(description="Vision analysis unavailable")

    async def terminal(
        self, command: str, timeout: int = 30
    ) -> TerminalResult:
        """Execute command via Python subprocess (fast path, no Hermes needed)."""
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
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

    async def investigate_angle(
        self, angle: str, query: str
    ) -> InvestigationResult:
        """Full OSINT investigation via Hermes MCP with Watson tools."""
        response = await self._hermes_mcp_chat(
            f"You are Watson, a world-class OSINT investigator. "
            f"You have access to MCP tools from the Watson server: "
            f"watson_search, watson_traverse, watson_context, "
            f"watson_stats, and watson_case.\n\n"
            f"TARGET: {query}\n"
            f"ANGLE: {angle}\n\n"
            f"IMPORTANT: Do NOT write a final report. Investigate step by step:\n"
            f"1. Use watson_context to check for prior intelligence on the target\n"
            f"2. Use watson_search to find information from multiple angles\n"
            f"3. Cross-reference across sources — verify names, dates, identifiers\n"
            f"4. Extract source URLs for every claim\n"
            f"5. Report findings with confidence scores\n\n"
            f"Be thorough. Use as many tool-calling turns as needed.",
            max_turns=20,
            timeout=300,
        )

        if not response:
            return InvestigationResult(angle=angle, confidence=0.0)

        urls = re.findall(r"https?://[^\s)\]]+", response)
        sources = urls[:10] if urls else []

        return InvestigationResult(
            angle=angle,
            raw=response,
            sources=sources,
            confidence=0.7 if len(response) > 200 else 0.4,
        )

    async def health_check(self) -> bool:
        """Check if Hermes binary exists and is executable."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.hermes_bin,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            return proc.returncode == 0
        except Exception:
            return False

    async def close(self):
        """No persistent connection — temp configs cleaned up per-call."""
        pass
