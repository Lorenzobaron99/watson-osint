"""
Hermes agent adapter — connects Watson to a local Hermes CLI.
Uses `hermes chat -q` (one-shot mode) for programmatic tool access.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil

from .base import (
    AgentAdapter,
    BrowseResult,
    InvestigationResult,
    SearchResult,
    TerminalResult,
    VisionResult,
)

HERMES_BIN = shutil.which("hermes") or "hermes"


class HermesCLIAdapter(AgentAdapter):
    """Adapter that delegates to Hermes CLI via subprocess.

    Uses `hermes chat -q` one-shot mode with --yolo for auto-approval.
    Each tool call spawns a short-lived Hermes process.

    For production: use HermesMCPAdapter for MCP protocol transport.
    """

    name = "hermes"
    description = "Local Hermes agent — full toolset (web, browser, vision, terminal, MCP)"

    def __init__(
        self,
        hermes_bin: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        timeout: int = 90,
    ):
        self.hermes_bin = hermes_bin or HERMES_BIN
        self.model = model
        self.provider = provider
        self.timeout = timeout

    def _build_args(self, query: str, toolsets: str = "web", max_turns: int = 5) -> list[str]:
        """Build Hermes CLI arguments."""
        args = [
            self.hermes_bin, "chat",
            "-q", query,
            "--yolo",
            "--max-turns", str(max_turns),
            "-t", toolsets,
        ]
        if self.model:
            args.extend(["-m", self.model])
        if self.provider:
            args.extend(["--provider", self.provider])
        return args

    async def _hermes_chat(
        self,
        query: str,
        toolsets: str = "web",
        max_turns: int = 5,
        timeout: int | None = None,
    ) -> str:
        """Run Hermes in one-shot mode and return the response text."""
        args = self._build_args(query, toolsets, max_turns)

        try:
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
            # Extract the response between the box-drawing header and footer
            return _extract_response(output)
        except asyncio.TimeoutError:
            return ""
        except FileNotFoundError:
            return f"[Hermes not found. Install Hermes: https://hermes-agent.nousresearch.com]"
        except Exception:
            return ""

def _extract_response(output: str) -> str:
    """Extract the agent's actual response from Hermes chat output.

    Shared between HermesCLIAdapter and HermesMCPAdapter.
    """
    import re

    # Strip ANSI escape sequences (SGR, cursor movement, etc.)
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r')
    clean = ansi_escape.sub('', output)

    # Strip box-drawing and other Unicode control glyphs that survive
    # terminal mangling
    clean = re.sub(r'[\x80-\x9f]', '', clean)

    lines = clean.split("\n")
    response_lines = []
    in_response = False
    for line in lines:
        stripped = line.strip()
        # Match header: any line containing "Hermes" followed by dashes
        if not in_response and "Hermes" in stripped:
            in_response = True
            continue
        if in_response:
            # Footer: line that is all dashes/spaces (end of box)
            if stripped and re.match(r'^[\u2500\u2501\u2014\u2015\-\s]+$', stripped):
                break
            if stripped:
                response_lines.append(stripped)
    return "\n".join(response_lines)

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Web search via Hermes."""
        response = await self._hermes_chat(
            f"Search the web for: {query}\n\n"
            f"Return results as a list with title and URL for each. "
            f"Be concise — {num_results} results max.",
            toolsets="web",
            max_turns=3,
        )
        if not response:
            return []

        results: list[SearchResult] = []
        # Parse: "1. Title — URL" or "Title (URL)" or markdown links
        for line in response.split("\n"):
            line = line.strip()
            if not line:
                continue
            url_match = re.search(r"(https?://[^\s)\]]+)", line)
            if url_match:
                url = url_match.group(1).rstrip(".)")
                title = re.sub(r"^\d+[\.\)]\s*", "", line[:url_match.start()]).strip()
                title = re.sub(r"[-–—]\s*$", "", title).strip()
                results.append(SearchResult(
                    title=title or query,
                    url=url,
                    snippet=line,
                    source="hermes-web-search",
                ))
        return results[:num_results]

    async def browse(self, url: str) -> BrowseResult:
        """Browse a URL via Hermes browser."""
        response = await self._hermes_chat(
            f"Go to this URL and extract the main content: {url}\n\n"
            f"Return the page title and a summary of what's on the page.",
            toolsets="web,browser",
            max_turns=5,
        )
        title = ""
        for line in response.split("\n"):
            if line.startswith("#") or "title" in line.lower():
                title = line.lstrip("# ").strip()
                break

        return BrowseResult(
            url=url,
            content=response,
            title=title or url,
        )

    async def vision(self, image_path: str, question: str = "Describe this image in detail.") -> VisionResult:
        """Analyze an image via Hermes vision."""
        # Hermes chat supports --image flag
        try:
            args = [
                self.hermes_bin, "chat",
                "-q", question,
                "--image", image_path,
                "--yolo",
                "--max-turns", "3",
                "-t", "vision",
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
            description = _extract_response(output)
            return VisionResult(description=description)
        except Exception:
            return VisionResult(description="Vision analysis unavailable")

    async def terminal(self, command: str, timeout: int = 30) -> TerminalResult:
        """Execute a command directly via Python subprocess (fast path)."""
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
        """Run a full investigation angle using Hermes with OSINT skills."""
        response = await self._hermes_chat(
            f"You are Watson, a world-class OSINT investigator using the Bellingcat methodology. "
            f"You have web search, browser, and terminal tools.\n\n"
            f"TARGET: {query}\n"
            f"ANGLE: {angle}\n\n"
            f"IMPORTANT: Do NOT write a final report. INSTEAD, investigate step by step:\n"
            f"1. Search the web for the target using multiple queries\n"
            f"2. Read the most relevant URLs to extract facts\n"
            f"3. Cross-reference across sources — names, dates, identifiers, documents\n"
            f"4. Search again for leads discovered in the sources\n"
            f"5. Resolve entities with confidence scores\n"
            f"6. Extract source URLs for every claim\n\n"
            f"Use as many tool-calling turns as needed. Be thorough.",
            toolsets="web,browser",
            max_turns=15,
            timeout=300,
        )

        if not response:
            return InvestigationResult(angle=angle, confidence=0.0)

        # Parse URLs from response
        urls = re.findall(r"https?://[^\s)\]]+", response)
        sources = urls[:10] if urls else []

        return InvestigationResult(
            angle=angle,
            raw=response,
            sources=sources,
            confidence=0.7 if len(response) > 200 else 0.4,
        )

    async def health_check(self) -> bool:
        """Check if Hermes CLI is available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.hermes_bin, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            return proc.returncode == 0
        except Exception:
            return False

    async def close(self):
        """No persistent connection to close."""
        pass
