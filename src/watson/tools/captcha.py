"""CAPTCHA solver — autonomous CAPTCHA solving using vision LLM.

Architecture adapted from i-am-a-bot (AashiqRamachandran, MIT licensed):
  Agent 1: Is this a CAPTCHA? → boolean
  Agent 2: What type? → text / math / rotation / puzzle / select
  Agent 3: Solve it → answer string

Uses the OpenAI-compatible vision API. Falls back to base64-encoded images
sent as data URLs when the model supports vision.
"""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from typing import Optional

import httpx

from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource


# Provider-agnostic vision prompts (adapted from i-am-a-bot)
AGENT_1_PROMPT = """Analyze this image. Is it a CAPTCHA or human verification challenge?
Respond with ONLY valid JSON: {"is_captcha": true} or {"is_captcha": false}
Do not include markdown, backticks, or any text outside the JSON."""

AGENT_2_PROMPT = """Analyze this CAPTCHA image. What type is it?
Possible types:
1 = text (read and enter displayed characters)
2 = math (solve the equation)
3 = rotation (rotate image to correct angle)
4 = puzzle (solve a puzzle)
5 = select (click matching images)
6 = other

Respond with ONLY valid JSON: {"captcha_type": <number 1-6>}"""

AGENT_3_TEXT_PROMPT = """Read the text in this CAPTCHA image. Return ONLY the characters shown.
Respond with ONLY valid JSON: {"answer": "the text here"}
Do not include spaces if there are none in the image."""

AGENT_3_MATH_PROMPT = """Read the math equation in this CAPTCHA image.
Return the equation as a Python-evaluatable expression.
Respond with ONLY valid JSON: {"equation": "the equation here"}"""


class CaptchaSolver:
    """Solves CAPTCHAs using a vision-capable LLM."""

    def __init__(
        self,
        api_base: str | None = None,
        api_key: str | None = None,
        model: str = "deepseek-v4-pro",
    ):
        self.api_base = api_base or os.environ.get(
            "OPENAI_API_BASE", "https://api.deepseek.com"
        )
        self.api_key = api_key or os.environ.get(
            "DEEPSEEK_API_KEY", ""
        ) or os.environ.get("OPENAI_API_KEY", "")

        # Try loading from Hermes .env if key is still empty
        if not self.api_key:
            env_path = os.path.expanduser("~/.hermes/.env")
            if os.path.exists(env_path):
                with open(env_path) as f:
                    for line in f:
                        if "=" in line and not line.startswith("#"):
                            k, v = line.strip().split("=", 1)
                            k = k.strip()
                            v = v.strip().strip('"').strip("'")
                            if k in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY") and v and v != "***":
                                self.api_key = v
                                break

        self.model = model

    def _encode_image(self, image_path: str) -> str:
        """Encode image as base64 data URL."""
        with open(image_path, "rb") as f:
            data = base64.b64encode(f.read()).decode("utf-8")
        ext = Path(image_path).suffix.lower().lstrip(".")
        mime = f"image/{ext}" if ext in ("png", "jpeg", "jpg", "gif", "webp") else "image/png"
        return f"data:{mime};base64,{data}"

    def _call_vision(self, prompt: str, image_path: str) -> str:
        """Call the vision API with an image and prompt."""
        image_url = self._encode_image(image_path)

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": image_url}},
                    ],
                }
            ],
            "max_tokens": 200,
            "temperature": 0.1,
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        try:
            with httpx.Client(timeout=30) as client:
                resp = client.post(
                    f"{self.api_base}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            raise RuntimeError(f"Vision API call failed: {e}")

    def _parse_json(self, text: str) -> dict:
        """Extract JSON from LLM response, handling markdown and noise."""
        # Remove markdown code blocks
        text = re.sub(r"```(?:json)?\s*", "", text)
        text = text.strip().strip("`")

        # Try to find JSON object
        match = re.search(r"\{[^{}]*\}", text)
        if match:
            return json.loads(match.group(0))

        raise ValueError(f"Could not parse JSON from: {text[:100]}")

    def solve(self, image_path: str) -> dict:
        """Solve a CAPTCHA from an image file.

        Returns:
            {"success": True, "answer": "...", "captcha_type": "text"}
            {"success": False, "error": "..."}
        """
        try:
            # Step 1: Is this a CAPTCHA?
            resp1 = self._call_vision(AGENT_1_PROMPT, image_path)
            result1 = self._parse_json(resp1)

            if not result1.get("is_captcha"):
                return {"success": False, "error": "Image does not appear to be a CAPTCHA"}

            # Step 2: What type?
            resp2 = self._call_vision(AGENT_2_PROMPT, image_path)
            result2 = self._parse_json(resp2)
            captcha_type = int(result2.get("captcha_type", 6))

            type_names = {1: "text", 2: "math", 3: "rotation", 4: "puzzle", 5: "select", 6: "other"}

            # Step 3: Solve based on type
            if captcha_type == 1:  # Text
                resp3 = self._call_vision(AGENT_3_TEXT_PROMPT, image_path)
                result3 = self._parse_json(resp3)
                return {
                    "success": True,
                    "answer": result3.get("answer", ""),
                    "captcha_type": "text",
                }

            elif captcha_type == 2:  # Math
                resp3 = self._call_vision(AGENT_3_MATH_PROMPT, image_path)
                result3 = self._parse_json(resp3)
                equation = result3.get("equation", "0")
                try:
                    solved = eval(equation, {"__builtins__": {}})
                except Exception:
                    solved = equation
                return {
                    "success": True,
                    "answer": str(solved),
                    "captcha_type": "math",
                    "equation": equation,
                }

            else:
                return {
                    "success": False,
                    "error": f"CAPTCHA type '{type_names.get(captcha_type, str(captcha_type))}' not yet supported",
                }

        except Exception as e:
            return {"success": False, "error": str(e)}


class CaptchaTool(OSINTTool):
    """Autonomous CAPTCHA solver for OSINT investigations."""

    category = FindingSource.IMAGE_VIDEO
    name = "captcha-solver"
    description = "Autonomous CAPTCHA solver using vision LLM — bypasses verification on OSINT data sources"
    free_tier_available = True
    rate_limit_rps = 0.5

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Check if the query references a CAPTCHA image
        image_path = self._extract_image_path(query)
        if not image_path:
            return findings

        if not os.path.exists(image_path):
            findings.append(
                self._make_finding(
                    title="CAPTCHA solver: image not found",
                    description=f"Image file not found: {image_path}",
                    confidence=0.0,
                )
            )
            return findings

        # Solve the CAPTCHA
        solver = CaptchaSolver()
        result = solver.solve(image_path)

        if result["success"]:
            findings.append(
                self._make_finding(
                    title=f"✅ CAPTCHA solved ({result['captcha_type']})",
                    description=f"Answer: **{result['answer']}**",
                    confidence=0.9,
                    captcha_type=result["captcha_type"],
                    answer=result["answer"],
                )
            )
        else:
            findings.append(
                self._make_finding(
                    title=f"❌ CAPTCHA solve failed",
                    description=result.get("error", "Unknown error"),
                    confidence=0.0,
                )
            )

        return findings

    def _extract_image_path(self, text: str) -> Optional[str]:
        """Extract an image file path from the query."""
        import re

        # Check for file path patterns
        patterns = [
            r"(?:solve|captcha|image|picture|photo)\s+(?:this|the)?\s*:?\s*([^\s]+\.(?:png|jpg|jpeg|gif|webp))",
            r"([/~].+\.(?:png|jpg|jpeg|gif|webp))",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                path = match.group(1)
                # Expand ~
                if path.startswith("~"):
                    path = os.path.expanduser(path)
                return path

        return None


# Register
captcha_tool = CaptchaTool()
registry.register(captcha_tool)
