"""LLM Verification Layer — second-pass validation to filter false positives.

After Phase 6 synthesis, each finding is re-examined by the LLM with a strict
verification prompt. The LLM checks:
  1. Does the source URL actually support the finding?
  2. Is the tier (CONFIRMED/PROBABLE/POSSIBLE) appropriate?
  3. Is anything hallucinated (fake entities, fabricated URLs, impossible claims)?
  4. Should the finding be downgraded or dropped?

Output: adjusted tier + verification_notes for each finding.

Thresholds:
  - Drop findings where verification_confidence < 30
  - Downgrade findings where LLM flags overconfidence
  - Keep findings that pass verification unchanged
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger("watson.verify")

# ── Verification prompt ───────────────────────────────────────

_VERIFY_SYSTEM = """You are a strict OSINT quality-assurance auditor. Your job is to validate
intelligence findings and catch false positives, hallucinations, and overconfident claims.

For each finding, check:
1. Does the source URL actually exist and support the claim? If the URL looks fabricated
   (random-looking domain, 404 patterns, impossible paths), flag it.
2. Is the confidence tier appropriate? CONFIRMED needs multi-source corroboration.
   PROBABLE needs a credible source. POSSIBLE is for weak signals.
3. Are there any hallucinated elements? Invented person names, fake organizations,
   impossible technical details, fabricated numbers/SAR IDs.
4. Is the finding logically coherent? Does the description actually match the title?

Respond with ONLY a JSON object. No markdown, no explanation outside the JSON."""

_VERIFY_PROMPT = """Review these OSINT findings for quality. Return a JSON dict with:
- "verifications": list of { "finding_id": str, "pass": bool, "adjusted_tier": str,
  "verification_confidence": int (0-100), "issues": [str], "notes": str }

Findings to verify:
{findings_json}

Rules:
- CONFIRMED tier requires: real source URL + specific verifiable claim + no hallucination risk
- PROBABLE tier requires: credible source URL + plausible claim
- POSSIBLE tier: weak signal, correlation, or unverified mention
- UNLIKELY/UNVERIFIED: should be dropped (pass=false)
- If source URL doesn't look real, flag and downgrade
- If finding contains invented names/numbers, drop it
- If description is generic/vague, downgrade to POSSIBLE
- If finding is about a different entity than the target, flag it

Return ONLY valid JSON."""


# ── Verification engine ───────────────────────────────────────

class FindingVerifier:
    """Second-pass LLM verification for OSINT findings."""

    def __init__(self, call_llm=None):
        """call_llm: async function (prompt, timeout, max_tokens) → str | None."""
        self._call_llm = call_llm

    async def verify(
        self,
        findings: list[Any],
        query: str = "",
        batch_size: int = 15,
    ) -> list[dict]:
        """Verify findings in batches. Returns list of verification results."""
        if not findings or not self._call_llm:
            return []

        results: list[dict] = []

        # Batch findings to avoid token overflow
        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            batch_results = await self._verify_batch(batch, query)
            results.extend(batch_results)

        return results

    async def _verify_batch(self, findings: list[Any], query: str) -> list[dict]:
        """Verify a batch of findings."""
        if not self._call_llm:
            return []
        # Serialize findings to compact JSON
        findings_data = []
        for f in findings:
            fid = getattr(f, "id", str(hash(f)))
            findings_data.append({
                "id": fid,
                "title": getattr(f, "title", "")[:200],
                "description": getattr(f, "description", "")[:300],
                "tier": getattr(f, "tier", "UNVERIFIED"),
                "source_url": getattr(f, "source_url", "")[:200],
                "source_type": getattr(f, "source_type", "osint"),
                "confidence": getattr(f, "confidence", 0.5),
            })

        prompt = _VERIFY_PROMPT.format(
            findings_json=json.dumps(findings_data, indent=2)
        )

        try:
            raw = await self._call_llm(
                prompt,
                timeout=120,
                max_tokens=4096,
                system=_VERIFY_SYSTEM,
            )
            if not raw or not raw.strip():
                logger.warning("verify: LLM returned empty — skipping verification")
                return [{"finding_id": fd["id"], "pass": True, "verification_confidence": 50,
                         "adjusted_tier": fd["tier"], "issues": [], "notes": "Verification skipped (LLM unavailable)"}
                        for fd in findings_data]

            parsed = self._parse_response(raw)
            return self._merge_results(findings_data, parsed)

        except Exception as e:
            logger.warning("verify: batch failed: %s", e)
            return [{"finding_id": fd["id"], "pass": True, "verification_confidence": 50,
                     "adjusted_tier": fd["tier"], "issues": [],
                     "notes": f"Verification error: {e}"}
                    for fd in findings_data]

    def _parse_response(self, raw: str) -> dict:
        """Parse LLM verification response."""
        # Strip markdown fences
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)

        # Try JSON parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON object
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(0))
                except json.JSONDecodeError:
                    pass

        logger.warning("verify: could not parse response: %s", raw[:200])
        return {}

    def _merge_results(self, findings_data: list[dict], parsed: dict) -> list[dict]:
        """Merge parsed verifications with original finding data."""
        verifications = parsed.get("verifications", [])
        if not verifications:
            # No structured verifications — pass everything
            return [{"finding_id": fd["id"], "pass": True, "verification_confidence": 50,
                     "adjusted_tier": fd["tier"], "issues": [], "notes": "No verification data"}
                    for fd in findings_data]

        # Build lookup
        vmap: dict[str, dict] = {v.get("finding_id", ""): v for v in verifications}

        results = []
        for fd in findings_data:
            fid = fd["id"]
            v = vmap.get(fid, {})
            results.append({
                "finding_id": fid,
                "pass": v.get("pass", True),
                "verification_confidence": v.get("verification_confidence", 50),
                "adjusted_tier": v.get("adjusted_tier", fd["tier"]),
                "issues": v.get("issues", []),
                "notes": v.get("notes", ""),
            })
        return results

    # ── Apply verification results to findings ────────────────

    @staticmethod
    def apply(finding: Any, verification: dict) -> tuple[Any, bool]:
        """Apply verification to a finding.

        Returns (possibly_modified_finding, was_dropped).
        """
        if not verification:
            return finding, False

        vconf = verification.get("verification_confidence", 50)
        passed = verification.get("pass", True)
        issues = verification.get("issues", [])

        # Drop findings with very low verification confidence
        if vconf < 30:
            logger.info("verify: dropping finding %s (confidence=%d, issues=%s)",
                        getattr(finding, "id", "?"), vconf, issues)
            return finding, True

        # Downgrade tier if LLM suggests it
        adjusted = verification.get("adjusted_tier", "")
        if adjusted and hasattr(finding, "tier"):
            tier_order = ["CONFIRMED", "PROBABLE", "POSSIBLE", "UNLIKELY", "UNVERIFIED"]
            old_idx = tier_order.index(finding.tier) if finding.tier in tier_order else 4
            new_idx = tier_order.index(adjusted) if adjusted in tier_order else old_idx
            if new_idx > old_idx:
                logger.info("verify: downgrading finding %s %s→%s",
                            getattr(finding, "id", "?"), finding.tier, adjusted)
                finding.tier = adjusted

        # Attach verification notes
        notes = verification.get("notes", "")
        if notes and hasattr(finding, "description"):
            finding.description = f"[Verified: {notes}] {finding.description}"

        if issues and hasattr(finding, "description"):
            finding.description = f"[⚠ Issues: {'; '.join(issues[:3])}] {finding.description}"

        return finding, False


# ── Factory ───────────────────────────────────────────────────

def create_verifier(provider: str | None = None) -> FindingVerifier | None:
    """Create a verifier using the configured LLM provider.

    Returns None if no LLM is available.
    """
    try:
        from watson.orchestration.llm_config import call_llm

        async def _call(prompt, timeout=120, max_tokens=2000, system=""):
            return await call_llm(prompt, timeout=timeout, max_tokens=max_tokens, system=system)

        return FindingVerifier(call_llm=_call)
    except ImportError:
        logger.warning("verify: could not import llm_config — verification disabled")
        return None
