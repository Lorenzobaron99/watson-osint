"""Cross-Referencer — LLM-powered correlation of investigation findings.

Replaces naive word-overlap with deep semantic analysis.
Works with dict findings — no model dependency.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CrossReference:
    title: str
    description: str
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    connection_type: str = "corroboration"


class CrossReferencer:
    """LLM-powered cross-referencing engine."""

    CROSS_REF_PROMPT = """You are a senior OSINT intelligence analyst reviewing findings from multiple sources.
Identify connections between findings that a human analyst would notice.

{findings_text}

Look for:
1. Corroboration: Two sources confirming the same fact
2. Contradiction: Two sources disagreeing
3. Pattern: A pattern emerging across multiple sources
4. Link: An entity/domain/person appearing in multiple unrelated findings
5. Gap: Something conspicuously missing

Return ONLY valid JSON array of connections:
[{{"title":"...","description":"...","sources":["source_a","source_b"],"connection_type":"corroboration|contradiction|pattern|link|gap","confidence":0.0-1.0,"evidence":["url"]}}]
If no connections exist, return []."""

    def __init__(self, api_key: str | None = None, model: str = "deepseek-chat"):
        self._api_key = api_key
        self._model = model
        if not self._api_key:
            for var in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
                self._api_key = os.environ.get(var, "")
                if self._api_key:
                    break
            if not self._api_key:
                env_path = os.path.expanduser("~/.hermes/.env")
                if os.path.exists(env_path):
                    with open(env_path) as f:
                        for line in f:
                            if "=" in line and not line.startswith("#"):
                                k, v = line.strip().split("=", 1)
                                if k.strip() in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
                                    self._api_key = v.strip().strip('"').strip("'")
                                    break

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def cross_reference(self, findings: list[dict], max_findings: int = 30) -> list[CrossReference]:
        if not findings or len(findings) < 2:
            return []
        if self.available:
            return self._llm_cross_reference(findings[:max_findings])
        return self._word_overlap(findings)

    def _llm_cross_reference(self, findings: list[dict]) -> list[CrossReference]:
        blocks = []
        for f in findings:
            src = f.get("source_type", f.get("source", "unknown"))
            blocks.append(
                f"[SOURCE: {src}]\n"
                f"TITLE: {f.get('title', '')}\n"
                f"DESC: {f.get('description', '')[:300]}\n"
            )
        prompt = self.CROSS_REF_PROMPT.format(findings_text="\n".join(blocks))

        try:
            raw = self._call_llm(prompt)
            if not raw:
                return self._word_overlap(findings)
            parsed = self._parse_json_array(raw)
            if not parsed:
                return self._word_overlap(findings)
            return [
                CrossReference(
                    title=item.get("title", ""),
                    description=item.get("description", ""),
                    sources=item.get("sources", []),
                    evidence=item.get("evidence", []),
                    confidence=float(item.get("confidence", 0.5)),
                    connection_type=item.get("connection_type", "link"),
                )
                for item in parsed
            ]
        except Exception:
            return self._word_overlap(findings)

    def _call_llm(self, prompt: str, timeout: int = 30) -> str | None:
        import concurrent.futures
        api_base = os.environ.get("DEEPSEEK_API_BASE", "https://api.deepseek.com/v1")

        def _call_sync():
            import urllib.request as ur
            body = json.dumps({
                "model": self._model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 1500,
            }).encode()
            req = ur.Request(
                f"{api_base}/chat/completions", data=body,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._api_key}"},
            )
            try:
                resp = ur.urlopen(req, timeout=timeout)
                return json.loads(resp.read())["choices"][0]["message"]["content"]
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(_call_sync).result(timeout=timeout + 5)

    def _parse_json_array(self, text: str) -> list[dict] | None:
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            match = re.search(r"\[.*\]", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        return None

    def _word_overlap(self, findings: list[dict]) -> list[CrossReference]:
        refs = []
        stopwords = {"the","a","an","is","was","are","were","be","been","in","on","at","to","for","of","and","or","not","this","that","with","from","by","as","it","its","found","search","result","error","failed","timeout"}
        by_source: dict[str, list[dict]] = {}
        for f in findings:
            src = f.get("source_type", f.get("source", "unknown"))
            by_source.setdefault(src, []).append(f)
        sources = list(by_source.keys())
        for i in range(len(sources)):
            for j in range(i + 1, len(sources)):
                for fa in by_source[sources[i]]:
                    for fb in by_source[sources[j]]:
                        wa = {w.lower() for w in fa.get("title","").split() if len(w) > 3 and w.lower() not in stopwords}
                        wb = {w.lower() for w in fb.get("title","").split() if len(w) > 3 and w.lower() not in stopwords}
                        overlap = wa & wb
                        meaningful = overlap - {"http","https","www","com","org"}
                        if len(meaningful) >= 1:
                            refs.append(CrossReference(
                                title=f"Link: {fa.get('title','')[:60]} ↔ {fb.get('title','')[:60]}",
                                description=f"Findings from {sources[i]} and {sources[j]} share: {', '.join(sorted(overlap))}",
                                sources=[sources[i], sources[j]],
                                evidence=fa.get("evidence",[])[:1] + fb.get("evidence",[])[:1],
                                confidence=min(fa.get("confidence",0.5), fb.get("confidence",0.5)),
                            ))
        seen = set()
        unique = [r for r in refs if not (r.title in seen or seen.add(r.title))]
        return unique[:15]
