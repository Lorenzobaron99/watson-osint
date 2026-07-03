"""LLM configuration — call any OpenAI-compatible API."""

from __future__ import annotations
import os, json, logging, re

logger = logging.getLogger("watson.llm")

# ── Provider config ──────────────────────────────────────────

_PROVIDER_CONFIG = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "api_key_env": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "default_model": "gpt-4o",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "api_key_env": "ANTHROPIC_API_KEY",
        "default_model": "claude-sonnet-4-20250514",
    },
    "hermes": {
        "base_url": os.environ.get("HERMES_API_BASE", "http://localhost:8080/v1"),
        "api_key_env": "HERMES_API_KEY",
        "default_model": "hermes",
    },
}

# ── Main call function ───────────────────────────────────────

async def call_llm(
    prompt: str,
    timeout: int = 60,
    max_tokens: int = 2048,
    model: str | None = None,
    provider: str | None = None,
) -> str | None:
    """Call an LLM via OpenAI-compatible API. Returns text or None."""
    
    # Resolve provider — check env, then config, then fallback
    if not provider:
        provider = os.environ.get("WATSON_LLM_PROVIDER", "deepseek")
    
    cfg = _PROVIDER_CONFIG.get(provider, _PROVIDER_CONFIG["deepseek"])
    api_key = os.environ.get(cfg["api_key_env"], "")
    
    if not api_key:
        logger.warning("llm: no API key for provider %s (env: %s)", provider, cfg["api_key_env"])
        return None
    
    if not model:
        model = cfg["default_model"]
    
    url = f"{cfg['base_url']}/chat/completions"
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    
    try:
        import httpx
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=15.0)) as client:
            resp = await client.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            logger.warning("llm: HTTP %d from %s", resp.status_code, provider)
            return None
    except Exception as e:
        logger.warning("llm: request failed: %s", e)
        return None
