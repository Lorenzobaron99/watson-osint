"""LLM configuration — call any OpenAI-compatible API."""

from __future__ import annotations
import os, json, logging, re

logger = logging.getLogger("watson.llm")

# ── Provider config ──────────────────────────────────────────

_PROVIDER_CONFIG = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "api_key_env": "DEEPSEEK_API_KEY",
        "default_model": os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro"),
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
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "default_model": "deepseek/deepseek-chat",
    },
}

# ── Main call function ───────────────────────────────────────

def _auto_detect_provider() -> str:
    """Auto-detect which LLM provider has an API key configured.
    
    Checks environment variables and the Watson key store.
    Returns the first available provider name, or '' if none found.
    """
    # Check env vars for each provider
    for provider_name, cfg in _PROVIDER_CONFIG.items():
        if os.environ.get(cfg["api_key_env"], ""):
            return provider_name
    
    # Check the Watson UI key store
    try:
        from watson.api_keys import list_keys
        stored = list_keys()
        for entry in stored:
            if entry.get("configured") and entry.get("slug") in _PROVIDER_CONFIG:
                return entry["slug"]
    except (ImportError, Exception):
        pass
    
    return ""

async def call_llm(
    prompt: str,
    timeout: int = 60,
    max_tokens: int = 2048,
    model: str | None = None,
    provider: str | None = None,
    system: str = "",
) -> str | None:
    """Call an LLM via OpenAI-compatible API. Returns text or None."""
    
    # Resolve provider: explicit > env var > auto-detect
    if not provider:
        provider = os.environ.get("WATSON_LLM_PROVIDER", "")
    if not provider:
        provider = _auto_detect_provider()
    if not provider:
        logger.warning(
            "llm: no LLM provider configured. Set one of: "
            "DEEPSEEK_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, "
            "OPENROUTER_API_KEY, or WATSON_LLM_PROVIDER. "
            "See .env.example for setup instructions."
        )
        return None
    
    cfg = _PROVIDER_CONFIG.get(provider)
    if not cfg:
        logger.warning("llm: unknown provider '%s' — known: %s", provider, list(_PROVIDER_CONFIG.keys()))
        return None
    
    api_key = os.environ.get(cfg["api_key_env"], "")
    
    # Fallback: check the Watson key store (user-configured via UI)
    if not api_key:
        try:
            from watson.api_keys import get_key
            api_key = get_key(provider) or ""
        except ImportError:
            pass
    
    if not api_key:
        logger.warning("llm: no API key for provider %s (env: %s)", provider, cfg["api_key_env"])
        return None
    
    if not model:
        model = cfg["default_model"]
    
    url = f"{cfg['base_url']}/chat/completions"
    
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    
    payload = {
        "model": model,
        "messages": messages,
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
                msg = data["choices"][0]["message"]
                content = msg.get("content", "") or ""
                # Reasoning models (deepseek-v4-pro, R1) put thinking in reasoning_content
                # and the final answer in content. If content is empty (all tokens spent
                # on reasoning), fall back to reasoning_content.
                if not content.strip():
                    reasoning = msg.get("reasoning_content", "") or ""
                    if reasoning.strip():
                        logger.debug("llm: using reasoning_content (content was empty)")
                        return reasoning
                    # Both empty — log response for debugging
                    logger.warning("llm: empty content AND empty reasoning_content — finish_reason=%s model=%s",
                                   data["choices"][0].get("finish_reason", "?"), model)
                    # Check if there's any text anywhere in the response
                    all_keys = list(msg.keys())
                    logger.debug("llm: message keys: %s", all_keys)
                    for k in all_keys:
                        v = msg.get(k, "")
                        if isinstance(v, str) and v.strip():
                            logger.info("llm: found text in key '%s', using that", k)
                            return v
                return content
            logger.warning("llm: HTTP %d from %s — body: %s", resp.status_code, provider,
                           resp.text[:300] if resp.text else "(empty)")
            return None
    except Exception as e:
        logger.warning("llm: request failed: %s", e)
        return None
