"""LLM configuration — call any OpenAI-compatible API with automatic provider fallback."""

from __future__ import annotations
import os, json, logging, re, time as _time

logger = logging.getLogger("watson.llm")

# ── Provider config ──────────────────────────────────────────

# Env-var overrides for default models — users can set OPENAI_MODEL=gpt-4o-mini, etc.
# Falls back to the hardcoded sensible default if env var is not set.
_MODEL_ENV_VARS = {
    "deepseek":   "DEEPSEEK_MODEL",
    "openai":     "OPENAI_MODEL",
    "anthropic":  "ANTHROPIC_MODEL",
    "hermes":     "HERMES_MODEL",
    "openrouter": "OPENROUTER_MODEL",
}


def _default_model(provider: str, fallback: str) -> str:
    """Return the default model for a provider, respecting env var, persisted config, then fallback.
    
    Priority: env var > persisted config (~/.watson/llm_config.json) > fallback.
    """
    # 1. Check per-provider env var (DEEPSEEK_MODEL, OPENAI_MODEL, etc.)
    env_var = _MODEL_ENV_VARS.get(provider)
    if env_var:
        env_val = os.environ.get(env_var, "")
        if env_val:
            return env_val
    
    # 2. Check persisted config from UI
    try:
        from pathlib import Path
        config_path = Path.home() / ".watson" / "llm_config.json"
        if config_path.exists():
            config = json.loads(config_path.read_text())
            if config.get("provider") == provider and config.get("model"):
                return config["model"]
    except Exception:
        pass
    
    # 3. Fall back to hardcoded default
    return fallback


_PROVIDER_CONFIG = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "api_key_env": "DEEPSEEK_API_KEY",
        "default_model": _default_model("deepseek", "deepseek-chat"),
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "default_model": _default_model("openai", "gpt-4o"),
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "api_key_env": "ANTHROPIC_API_KEY",
        "default_model": _default_model("anthropic", "claude-sonnet-4-20250514"),
    },
    "hermes": {
        "base_url": os.environ.get("HERMES_API_BASE", "http://localhost:8080/v1"),
        "api_key_env": "HERMES_API_KEY",
        "default_model": _default_model("hermes", "hermes"),
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "default_model": _default_model("openrouter", "deepseek/deepseek-chat"),
    },
}

# ── Provider exhaustion tracking ─────────────────────────────

_EXHAUSTED_PROVIDERS: dict[str, float] = {}
_EXHAUST_COOLDOWN = 300  # seconds before retrying a dead provider


def _provider_available(provider: str) -> bool:
    """Check if a provider is currently available (not rate-limited/exhausted)."""
    if provider not in _EXHAUSTED_PROVIDERS:
        return True
    if _time.time() - _EXHAUSTED_PROVIDERS[provider] > _EXHAUST_COOLDOWN:
        del _EXHAUSTED_PROVIDERS[provider]
        return True
    return False


def _mark_provider_exhausted(provider: str):
    """Mark a provider as temporarily exhausted (rate-limited or no credits)."""
    _EXHAUSTED_PROVIDERS[provider] = _time.time()
    logger.warning("llm: provider '%s' marked exhausted for %ds", provider, _EXHAUST_COOLDOWN)


def _get_api_key(provider: str) -> str:
    """Get API key for a provider from env or Watson key store."""
    cfg = _PROVIDER_CONFIG.get(provider, {})
    api_key = os.environ.get(cfg.get("api_key_env", ""), "")
    if not api_key:
        try:
            from watson.api_keys import get_key
            api_key = get_key(provider) or ""
        except ImportError:
            pass
    return api_key


# ── Auto-detect ──────────────────────────────────────────────

def _auto_detect_provider() -> str:
    """Auto-detect which LLM provider has an API key configured.
    
    Checks environment variables and the Watson key store.
    Returns the first available provider name, or '' if none found.
    """
    for provider_name, cfg in _PROVIDER_CONFIG.items():
        if os.environ.get(cfg["api_key_env"], ""):
            return provider_name
    
    try:
        from watson.api_keys import list_keys
        stored = list_keys()
        for entry in stored:
            if entry.get("configured") and entry.get("slug") in _PROVIDER_CONFIG:
                return entry["slug"]
    except (ImportError, Exception):
        pass
    
    return ""


def _get_fallback_providers(current: str) -> list[str]:
    """Get ordered list of fallback providers with valid API keys."""
    priority = ["deepseek", "openrouter", "openai", "anthropic", "hermes"]
    fallbacks = []
    for p in priority:
        if p != current and p in _PROVIDER_CONFIG and _provider_available(p):
            if _get_api_key(p):
                fallbacks.append(p)
    return fallbacks


# ── Main call function ───────────────────────────────────────

async def call_llm(
    prompt: str,
    timeout: int = 60,
    max_tokens: int = 2048,
    model: str | None = None,
    provider: str | None = None,
    system: str = "",
    fallback: bool = True,
) -> str | None:
    """Call an LLM via OpenAI-compatible API. Returns text or None.

    With fallback=True (default), automatically tries alternative providers if
    the primary fails with 402 (no credits) or 429 (rate limited).
    """
    if fallback:
        return await call_llm_with_fallback(
            prompt=prompt, timeout=timeout, max_tokens=max_tokens,
            model=model, provider=provider, system=system,
        )
    
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
    
    api_key = _get_api_key(provider)
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
                if not content.strip():
                    reasoning = msg.get("reasoning_content", "") or ""
                    if reasoning.strip():
                        logger.debug("llm: using reasoning_content (content was empty)")
                        return reasoning
                    logger.warning("llm: empty content AND empty reasoning_content — finish_reason=%s model=%s",
                                   data["choices"][0].get("finish_reason", "?"), model)
                    all_keys = list(msg.keys())
                    logger.debug("llm: message keys: %s", all_keys)
                    for k in all_keys:
                        v = msg.get(k, "")
                        if isinstance(v, str) and v.strip():
                            logger.info("llm: found text in key '%s', using that", k)
                            return v
                return content
            
            # Credit exhaustion or rate limit — mark for fallback
            if resp.status_code in (402, 429):
                logger.warning("llm: %s returned %d — marking exhausted: %s", provider, resp.status_code,
                               resp.text[:200] if resp.text else "(empty)")
                _mark_provider_exhausted(provider)
            else:
                logger.warning("llm: HTTP %d from %s — body: %s", resp.status_code, provider,
                               resp.text[:300] if resp.text else "(empty)")
            return None
    except Exception as e:
        logger.warning("llm: request failed for %s: %s", provider, e)
        return None


# ── Fallback-aware wrapper ───────────────────────────────────

async def call_llm_with_fallback(
    prompt: str,
    timeout: int = 60,
    max_tokens: int = 2048,
    model: str | None = None,
    provider: str | None = None,
    system: str = "",
) -> str | None:
    """Call LLM with automatic provider fallback.

    Tries the primary provider first, then falls back through available providers
    if the primary fails with 402 (no credits), 429 (rate limited), 5xx, or timeout.
    Each exhausted provider is skipped for 5 minutes.
    """
    if not provider:
        provider = os.environ.get("WATSON_LLM_PROVIDER", "")
    if not provider:
        provider = _auto_detect_provider()
    
    if not provider:
        logger.warning("llm_fallback: no provider configured")
        return None
    
    tried: list[str] = []
    providers_to_try = [provider] + _get_fallback_providers(provider)
    
    for p in providers_to_try:
        if p in tried:
            continue
        if not _provider_available(p):
            logger.debug("llm_fallback: skipping exhausted provider '%s'", p)
            continue
        
        tried.append(p)
        logger.info("llm_fallback: trying provider '%s'%s", p,
                     " (fallback)" if p != provider else "")
        
        result = await call_llm(
            prompt=prompt, timeout=timeout, max_tokens=max_tokens,
            model=model, provider=p, system=system, fallback=False,
        )
        
        if result is not None:
            if p != provider:
                logger.info("llm_fallback: succeeded with fallback provider '%s'", p)
            return result
    
    logger.warning("llm_fallback: all %d providers failed: %s", len(tried), tried)
    return None
