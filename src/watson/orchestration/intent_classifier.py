"""Intent classifier — determines if a message is an investigation or chat."""

from __future__ import annotations

from typing import Callable, Coroutine, Tuple


async def classify_intent(
    msg: str,
    call_llm: Callable[..., Coroutine],
) -> Tuple[str, float, str]:
    """Classify a message as 'investigate' or 'chat' using LLM fallback.

    Args:
        msg: The user message to classify.
        call_llm: Async function to call the LLM.

    Returns:
        Tuple of (intent: str, confidence: float, reason: str)
    """
    prompt = (
        "Classify this message as 'investigate' or 'chat'.\n"
        "'investigate' means the user wants to investigate a person, domain, company, "
        "crypto address, IP, email, or similar target.\n"
        "'chat' means it's a conversational question about OSINT, methodology, or general knowledge.\n\n"
        f"Message: \"{msg[:500]}\"\n\n"
        "Respond with only one word: investigate or chat"
    )

    try:
        result = await call_llm(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=10,
            temperature=0.0,
        )
        answer = result.strip().lower()
        if "investigate" in answer:
            return "investigate", 0.65, "llm_classifier"
        elif "chat" in answer:
            return "chat", 0.65, "llm_classifier"
        else:
            # Default: ambiguous → treat as chat for safety
            return "chat", 0.5, "llm_ambiguous"
    except Exception:
        return "chat", 0.5, "llm_unavailable"
