"""Conversation Agent — chat interface with investigation capabilities."""

from __future__ import annotations
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger("watson.conversation")


class ConversationAgent:
    """Chat agent that can investigate and converse."""
    
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._history: list[dict] = []
    
    async def chat(
        self,
        message: str,
        findings: list | None = None,
        history: list | None = None,
        on_event: Optional[Callable[[str, Any], None]] = None,
    ) -> dict:
        """Process a chat message. Returns response dict with events."""
        
        events = []
        
        # Determine if this is an investigation request
        investigation_keywords = [
            "investigate", "look up", "search", "find", "who is",
            "what is", "research", "dig into", "analyze", "check",
        ]
        
        msg_lower = message.lower().strip()
        is_investigation = any(kw in msg_lower for kw in investigation_keywords)
        
        if is_investigation:
            # Extract the target from the message
            target = message
            for kw in investigation_keywords:
                idx = msg_lower.find(kw)
                if idx >= 0:
                    target = message[idx + len(kw):].strip().rstrip(".!?")
                    break
            
            if target:
                try:
                    from .agent import OSINTAgent
                    agent = OSINTAgent(depth=2)
                    inv_events = await agent.investigate(
                        query=target,
                        on_event=on_event,
                    )
                    events.extend(inv_events)
                except Exception as e:
                    logger.warning("conversation_investigation_failed: %s", e)
                    events.append({
                        "event": "message",
                        "data": {"content": f"I tried to investigate '{target}' but encountered an error: {e}"},
                    })
        
        if not events:
            events.append({
                "event": "message",
                "data": {"content": f"I can help you investigate. Try asking me to investigate a person, company, or domain."},
            })
        
        return {"events": events, "investigation_triggered": is_investigation}
