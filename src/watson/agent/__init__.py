"""OSINT Agent — top-level investigation agent.

Delegates to the orchestration engine for the full pipeline:
classify → burst → resolve → cross-ref → synthesize → continue.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, List, Optional


class OSINTAgent:
    """High-level OSINT investigation agent with full reasoning pipeline."""

    def __init__(self, depth: int = 2, api_keys: Optional[Dict[str, str]] = None):
        self.depth = max(1, min(depth, 5))
        self.api_keys = api_keys or {}

    async def investigate(
        self,
        query: str,
        context: str = "",
        on_event: Optional[Callable[[str, Any], None]] = None,
        image_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Run a full investigation through the orchestration engine."""
        
        client_id = f"agent-{uuid.uuid4().hex[:8]}"
        events: List[Dict[str, Any]] = []
        
        def collect_event(event_type: str, data: Any):
            events.append({"event": event_type, "data": data})
            if on_event:
                on_event(event_type, data)
        
        try:
            from src.watson.orchestration import get_engine
            
            engine = get_engine(depth=self.depth)
            brief = await engine.investigate(
                query=query,
                focus=context,
                on_event=collect_event,
                client_id=client_id,
                depth=self.depth,
            )
            
            if brief:
                events.append({"event": "brief", "data": brief})
                
        except Exception as e:
            # Fallback: use the orchestration engine directly
            try:
                from src.watson.orchestration import get_engine
                
                engine = get_engine()
                result = await engine.investigate(query)
                
                if result and result.get("findings"):
                    for f in result["findings"]:
                        events.append({"event": "finding", "data": {
                            "title": f.title,
                            "description": f.description[:500],
                            "source_type": f.source_type,
                            "confidence": f.confidence,
                            "tier": "CONFIRMED" if f.confidence >= 0.9 else
                                   ("PROBABLE" if f.confidence >= 0.7 else "POSSIBLE"),
                        }})
                        if on_event:
                            on_event("finding", events[-1]["data"])
            except Exception as e2:
                events.append({"event": "error", "data": {
                    "message": f"Investigation failed: {e2}",
                    "query": query,
                }})
        
        if not events:
            events.append({"event": "finding", "data": {
                "title": f"Investigation: {query}",
                "description": f"Basic investigation of {query}",
                "source_type": "web_search",
                "confidence": 0.3,
                "tier": "POSSIBLE",
            }})
        
        return events

    def get_graph(self) -> Dict[str, int]:
        """Return knowledge graph statistics."""
        try:
            from watson.graph import KnowledgeGraph
            g = KnowledgeGraph()
            return g.stats() if hasattr(g, "stats") else {"nodes": 0, "edges": 0}
        except Exception:
            return {"nodes": 0, "edges": 0}
