"""Watson Orchestration — the intelligence pipeline that makes Watson more than a search engine.

Layers on top of the 7-phase sequential engine with:
  classify → surface → pivot → deep → dark → analyze → report
"""

from __future__ import annotations
from .engine import OrchestrationEngine, get_engine
from .resolution import (
    build_intelligence_picture,
    resolve_entities,
    propagate_confidence,
    cross_reference_advanced,
)

__all__ = [
    "OrchestrationEngine",
    "get_engine",
    "build_intelligence_picture",
    "resolve_entities",
    "propagate_confidence",
    "cross_reference_advanced",
]
