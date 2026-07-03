"""Agent adapters for Watson — pluggable backends."""

from .base import AgentAdapter, BrowseResult, InvestigationResult, SearchResult, TerminalResult, VisionResult
from .hermes import HermesAdapter

__all__ = [
    "AgentAdapter",
    "HermesAdapter",
    "SearchResult",
    "BrowseResult",
    "VisionResult",
    "TerminalResult",
    "InvestigationResult",
]
