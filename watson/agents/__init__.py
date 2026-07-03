"""Agent adapters for Watson — pluggable backends."""

from .base import AgentAdapter, BrowseResult, InvestigationResult, SearchResult, TerminalResult, VisionResult
from .hermes import HermesCLIAdapter
from .hermes_mcp import HermesMCPAdapter

# Legacy alias — kept for backward compatibility
HermesAdapter = HermesCLIAdapter

__all__ = [
    "AgentAdapter",
    "HermesAdapter",         # Legacy alias
    "HermesCLIAdapter",      # CLI subprocess backend
    "HermesMCPAdapter",      # MCP protocol backend
    "SearchResult",
    "BrowseResult",
    "VisionResult",
    "TerminalResult",
    "InvestigationResult",
]
