"""Tool registry — discovers and manages OSINT tools."""

from __future__ import annotations

from typing import Optional

from ..core.models import FindingSource
from .base import OSINTTool


class ToolRegistry:
    """Manages available OSINT tools and maps categories to tools."""

    def __init__(self):
        self._tools: dict[str, OSINTTool] = {}
        self._by_category: dict[FindingSource, list[OSINTTool]] = {s: [] for s in FindingSource}

    def register(self, tool: OSINTTool) -> None:
        """Register a tool instance."""
        self._tools[tool.name] = tool
        self._by_category[tool.category].append(tool)

    def get(self, name: str) -> Optional[OSINTTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def get_for_category(self, category: FindingSource) -> list[OSINTTool]:
        """Get all tools for a given category."""
        return self._by_category.get(category, [])

    def list_all(self) -> list[OSINTTool]:
        """Return all registered tools."""
        return list(self._tools.values())

    def list_categories(self) -> list[dict]:
        """Return categories with tool counts and descriptions."""
        return [
            {
                "category": cat.value,
                "tool_count": len(tools),
                "tools": [t.name for t in tools],
            }
            for cat, tools in self._by_category.items()
            if tools
        ]

    @property
    def tool_count(self) -> int:
        return len(self._tools)

    def __repr__(self) -> str:
        return f"<ToolRegistry {self.tool_count} tools>"


# Singleton registry for the application
registry = ToolRegistry()
