"""Search — full-text search across investigations.

Delegates to watson.memory for SQLite FTS5 search.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class SearchInterface:
    """Unified search across investigations and findings."""

    def __init__(self):
        self._memory = None

    @property
    def memory(self):
        if self._memory is None:
            try:
                from watson.memory import memory as mem
                self._memory = mem
            except ImportError:
                self._memory = None
        return self._memory

    def search(
        self,
        query: str,
        limit: int = 20,
        agent_filter: str = "",
        tier_filter: str = "",
    ) -> List[Dict[str, Any]]:
        """Full-text search across findings.

        Args:
            query: Search query.
            limit: Max results.
            agent_filter: Filter by agent role (not currently implemented beyond pass-through).
            tier_filter: Filter by evidence tier.

        Returns:
            List of result dicts.
        """
        results: List[Dict[str, Any]] = []

        if self.memory and hasattr(self.memory, "search"):
            try:
                raw = self.memory.search(query, limit=limit)
                for r in raw:
                    result = dict(r) if isinstance(r, dict) else {"title": str(r)}
                    if tier_filter and result.get("tier", "").lower() != tier_filter.lower():
                        continue
                    results.append(result)
                return results
            except Exception:
                pass

        # Fallback: return empty results
        return results

    def search_investigations(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search investigation-level metadata."""
        if self.memory and hasattr(self.memory, "list_recent"):
            try:
                all_inv = self.memory.list_recent(limit=100)
                matched = []
                q = query.lower()
                for inv in all_inv:
                    inv_q = (inv.get("query", "") or "").lower()
                    if q in inv_q or q in str(inv).lower():
                        matched.append(dict(inv) if isinstance(inv, dict) else {"id": str(inv)})
                    if len(matched) >= limit:
                        break
                return matched
            except Exception:
                pass
        return []

    def get_stats(self) -> Dict[str, Any]:
        """Get search index statistics."""
        try:
            if self.memory and hasattr(self.memory, "stats"):
                stats = self.memory.stats()
                return {
                    "total_indexed": stats.get("investigations", 0),
                    "entities": stats.get("entities", 0),
                    "findings": stats.get("findings", 0),
                }
        except Exception:
            pass
        return {"total_indexed": 0, "entities": 0, "findings": 0}


# Singleton
_search: Optional[SearchInterface] = None


def get_search() -> SearchInterface:
    global _search
    if _search is None:
        _search = SearchInterface()
    return _search
