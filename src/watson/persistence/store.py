"""Persistence store — SQLite-backed investigation storage.

Full CRUD for investigations and steps with stats.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import Investigation, InvestigationStatus, InvestigationStep, StepStatus


class InvestigationStore:
    """SQLite-backed store for investigations and steps."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = Path.home() / ".watson" / "investigations.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        import sqlite3
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    investigation_id TEXT PRIMARY KEY,
                    original_query TEXT NOT NULL,
                    target_type TEXT DEFAULT 'unknown',
                    target_value TEXT DEFAULT '',
                    status TEXT DEFAULT 'pending',
                    total_hops INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    confirmed_count INTEGER DEFAULT 0,
                    cross_references TEXT DEFAULT '[]',
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS investigation_steps (
                    step_id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    hop_number INTEGER DEFAULT 0,
                    agent TEXT DEFAULT '',
                    agent_role TEXT DEFAULT '',
                    query TEXT DEFAULT '',
                    angle TEXT DEFAULT '',
                    target_type TEXT DEFAULT '',
                    status TEXT DEFAULT 'pending',
                    findings_json TEXT DEFAULT '[]',
                    sources_json TEXT DEFAULT '[]',
                    created_at TEXT,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id)
                )
            """)

    # ── Investigation CRUD ────────────────────────────────────

    def create(self, query: str, target_type: str = "unknown") -> Investigation:
        """Create a new investigation."""
        inv = Investigation(
            original_query=query,
            target_type=target_type,
        )
        self._insert(inv)
        return inv

    def _insert(self, inv: Investigation):
        import sqlite3
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                INSERT INTO investigations
                (investigation_id, original_query, target_type, target_value, status,
                 total_hops, total_findings, confirmed_count, cross_references,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (inv.investigation_id, inv.original_query, inv.target_type,
                  inv.target_value, inv.status.value, inv.total_hops,
                  inv.total_findings, inv.confirmed_count, inv.cross_references,
                  inv.created_at, inv.updated_at))

    def get(self, investigation_id: str) -> Optional[Investigation]:
        """Retrieve an investigation by ID."""
        import sqlite3
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM investigations WHERE investigation_id = ?",
                (investigation_id,)
            ).fetchone()
            if not row:
                return None
            return Investigation.from_row(dict(row))

    def update(self, inv: Investigation) -> None:
        """Insert or update an investigation."""
        import sqlite3
        inv.updated_at = datetime.now(timezone.utc).isoformat()
        if not inv.created_at:
            inv.created_at = inv.updated_at
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO investigations
                (investigation_id, original_query, target_type, target_value, status,
                 total_hops, total_findings, confirmed_count, cross_references,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (inv.investigation_id, inv.original_query, inv.target_type,
                  inv.target_value, inv.status.value, inv.total_hops,
                  inv.total_findings, inv.confirmed_count, inv.cross_references,
                  inv.created_at, inv.updated_at))

    def list_recent(self, limit: int = 20) -> List[Investigation]:
        """List recent investigations, newest first."""
        import sqlite3
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM investigations ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [Investigation.from_row(dict(r)) for r in rows]

    def list_investigations(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent investigations as dicts (backward compat)."""
        return [inv.to_row() for inv in self.list_recent(limit)]

    def get_active(self) -> List[Investigation]:
        """Get investigations that are not completed/failed/cancelled."""
        import sqlite3
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM investigations WHERE status IN ('created', 'pending', 'running') ORDER BY created_at DESC"
            ).fetchall()
            return [Investigation.from_row(dict(r)) for r in rows]

    # ── Step CRUD ────────────────────────────────────────────

    def add_step(self, step: InvestigationStep) -> None:
        """Insert an investigation step."""
        import sqlite3
        if not step.created_at:
            step.created_at = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO investigation_steps
                (step_id, investigation_id, hop_number, agent, agent_role, query, angle,
                 target_type, status, findings_json, sources_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (step.step_id, step.investigation_id, step.hop_number,
                  step.agent, step.agent_role, step.query, step.angle,
                  step.target_type, step.status.value, step.findings_json,
                  step.sources_json, step.created_at))

    def get_steps(self, investigation_id: str) -> List[InvestigationStep]:
        """Get all steps for an investigation, ordered by hop."""
        import sqlite3
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM investigation_steps WHERE investigation_id = ? ORDER BY hop_number",
                (investigation_id,)
            ).fetchall()
            return [InvestigationStep.from_row(dict(r)) for r in rows]

    def update_step(self, step: InvestigationStep) -> None:
        """Update an existing step."""
        self.add_step(step)  # INSERT OR REPLACE handles this

    def get_full_investigation(self, investigation_id: str) -> Tuple[Optional[Investigation], List[InvestigationStep]]:
        """Get an investigation with all its steps."""
        inv = self.get(investigation_id)
        if inv is None:
            return None, []
        steps = self.get_steps(investigation_id)
        return inv, steps

    # ── Stats ─────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return store statistics."""
        import sqlite3
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cur = conn.execute(
                    "SELECT COUNT(*), SUM(total_findings), SUM(confirmed_count) FROM investigations"
                )
                row = cur.fetchone()
                total = row[0] or 0
                findings = row[1] or 0
                confirmed = row[2] or 0

                cur2 = conn.execute(
                    "SELECT COUNT(*) FROM investigations WHERE status = 'completed'"
                )
                completed = cur2.fetchone()[0] or 0

                return {
                    "total_investigations": total,
                    "completed": completed,
                    "total_findings": findings,
                    "confirmed_findings": confirmed,
                }
        except Exception:
            return {
                "total_investigations": 0,
                "completed": 0,
                "total_findings": 0,
                "confirmed_findings": 0,
            }


# Singleton
_store: Optional[InvestigationStore] = None


def get_store() -> InvestigationStore:
    global _store
    if _store is None:
        _store = InvestigationStore()
    return _store
