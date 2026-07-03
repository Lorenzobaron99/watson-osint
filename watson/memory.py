"""Memory Engine — persistent cross-session memory for Watson.

Stores investigations, findings, and entities in a SQLite database
at ~/.watson/memory.db. Enables:
- Full-text search (FTS5) across past investigations
- Entity tracking across cases (same person/domain appearing in multiple investigations)
- Context injection: when investigating a target, surface relevant past findings

Inspired by Hermes Agent's memory system — durable facts that survive restarts.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class MemoryEngine:
    """Persistent investigation memory with full-text search.

    Usage:
        mem = MemoryEngine()
        mem.save_investigation("target", findings, reasoning)

        # Later session:
        results = mem.search("Elon Musk")
        context = mem.get_context_for_target("shadowy-company.com")
    """

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = Path.home() / ".watson" / "memory.db"
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    query TEXT NOT NULL,
                    target_type TEXT,
                    investigation_goal TEXT,
                    reasoning_json TEXT,
                    findings_count INTEGER DEFAULT 0,
                    sources_count INTEGER DEFAULT 0,
                    risk_level TEXT,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT DEFAULT '{}'
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    source TEXT,
                    tool TEXT,
                    severity TEXT DEFAULT 'info',
                    confidence REAL DEFAULT 0.5,
                    evidence_json TEXT DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    mention_count INTEGER DEFAULT 1,
                    metadata_json TEXT DEFAULT '{}'
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS entity_mentions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    investigation_id TEXT NOT NULL,
                    finding_id TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (entity_id) REFERENCES entities(id),
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
                )
            """)

            # FTS5 index for full-text search across investigations and findings
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
                    query,
                    findings_text,
                    entities_text,
                    content='investigations',
                    content_rowid='rowid'
                )
            """)

            conn.commit()

    # ── Save ──────────────────────────────────────────────────────

    def save_investigation(
        self,
        query: str,
        findings: list[dict],
        reasoning: dict | None = None,
        target_type: str = "unknown",
        risk_level: str = "low",
        metadata: dict | None = None,
    ) -> str:
        """Save an investigation and its findings to memory.

        Returns the investigation ID.
        """
        inv_id = str(uuid.uuid4())[:12]
        now = datetime.now(timezone.utc).isoformat()

        # Extract entities from findings
        entities = self._extract_entities(findings)

        with sqlite3.connect(str(self._db_path)) as conn:
            # Save investigation
            conn.execute(
                """INSERT INTO investigations 
                   (id, query, target_type, investigation_goal, reasoning_json,
                    findings_count, sources_count, risk_level, created_at, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    inv_id,
                    query,
                    target_type,
                    reasoning.get("investigation_goal", "") if reasoning else "",
                    json.dumps(reasoning) if reasoning else "{}",
                    len(findings),
                    len({f.get("source", "unknown") for f in findings}),
                    risk_level,
                    now,
                    json.dumps(metadata or {}),
                ),
            )

            # Save findings
            for f in findings:
                f_id = f.get("id", str(uuid.uuid4())[:8])
                conn.execute(
                    """INSERT OR IGNORE INTO findings
                       (id, investigation_id, title, description, source, tool,
                        severity, confidence, evidence_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        f_id,
                        inv_id,
                        f.get("title", "")[:300],
                        f.get("description", "")[:2000],
                        f.get("source", "unknown"),
                        f.get("tool", "unknown"),
                        f.get("severity", "info"),
                        f.get("confidence", 0.5),
                        json.dumps(f.get("evidence", [])),
                        now,
                    ),
                )

            # Save entities
            for entity in entities:
                e_id = self._upsert_entity(conn, entity, inv_id, now)

            # Update FTS index
            findings_text = " ".join(
                f"{f.get('title','')} {f.get('description','')[:500]}"
                for f in findings
            )
            entities_text = " ".join(
                f"{e['name']} {e['type']}" for e in entities
            )
            conn.execute(
                """INSERT INTO memory_fts (query, findings_text, entities_text)
                   VALUES (?, ?, ?)""",
                (query, findings_text, entities_text),
            )

            conn.commit()

        return inv_id

    def _upsert_entity(
        self, conn: sqlite3.Connection, entity: dict, inv_id: str, now: str
    ) -> str:
        """Insert or update an entity, linking to the investigation."""
        name = entity["name"].lower().strip()
        etype = entity["type"]

        # Check if entity exists (case-insensitive name match)
        row = conn.execute(
            "SELECT id, mention_count FROM entities WHERE LOWER(name) = ? AND type = ?",
            (name, etype),
        ).fetchone()

        if row:
            e_id = row[0]
            count = row[1]
            conn.execute(
                "UPDATE entities SET last_seen = ?, mention_count = ? WHERE id = ?",
                (now, count + 1, e_id),
            )
        else:
            e_id = str(uuid.uuid4())[:12]
            conn.execute(
                """INSERT INTO entities (id, name, type, first_seen, last_seen, mention_count)
                   VALUES (?, ?, ?, ?, ?, 1)""",
                (e_id, entity["name"], etype, now, now),
            )

        # Link to investigation
        conn.execute(
            """INSERT INTO entity_mentions (entity_id, investigation_id, created_at)
               VALUES (?, ?, ?)""",
            (e_id, inv_id, now),
        )

        return e_id

    def _extract_entities(self, findings: list[dict]) -> list[dict]:
        """Extract entities (people, domains, orgs) from findings."""
        import re

        entities: list[dict] = []
        seen: set[tuple[str, str]] = set()

        # Known entity patterns
        for f in findings:
            text = f"{f.get('title', '')} {f.get('description', '')}"

            # Extract domains
            for match in re.finditer(
                r"\b([\w-]+\.(com|org|net|io|gov|edu|uk|de|fr|ru|cn|jp|ai|dev))\b",
                text,
                re.IGNORECASE,
            ):
                domain = match.group(1).lower()
                key = (domain, "domain")
                if key not in seen:
                    seen.add(key)
                    entities.append({"name": domain, "type": "domain"})

            # Extract emails
            for match in re.finditer(r"[\w.+-]+@[\w-]+\.\w+", text):
                email = match.group(0).lower()
                key = (email, "email")
                if key not in seen:
                    seen.add(key)
                    entities.append({"name": email, "type": "email"})

            # Extract capitalized names (2+ words)
            for match in re.finditer(
                r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b", text
            ):
                name = match.group(1)
                if len(name.split()) >= 2:
                    key = (name.lower(), "person")
                    if key not in seen:
                        seen.add(key)
                        entities.append({"name": name, "type": "person"})

        return entities[:30]  # cap

    # ── Search ─────────────────────────────────────────────────────

    def search(
        self, query: str, limit: int = 10
    ) -> list[dict]:
        """Full-text search across past investigations.

        Returns matching investigations with snippets.
        """
        with sqlite3.connect(str(self._db_path)) as conn:
            try:
                rows = conn.execute(
                    """SELECT i.id, i.query, i.target_type, i.investigation_goal,
                              i.findings_count, i.risk_level, i.created_at,
                              snippet(memory_fts, 2, '<mark>', '</mark>', '...', 40) as snippet
                       FROM memory_fts
                       JOIN investigations i ON memory_fts.rowid = i.rowid
                       WHERE memory_fts MATCH ?
                       ORDER BY rank
                       LIMIT ?""",
                    (query, limit),
                ).fetchall()
            except sqlite3.OperationalError:
                # FTS5 syntax error — try simple LIKE
                like_q = f"%{query}%"
                rows = conn.execute(
                    """SELECT id, query, target_type, investigation_goal,
                              findings_count, risk_level, created_at, '' as snippet
                       FROM investigations
                       WHERE query LIKE ? OR investigation_goal LIKE ?
                       ORDER BY created_at DESC
                       LIMIT ?""",
                    (like_q, like_q, limit),
                ).fetchall()

        return [
            {
                "id": r[0],
                "query": r[1],
                "target_type": r[2],
                "goal": r[3],
                "findings_count": r[4],
                "risk_level": r[5],
                "created_at": r[6],
                "snippet": r[7] if len(r) > 7 else "",
            }
            for r in rows
        ]

    def get_context_for_target(self, target: str) -> dict | None:
        """Get relevant past context when investigating a target.

        If this target (or related entities) were investigated before,
        returns past findings and entity history to inject into the new
        investigation.
        """
        results = self.search(target, limit=3)
        if not results:
            return None

        with sqlite3.connect(str(self._db_path)) as conn:
            # Get findings from the most relevant past investigation
            best = results[0]
            findings_rows = conn.execute(
                """SELECT title, description, source, severity, confidence
                   FROM findings
                   WHERE investigation_id = ?
                   ORDER BY confidence DESC
                   LIMIT 10""",
                (best["id"],),
            ).fetchall()

            # Get entity history for this target
            entity_rows = conn.execute(
                """SELECT e.name, e.type, e.mention_count, e.first_seen, e.last_seen,
                          COUNT(em.id) as investigation_count
                   FROM entities e
                   JOIN entity_mentions em ON e.id = em.entity_id
                   WHERE LOWER(e.name) LIKE ?
                   GROUP BY e.id
                   ORDER BY e.last_seen DESC
                   LIMIT 5""",
                (f"%{target.lower()}%",),
            ).fetchall()

        return {
            "past_investigations": results,
            "relevant_findings": [
                {
                    "title": r[0],
                    "description": r[1][:300] if r[1] else "",
                    "source": r[2],
                    "severity": r[3],
                    "confidence": r[4],
                }
                for r in findings_rows
            ],
            "entity_history": [
                {
                    "name": r[0],
                    "type": r[1],
                    "mention_count": r[2],
                    "first_seen": r[3],
                    "last_seen": r[4],
                    "investigation_count": r[5],
                }
                for r in entity_rows
            ],
        }

    def list_recent(self, limit: int = 20) -> list[dict]:
        """List recent investigations."""
        with sqlite3.connect(str(self._db_path)) as conn:
            rows = conn.execute(
                """SELECT id, query, target_type, findings_count, 
                          risk_level, created_at
                   FROM investigations
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()

        return [
            {
                "id": r[0],
                "query": r[1],
                "target_type": r[2],
                "findings_count": r[3],
                "risk_level": r[4],
                "created_at": r[5],
            }
            for r in rows
        ]

    def get_investigation(self, inv_id: str) -> dict | None:
        """Retrieve a full investigation by ID."""
        with sqlite3.connect(str(self._db_path)) as conn:
            row = conn.execute(
                """SELECT id, query, target_type, investigation_goal,
                          reasoning_json, findings_count, sources_count,
                          risk_level, created_at, metadata_json
                   FROM investigations WHERE id = ?""",
                (inv_id,),
            ).fetchone()

            if not row:
                return None

            findings_rows = conn.execute(
                """SELECT id, title, description, source, tool, severity,
                          confidence, evidence_json
                   FROM findings WHERE investigation_id = ?
                   ORDER BY confidence DESC""",
                (inv_id,),
            ).fetchall()

            entity_rows = conn.execute(
                """SELECT e.name, e.type
                   FROM entities e
                   JOIN entity_mentions em ON e.id = em.entity_id
                   WHERE em.investigation_id = ?""",
                (inv_id,),
            ).fetchall()

        return {
            "id": row[0],
            "query": row[1],
            "target_type": row[2],
            "goal": row[3],
            "reasoning": json.loads(row[4]) if row[4] else {},
            "findings_count": row[5],
            "sources_count": row[6],
            "risk_level": row[7],
            "created_at": row[8],
            "metadata": json.loads(row[9]) if row[9] else {},
            "findings": [
                {
                    "id": fr[0],
                    "title": fr[1],
                    "description": fr[2],
                    "source": fr[3],
                    "tool": fr[4],
                    "severity": fr[5],
                    "confidence": fr[6],
                    "evidence": json.loads(fr[7]) if fr[7] else [],
                }
                for fr in findings_rows
            ],
            "entities": [{"name": er[0], "type": er[1]} for er in entity_rows],
        }

    def get_entity_profile(self, name: str) -> dict | None:
        """Get full profile of an entity across all investigations."""
        with sqlite3.connect(str(self._db_path)) as conn:
            entity_row = conn.execute(
                """SELECT id, name, type, first_seen, last_seen, mention_count
                   FROM entities WHERE LOWER(name) = ?""",
                (name.lower(),),
            ).fetchone()

            if not entity_row:
                return None

            e_id = entity_row[0]

            # Get all investigations mentioning this entity
            inv_rows = conn.execute(
                """SELECT i.id, i.query, i.created_at
                   FROM investigations i
                   JOIN entity_mentions em ON i.id = em.investigation_id
                   WHERE em.entity_id = ?
                   ORDER BY i.created_at DESC""",
                (e_id,),
            ).fetchall()

            # Get related entities (co-occurring in same investigations)
            related_rows = conn.execute(
                """SELECT e.name, e.type, COUNT(DISTINCT em2.investigation_id) as shared
                   FROM entities e
                   JOIN entity_mentions em2 ON e.id = em2.entity_id
                   WHERE em2.investigation_id IN (
                       SELECT investigation_id FROM entity_mentions WHERE entity_id = ?
                   )
                   AND e.id != ?
                   GROUP BY e.id
                   ORDER BY shared DESC
                   LIMIT 10""",
                (e_id, e_id),
            ).fetchall()

        return {
            "name": entity_row[1],
            "type": entity_row[2],
            "first_seen": entity_row[3],
            "last_seen": entity_row[4],
            "mention_count": entity_row[5],
            "investigations": [
                {"id": r[0], "query": r[1], "created_at": r[2]}
                for r in inv_rows
            ],
            "related_entities": [
                {"name": r[0], "type": r[1], "shared_investigations": r[2]}
                for r in related_rows
            ],
        }

    def stats(self) -> dict:
        """Return memory statistics."""
        with sqlite3.connect(str(self._db_path)) as conn:
            inv_count = conn.execute(
                "SELECT COUNT(*) FROM investigations"
            ).fetchone()[0]
            finding_count = conn.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]
            entity_count = conn.execute(
                "SELECT COUNT(*) FROM entities"
            ).fetchone()[0]
            db_size = self._db_path.stat().st_size if self._db_path.exists() else 0

        return {
            "investigations": inv_count,
            "findings": finding_count,
            "entities": entity_count,
            "db_size_bytes": db_size,
            "db_path": str(self._db_path),
        }


# Singleton instance
memory = MemoryEngine()
