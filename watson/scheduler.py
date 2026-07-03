"""Autonomous Scheduler — recurring target monitoring for Watson.

Schedules investigations to run on a timer. Each tick:
  1. Runs the full investigation pipeline (reason → dispatch → cross-ref)
  2. Compares findings against past results (memory engine diff)
  3. If new findings or risk level changes → alerts
  4. Saves results to memory

Jobs are stored in ~/.watson/scheduler.db with SQLite.
The scheduler runs in a background thread, waking every 30s to check.

Inspired by Hermes Agent's cronjob system — fully autonomous,
no user interaction needed during runs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("watson.scheduler")


@dataclass
class ScheduledJob:
    """A recurring investigation target."""
    id: str
    query: str
    interval_minutes: int
    target_type: str = "unknown"
    enabled: bool = True
    last_run: str | None = None
    next_run: str | None = None
    run_count: int = 0
    alert_on_change: bool = True
    alert_on_new_findings: bool = True
    findings_threshold: int = 1  # min new findings to trigger alert
    created_at: str = ""
    metadata: dict = field(default_factory=dict)


class SchedulerDB:
    """SQLite-backed job store."""

    def __init__(self, db_path: Path):
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _init(self):
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    query TEXT NOT NULL,
                    interval_minutes INTEGER NOT NULL DEFAULT 60,
                    target_type TEXT DEFAULT 'unknown',
                    enabled INTEGER DEFAULT 1,
                    last_run TEXT,
                    next_run TEXT,
                    run_count INTEGER DEFAULT 0,
                    alert_on_change INTEGER DEFAULT 1,
                    alert_on_new_findings INTEGER DEFAULT 1,
                    findings_threshold INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS run_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    run_at TEXT NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    new_findings_count INTEGER DEFAULT 0,
                    risk_level_before TEXT,
                    risk_level_after TEXT,
                    duration_seconds REAL,
                    error TEXT,
                    FOREIGN KEY (job_id) REFERENCES jobs(id)
                )
            """)
            conn.commit()

    def create(self, job: ScheduledJob) -> str:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                """INSERT INTO jobs
                   (id, query, interval_minutes, target_type, enabled,
                    last_run, next_run, run_count, alert_on_change,
                    alert_on_new_findings, findings_threshold, created_at, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job.id,
                    job.query,
                    job.interval_minutes,
                    job.target_type,
                    1 if job.enabled else 0,
                    job.last_run,
                    job.next_run or now,
                    job.run_count,
                    1 if job.alert_on_change else 0,
                    1 if job.alert_on_new_findings else 0,
                    job.findings_threshold,
                    job.created_at or now,
                    json.dumps(job.metadata),
                ),
            )
            conn.commit()
        return job.id

    def list_all(self) -> list[ScheduledJob]:
        with sqlite3.connect(str(self._db_path)) as conn:
            rows = conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC"
            ).fetchall()

        jobs = []
        for r in rows:
            jobs.append(ScheduledJob(
                id=r[0], query=r[1], interval_minutes=r[2], target_type=r[3],
                enabled=bool(r[4]), last_run=r[5], next_run=r[6], run_count=r[7],
                alert_on_change=bool(r[8]), alert_on_new_findings=bool(r[9]),
                findings_threshold=r[10], created_at=r[11],
                metadata=json.loads(r[12]) if r[12] else {},
            ))
        return jobs

    def get(self, job_id: str) -> ScheduledJob | None:
        with sqlite3.connect(str(self._db_path)) as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        if not row:
            return None
        return ScheduledJob(
            id=row[0], query=row[1], interval_minutes=row[2], target_type=row[3],
            enabled=bool(row[4]), last_run=row[5], next_run=row[6], run_count=row[7],
            alert_on_change=bool(row[8]), alert_on_new_findings=bool(row[9]),
            findings_threshold=row[10], created_at=row[11],
            metadata=json.loads(row[12]) if row[12] else {},
        )

    def update(self, job_id: str, **kwargs):
        allowed = {
            "enabled", "last_run", "next_run", "run_count", "interval_minutes",
            "alert_on_change", "alert_on_new_findings", "findings_threshold",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [job_id]

        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                f"UPDATE jobs SET {set_clause} WHERE id = ?", values
            )
            conn.commit()

    def delete(self, job_id: str):
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            conn.execute("DELETE FROM run_history WHERE job_id = ?", (job_id,))
            conn.commit()

    def log_run(
        self, job_id: str, findings_count: int, new_findings: int,
        risk_before: str, risk_after: str, duration: float, error: str = "",
    ):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                """INSERT INTO run_history
                   (job_id, run_at, findings_count, new_findings_count,
                    risk_level_before, risk_level_after, duration_seconds, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (job_id, now, findings_count, new_findings, risk_before,
                 risk_after, duration, error),
            )
            conn.commit()

    def get_history(self, job_id: str, limit: int = 20) -> list[dict]:
        with sqlite3.connect(str(self._db_path)) as conn:
            rows = conn.execute(
                """SELECT run_at, findings_count, new_findings_count,
                          risk_level_before, risk_level_after, duration_seconds, error
                   FROM run_history WHERE job_id = ?
                   ORDER BY run_at DESC LIMIT ?""",
                (job_id, limit),
            ).fetchall()
        return [
            {
                "run_at": r[0], "findings_count": r[1],
                "new_findings_count": r[2], "risk_before": r[3],
                "risk_after": r[4], "duration": r[5], "error": r[6],
            }
            for r in rows
        ]


class Scheduler:
    """Background scheduler for recurring OSINT investigations.

    Usage:
        sched = Scheduler(investigate_fn=my_investigate_function)
        sched.start()  # begins checking every 30s
    """

    def __init__(
        self,
        db_path: Path | None = None,
        investigate_fn: Callable | None = None,
        on_alert: Callable | None = None,
    ):
        if db_path is None:
            db_path = Path.home() / ".watson" / "scheduler.db"
        self._db = SchedulerDB(db_path)
        self._investigate_fn = investigate_fn
        self._on_alert = on_alert
        self._thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._running

    def start(self):
        """Start the scheduler in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Scheduler started")

    def stop(self):
        """Stop the scheduler."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Scheduler stopped")

    def _loop(self):
        """Main scheduler loop — checks for due jobs every 30s."""
        while self._running:
            try:
                self._tick()
            except Exception as e:
                logger.error(f"Scheduler tick error: {e}")
            time.sleep(30)

    def _tick(self):
        """Check for and execute due jobs."""
        jobs = self._db.list_all()
        now_utc = datetime.now(timezone.utc)

        for job in jobs:
            if not job.enabled:
                continue
            if not job.next_run:
                continue

            next_run = datetime.fromisoformat(job.next_run.replace("Z", "+00:00"))
            if now_utc < next_run:
                continue

            # Job is due — execute with lock
            with self._lock:
                try:
                    self._execute_job(job)
                except Exception as e:
                    logger.error(f"Job {job.id} failed: {e}")
                    self._db.log_run(
                        job.id, 0, 0, "", "", 0, str(e)[:200]
                    )

    def _execute_job(self, job: ScheduledJob):
        """Execute a single scheduled investigation."""
        start = time.time()

        # Update run tracking
        now = datetime.now(timezone.utc)
        self._db.update(
            job.id,
            last_run=now.isoformat(),
            run_count=job.run_count + 1,
        )

        # Get previous risk level from memory
        try:
            from .memory import memory as mem
            prev_ctx = mem.get_context_for_target(job.query)
            prev_risk = prev_ctx["past_investigations"][0]["risk_level"] if prev_ctx and prev_ctx["past_investigations"] else "unknown"
        except Exception:
            prev_risk = "unknown"

        error = ""

        try:
            # Run investigation
            if self._investigate_fn:
                result = self._investigate_fn(job.query)
            else:
                result = {}

            duration = time.time() - start
            findings_count = result.get("findings", 0) if result else 0
            new_risk = result.get("risk_level", "unknown") if result else "unknown"

            # Determine new findings (compared to previous run)
            new_findings = self._count_new_findings(job.id, result)

            # Log
            self._db.log_run(
                job.id, findings_count, new_findings,
                prev_risk, new_risk, duration, "",
            )

            # Alert if needed
            if self._on_alert:
                should_alert = False
                reason = ""

                if job.alert_on_new_findings and new_findings >= job.findings_threshold:
                    should_alert = True
                    reason = f"{new_findings} new findings"
                if job.alert_on_change and new_risk != prev_risk and prev_risk != "unknown":
                    should_alert = True
                    reason = f"Risk changed from {prev_risk} → {new_risk}"

                if should_alert:
                    self._on_alert({
                        "job_id": job.id,
                        "query": job.query,
                        "reason": reason,
                        "findings_count": findings_count,
                        "new_findings": new_findings,
                        "risk_before": prev_risk,
                        "risk_after": new_risk,
                        "timestamp": now.isoformat(),
                    })

        except Exception as e:
            duration = time.time() - start
            error = str(e)[:200]
            self._db.log_run(job.id, 0, 0, prev_risk, "error", duration, error)

        # Schedule next run
        next_run = datetime.now(timezone.utc)
        from datetime import timedelta
        next_run += timedelta(minutes=job.interval_minutes)
        self._db.update(job.id, next_run=next_run.isoformat())

    def _count_new_findings(self, job_id: str, result: dict | None) -> int:
        """Count findings that are new compared to the last run."""
        if not result:
            return 0

        history = self._db.get_history(job_id, limit=1)
        if not history or history[0]["findings_count"] == 0:
            return result.get("findings", 0)

        # Simple heuristic: if findings count changed significantly
        current = result.get("findings", 0)
        previous = history[0]["findings_count"]
        diff = max(0, current - previous)
        return diff

    # ── Public API ────────────────────────────────────────────────

    def add_job(
        self,
        query: str,
        interval_minutes: int = 60,
        target_type: str = "unknown",
        alert_on_change: bool = True,
        alert_on_new_findings: bool = True,
        findings_threshold: int = 1,
        metadata: dict | None = None,
    ) -> str:
        """Schedule a new recurring investigation.

        Args:
            query: Investigation target
            interval_minutes: How often to run (minimum: 5)
            target_type: person/domain/company/etc.
            alert_on_change: Alert if risk level changes
            alert_on_new_findings: Alert if new findings appear
            findings_threshold: Min new findings to trigger alert
            metadata: Optional extra data
        """
        interval_minutes = max(5, interval_minutes)

        now = datetime.now(timezone.utc)
        next_run = now.isoformat()

        job = ScheduledJob(
            id=str(uuid.uuid4())[:12],
            query=query,
            interval_minutes=interval_minutes,
            target_type=target_type,
            enabled=True,
            last_run=None,
            next_run=next_run,
            run_count=0,
            alert_on_change=alert_on_change,
            alert_on_new_findings=alert_on_new_findings,
            findings_threshold=findings_threshold,
            created_at=now.isoformat(),
            metadata=metadata or {},
        )
        return self._db.create(job)

    def list_jobs(self) -> list[dict]:
        """List all scheduled jobs."""
        jobs = self._db.list_all()
        return [
            {
                "id": j.id,
                "query": j.query,
                "interval_minutes": j.interval_minutes,
                "target_type": j.target_type,
                "enabled": j.enabled,
                "last_run": j.last_run,
                "next_run": j.next_run,
                "run_count": j.run_count,
                "alert_on_change": j.alert_on_change,
                "alert_on_new_findings": j.alert_on_new_findings,
                "created_at": j.created_at,
            }
            for j in jobs
        ]

    def get_job(self, job_id: str) -> dict | None:
        """Get a job with its run history."""
        job = self._db.get(job_id)
        if not job:
            return None
        history = self._db.get_history(job_id)
        return {
            "id": job.id,
            "query": job.query,
            "interval_minutes": job.interval_minutes,
            "target_type": job.target_type,
            "enabled": job.enabled,
            "last_run": job.last_run,
            "next_run": job.next_run,
            "run_count": job.run_count,
            "alert_on_change": job.alert_on_change,
            "alert_on_new_findings": job.alert_on_new_findings,
            "findings_threshold": job.findings_threshold,
            "created_at": job.created_at,
            "history": history,
        }

    def toggle_job(self, job_id: str, enabled: bool):
        """Enable or disable a job."""
        self._db.update(job_id, enabled=enabled)

    def remove_job(self, job_id: str):
        """Delete a scheduled job."""
        self._db.delete(job_id)

    def run_now(self, job_id: str):
        """Force an immediate run of a scheduled job."""
        job = self._db.get(job_id)
        if not job:
            return
        # Set next_run to now so it executes on next tick
        self._db.update(
            job_id,
            next_run=datetime.now(timezone.utc).isoformat(),
        )
