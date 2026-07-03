"""Persistence data models — dataclasses for investigations.

Canonical source for Investigation, InvestigationStatus, InvestigationStep,
and StepStatus used by the SQLite store and the test suite.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


class InvestigationStatus(str, enum.Enum):
    CREATED = "created"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Investigation:
    investigation_id: str = ""
    original_query: str = ""
    target_type: str = "unknown"
    target_value: str = ""
    status: InvestigationStatus = InvestigationStatus.CREATED
    total_hops: int = 0
    total_findings: int = 0
    confirmed_count: int = 0
    cross_references: str = "[]"  # JSON string
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        if not self.investigation_id:
            self.investigation_id = uuid.uuid4().hex[:16]
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_row(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "original_query": self.original_query,
            "target_type": self.target_type,
            "target_value": self.target_value,
            "status": self.status.value,
            "total_hops": self.total_hops,
            "total_findings": self.total_findings,
            "confirmed_count": self.confirmed_count,
            "cross_references": self.cross_references,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_row(cls, row: dict) -> "Investigation":
        status_val = row.get("status", "pending")
        try:
            status = InvestigationStatus(status_val)
        except ValueError:
            status = InvestigationStatus.PENDING
        return cls(
            investigation_id=row.get("investigation_id", ""),
            original_query=row.get("original_query", ""),
            target_type=row.get("target_type", "unknown"),
            target_value=row.get("target_value", ""),
            status=status,
            total_hops=row.get("total_hops", 0),
            total_findings=row.get("total_findings", 0),
            confirmed_count=row.get("confirmed_count", 0),
            cross_references=row.get("cross_references", "[]"),
            created_at=row.get("created_at", ""),
            updated_at=row.get("updated_at", ""),
        )


@dataclass
class InvestigationStep:
    step_id: str = ""
    investigation_id: str = ""
    hop_number: int = 0
    agent: str = ""  # agent role name (backward compat: also stored as agent_role)
    agent_role: str = ""  # alias for agent
    query: str = ""  # the query/angle for this step
    angle: str = ""  # alias for query
    target_type: str = ""
    status: StepStatus = StepStatus.PENDING
    findings_json: str = "[]"  # JSON string
    sources_json: str = "[]"   # JSON string
    created_at: str = ""

    def __post_init__(self):
        if not self.step_id:
            self.step_id = uuid.uuid4().hex[:16]
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        # Sync agent/agent_role
        if self.agent and not self.agent_role:
            self.agent_role = self.agent
        elif self.agent_role and not self.agent:
            self.agent = self.agent_role
        # Sync query/angle
        if self.query and not self.angle:
            self.angle = self.query
        elif self.angle and not self.query:
            self.query = self.angle

    def to_row(self) -> dict:
        return {
            "step_id": self.step_id,
            "investigation_id": self.investigation_id,
            "hop_number": self.hop_number,
            "agent": self.agent or self.agent_role,
            "agent_role": self.agent_role or self.agent,
            "query": self.query or self.angle,
            "angle": self.angle or self.query,
            "target_type": self.target_type,
            "status": self.status.value,
            "findings_json": self.findings_json,
            "sources_json": self.sources_json,
            "created_at": self.created_at,
        }

    @classmethod
    def from_row(cls, row: dict) -> "InvestigationStep":
        status_val = row.get("status", "pending")
        try:
            status = StepStatus(status_val)
        except ValueError:
            status = StepStatus.PENDING
        agent = row.get("agent") or row.get("agent_role", "")
        query = row.get("query") or row.get("angle", "")
        return cls(
            step_id=row.get("step_id", ""),
            investigation_id=row.get("investigation_id", ""),
            hop_number=row.get("hop_number", 0),
            agent=agent,
            agent_role=agent,
            query=query,
            angle=query,
            target_type=row.get("target_type", ""),
            status=status,
            findings_json=row.get("findings_json", "[]"),
            sources_json=row.get("sources_json", "[]"),
            created_at=row.get("created_at", ""),
        )
