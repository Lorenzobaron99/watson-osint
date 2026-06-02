"""Core models for Watson — Pydantic data structures."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingSource(str, Enum):
    SATELLITE = "satellite"
    GEOLOCATION = "geolocation"
    IMAGE_VIDEO = "image_video"
    SOCIAL_MEDIA = "social_media"
    PEOPLE = "people"
    WEBSITES = "websites"
    CORPORATE = "corporate"
    CONFLICT = "conflict"
    OSINT = "osint"
    BELLINGCAT = "bellingcat"
    SOCMINT = "socmint"
    CROSS_REF = "cross_ref"


class Finding(BaseModel):
    """A single finding from an investigation tool."""

    id: str = Field(description="Unique finding ID")
    source: FindingSource
    tool: str = Field(description="Tool name that produced this finding")
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list, description="URLs or references")
    severity: FindingSeverity = FindingSeverity.INFO
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=datetime.now)
    metadata: dict = Field(default_factory=dict)


class InvestigationTask(BaseModel):
    """A decomposed investigation subtask dispatched to a tool."""

    id: str
    tool_category: FindingSource
    tool_name: str = ""
    query: str
    context: str = ""
    priority: int = 1


class InvestigationRequest(BaseModel):
    """Top-level investigation request from user."""

    query: str
    tools: list[FindingSource] | None = Field(default=None)
    max_findings_per_tool: int = 10
    cross_reference: bool = True


class Report(BaseModel):
    """Final investigation report."""

    query: str
    generated_at: datetime = Field(default_factory=datetime.now)
    findings: list[Finding] = Field(default_factory=list)
    cross_references: list[Finding] = Field(default_factory=list)
    summary: str = ""
    tool_stats: dict[str, int] = Field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings) + len(self.cross_references)

    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings + self.cross_references:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def by_source(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.source.value] = counts.get(f.source.value, 0) + 1
        return counts
