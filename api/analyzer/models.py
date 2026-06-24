"""Pydantic models for analysis findings."""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    record_name: str
    record_type: str
    title: str
    description: str
    recommendation: str
    details: dict[str, Any] = {}


class ZoneAnalysis(BaseModel):
    zone_id: str
    zone_name: str
    is_private: bool
    record_count: int
    findings: list[Finding]

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def model_post_init(self, __context: Any) -> None:
        # Sort findings: CRITICAL first, then WARNING, then INFO
        order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        self.findings.sort(key=lambda f: order[f.severity])


class AnalysisSummary(BaseModel):
    zone_count: int
    record_count: int
    critical_count: int
    warning_count: int
    info_count: int
    zones: list[ZoneAnalysis]
