"""Pydantic models for API requests, responses, and internal records."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ParsedEvent(BaseModel):
    source_type: str
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    user: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    action: Optional[str] = None
    query: Optional[str] = None
    response: Optional[str] = None
    raw: str
    extras: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    description: str
    severity: str
    source_type: str
    matched_events: List[ParsedEvent]
    mitre_techniques: List[str] = Field(default_factory=list)
    mitre_details: List[Dict[str, Any]] = Field(default_factory=list)
    score: int = 0
    notes: Optional[str] = None


class TimelineEntry(BaseModel):
    timestamp: Optional[str]
    source_type: str
    summary: str
    severity: Optional[str] = None
    rule_id: Optional[str] = None


class CorrelatedIncident(BaseModel):
    incident_id: str
    actor: Optional[str] = None
    rule_ids: List[str]
    severities: List[str]
    techniques: List[str]
    score: int
    summary: str


class IncidentReport(BaseModel):
    generated_at: str
    total_events: int
    total_findings: int
    overall_score: int
    overall_severity: str
    findings: List[Finding]
    timeline: List[TimelineEntry]
    correlated_incidents: List[CorrelatedIncident]
    ai_summary: str


class ParseRequest(BaseModel):
    source_type: str
    raw_logs: str


class AnalyzeRequest(BaseModel):
    source_type: str
    raw_logs: str


class ScenarioRunResult(BaseModel):
    scenario_id: str
    name: str
    expected_rule_ids: List[str]
    matched_rule_ids: List[str]
    missing_rule_ids: List[str]
    unexpected_rule_ids: List[str]
    passed: bool


class EvaluationRunResponse(BaseModel):
    total: int
    passed: int
    failed: int
    results: List[ScenarioRunResult]


class DashboardSummary(BaseModel):
    total_findings: int
    by_severity: Dict[str, int]
    top_rules: List[Dict[str, Any]]
    top_source_ips: List[Dict[str, Any]]
    techniques: List[str]
