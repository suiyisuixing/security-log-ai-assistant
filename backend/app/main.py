"""FastAPI app: security log AI assistant.

Exposes parsing, detection, MITRE mapping, risk scoring, report generation,
and detection evaluation endpoints. All file access is constrained to the
project data directory. No external services are contacted.
"""
from __future__ import annotations

from collections import Counter
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .config import ALLOWED_LOG_NAMES, resolve_sample_log
from .detectors import detect_events, load_detection_rules
from .evaluation import (
    load_scenarios,
    run_all_detection_scenarios,
    run_one_scenario,
)
from .mitre import enrich_findings_with_mitre, list_techniques, load_mitre_mapping
from .parsers import parse_log_file, parse_raw_logs, source_type_for_sample
from .reporting import build_incident_report, build_markdown_report
from .risk import score_finding
from .schemas import (
    AnalyzeRequest,
    DashboardSummary,
    EvaluationRunResponse,
    Finding,
    IncidentReport,
    ParseRequest,
    ParsedEvent,
)


def create_app() -> FastAPI:
    app = FastAPI(
        title="security-log-ai-assistant",
        version=__version__,
        description=(
            "Local AI-assisted Security Log Analysis and SOC Triage Platform. "
            "Mock AI summarizer only; no external LLM or SIEM."
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/")
    def root() -> dict:
        return {
            "name": "security-log-ai-assistant",
            "version": __version__,
            "ai_disclosure": (
                "This project was developed as an AI-assisted learning and "
                "engineering project. AI tools were used for planning, code "
                "review, documentation support, and debugging guidance. All "
                "repository commits and project decisions were managed by "
                "the author."
            ),
        }

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/sample-logs")
    def sample_logs() -> dict:
        return {"sample_logs": sorted(ALLOWED_LOG_NAMES)}

    @app.get("/sample-logs/{log_name}")
    def get_sample_log(log_name: str) -> dict:
        try:
            path = resolve_sample_log(log_name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "name": log_name,
            "source_type": source_type_for_sample(log_name),
            "content": path.read_text(encoding="utf-8"),
        }

    @app.post("/parse")
    def parse_endpoint(req: ParseRequest) -> List[ParsedEvent]:
        try:
            return parse_raw_logs(req.source_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/analyze")
    def analyze(req: AnalyzeRequest) -> IncidentReport:
        try:
            events = parse_raw_logs(req.source_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        return build_incident_report(findings, total_events=len(events))

    @app.post("/analyze-sample/{log_name}")
    def analyze_sample(log_name: str) -> IncidentReport:
        try:
            events = parse_log_file(log_name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        return build_incident_report(findings, total_events=len(events))

    @app.get("/rules")
    def rules() -> dict:
        return {"rules": load_detection_rules()}

    @app.get("/mitre")
    def mitre() -> dict:
        return {"techniques": list_techniques()}

    @app.post("/report/json")
    def report_json(req: AnalyzeRequest) -> IncidentReport:
        events = parse_raw_logs(req.source_type, req.raw_logs)
        findings = detect_events(events)
        return build_incident_report(findings, total_events=len(events))

    @app.post("/report/markdown")
    def report_markdown(req: AnalyzeRequest) -> dict:
        events = parse_raw_logs(req.source_type, req.raw_logs)
        findings = detect_events(events)
        report = build_incident_report(findings, total_events=len(events))
        return {"markdown": build_markdown_report(report)}

    @app.get("/evaluation/scenarios")
    def evaluation_scenarios() -> dict:
        return {"scenarios": load_scenarios()}

    @app.post("/evaluation/run")
    def evaluation_run() -> EvaluationRunResponse:
        return run_all_detection_scenarios()

    @app.post("/evaluation/run-one/{scenario_id}")
    def evaluation_run_one(scenario_id: str) -> dict:
        result = run_one_scenario(scenario_id)
        if result is None:
            raise HTTPException(status_code=404, detail="scenario not found")
        return result.model_dump()

    @app.get("/dashboard/summary")
    def dashboard_summary() -> DashboardSummary:
        all_findings: List[Finding] = []
        for name in sorted(ALLOWED_LOG_NAMES):
            try:
                events = parse_log_file(name)
            except Exception:
                continue
            all_findings.extend(detect_events(events))
        enrich_findings_with_mitre(all_findings)
        for f in all_findings:
            score_finding(f)
        by_sev = Counter(f.severity for f in all_findings)
        rule_count = Counter((f.rule_id, f.rule_name) for f in all_findings)
        ip_count: Counter = Counter()
        for f in all_findings:
            for ev in f.matched_events:
                if ev.source_ip:
                    ip_count[ev.source_ip] += 1
        techs = sorted({t for f in all_findings for t in f.mitre_techniques})
        return DashboardSummary(
            total_findings=len(all_findings),
            by_severity=dict(by_sev),
            top_rules=[
                {"rule_id": rid, "rule_name": rname, "count": c}
                for (rid, rname), c in rule_count.most_common(5)
            ],
            top_source_ips=[
                {"ip": ip, "count": c} for ip, c in ip_count.most_common(5)
            ],
            techniques=techs,
        )

    @app.get("/api/surface")
    def api_surface() -> dict:
        return {
            "endpoints": [
                {"method": "GET", "path": "/"},
                {"method": "GET", "path": "/health"},
                {"method": "GET", "path": "/sample-logs"},
                {"method": "GET", "path": "/sample-logs/{log_name}"},
                {"method": "POST", "path": "/parse"},
                {"method": "POST", "path": "/analyze"},
                {"method": "POST", "path": "/analyze-sample/{log_name}"},
                {"method": "GET", "path": "/rules"},
                {"method": "GET", "path": "/mitre"},
                {"method": "POST", "path": "/report/json"},
                {"method": "POST", "path": "/report/markdown"},
                {"method": "GET", "path": "/evaluation/scenarios"},
                {"method": "POST", "path": "/evaluation/run"},
                {"method": "POST", "path": "/evaluation/run-one/{scenario_id}"},
                {"method": "GET", "path": "/dashboard/summary"},
                {"method": "GET", "path": "/api/surface"},
            ]
        }

    return app


app = create_app()
