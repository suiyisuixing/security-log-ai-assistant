"""FastAPI app: security log AI assistant — v2 SOC platform.

Exposes parsing, detection, MITRE mapping, risk scoring, report generation,
detection evaluation, alert triage, incident case management, entity risk
profiles, kill-chain view, detection coverage matrix, false-positive review,
and rule tuning endpoints. All file access is constrained to the project
data directory. No external services are contacted.
"""
from __future__ import annotations

from collections import Counter
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import __version__
from .cases import create_cases_from_alerts, summarize_cases
from .config import ALLOWED_LOG_NAMES, resolve_sample_log
from .correlation import correlate_findings
from .coverage import build_detection_coverage_matrix, summarize_coverage
from .detection_engineering import (
    build_detection_engineering_report,
    explain_rule,
    rule_quality_score,
)
from .detectors import detect_events, load_detection_rules
from .entities import build_entity_profiles, summarize_entities
from .evaluation import (
    analyze_dataset,
    evaluate_datasets,
    get_dataset_metadata,
    list_datasets,
    load_scenarios,
    run_all_detection_scenarios,
    run_one_scenario,
)
from .false_positive import (
    annotate_alerts_with_fp_likelihood,
    summarize_false_positive_review,
)
from .kill_chain import build_kill_chain_view
from .metrics import (
    calculate_category_metrics,
    calculate_detection_metrics,
    calculate_rule_metrics,
    summarize_metrics,
)
from .mitre import enrich_findings_with_mitre, list_techniques, load_mitre_mapping
from .parsers import parse_log_file, parse_raw_logs, source_type_for_sample
from .playbooks import (
    load_playbooks,
    recommend_playbooks,
    summarize_playbook_recommendations,
)
from .reporting import (
    build_analyst_report,
    build_detection_engineering_report_markdown,
    build_executive_report,
    build_incident_report,
    build_markdown_report,
    build_soc_markdown_report,
    build_soc_report,
)
from .risk import score_finding
from .rule_tuning import build_rule_tuning_report
from .schemas import (
    AnalyzeRequest,
    DashboardSummary,
    EvaluationRunResponse,
    Finding,
    IncidentReport,
    ParseRequest,
    ParsedEvent,
)
from .triage import generate_alerts_from_findings, summarize_alert_queue
from .workflow import (
    generate_workflow_summary,
    simulate_soc_workflow,
)


class V2AnalyzeRequest(BaseModel):
    log_type: str
    raw_logs: str
    include_correlation: bool = True


def _events_for_all_samples() -> List[ParsedEvent]:
    events: List[ParsedEvent] = []
    for name in sorted(ALLOWED_LOG_NAMES):
        try:
            events.extend(parse_log_file(name))
        except Exception:
            continue
    return events


def _findings_for_all_samples() -> tuple[List[ParsedEvent], List[Finding]]:
    events = _events_for_all_samples()
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    return events, findings


def create_app() -> FastAPI:
    app = FastAPI(
        title="security-log-ai-assistant",
        version=__version__,
        description=(
            "Local Security Operations Evaluation Platform for AI-assisted "
            "log analysis, alert triage, MITRE ATT&CK mapping, incident case "
            "management, detection evaluation, false-positive review, and "
            "SOC analyst reporting. Mock AI only; no external LLM or SIEM."
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---------- v1 endpoints ----------

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
        events, findings = _findings_for_all_samples()
        by_sev = Counter(f.severity for f in findings)
        rule_count = Counter((f.rule_id, f.rule_name) for f in findings)
        ip_count: Counter = Counter()
        for f in findings:
            for ev in f.matched_events:
                if ev.source_ip:
                    ip_count[ev.source_ip] += 1
        techs = sorted({t for f in findings for t in f.mitre_techniques})
        return DashboardSummary(
            total_findings=len(findings),
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

    # ---------- v2 endpoints ----------

    @app.get("/triage/sample")
    def triage_sample() -> dict:
        _, findings = _findings_for_all_samples()
        alerts = generate_alerts_from_findings(findings)
        annotate_alerts_with_fp_likelihood(alerts)
        return {
            "alerts": [a.model_dump() for a in alerts],
            "queue_summary": summarize_alert_queue(alerts),
        }

    @app.post("/triage/analyze")
    def triage_analyze(req: V2AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.log_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        enrich_findings_with_mitre(findings)
        for f in findings:
            score_finding(f)
        alerts = generate_alerts_from_findings(findings)
        annotate_alerts_with_fp_likelihood(alerts)
        correlated = correlate_findings(findings) if req.include_correlation else []
        risk_summary = {
            "total_findings": len(findings),
            "total_alerts": len(alerts),
            "severity_counts": dict(Counter(f.severity for f in findings)),
        }
        return {
            "alerts": [a.model_dump() for a in alerts],
            "queue_summary": summarize_alert_queue(alerts),
            "findings": [f.model_dump() for f in findings],
            "risk_summary": risk_summary,
            "correlated_incidents": [c.model_dump() for c in correlated],
        }

    @app.get("/cases/sample")
    def cases_sample() -> dict:
        _, findings = _findings_for_all_samples()
        alerts = generate_alerts_from_findings(findings)
        annotate_alerts_with_fp_likelihood(alerts)
        correlated = correlate_findings(findings)
        cases = create_cases_from_alerts(alerts, correlated)
        return {
            "cases": [c.model_dump() for c in cases],
            "case_summary": summarize_cases(cases),
        }

    @app.post("/cases/from-analysis")
    def cases_from_analysis(req: V2AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.log_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        enrich_findings_with_mitre(findings)
        for f in findings:
            score_finding(f)
        alerts = generate_alerts_from_findings(findings)
        annotate_alerts_with_fp_likelihood(alerts)
        correlated = correlate_findings(findings) if req.include_correlation else []
        cases = create_cases_from_alerts(alerts, correlated)
        return {
            "cases": [c.model_dump() for c in cases],
            "case_summary": summarize_cases(cases),
            "alerts": [a.model_dump() for a in alerts],
            "correlated_incidents": [c.model_dump() for c in correlated],
        }

    @app.post("/false-positive/review")
    def false_positive_review(req: V2AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.log_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        enrich_findings_with_mitre(findings)
        for f in findings:
            score_finding(f)
        alerts = generate_alerts_from_findings(findings)
        annotate_alerts_with_fp_likelihood(alerts)
        return {
            "alerts": [a.model_dump() for a in alerts],
            "false_positive_summary": summarize_false_positive_review(alerts),
        }

    @app.get("/rules/tuning")
    def rules_tuning() -> dict:
        return build_rule_tuning_report()

    @app.get("/entities/sample")
    def entities_sample() -> dict:
        events, findings = _findings_for_all_samples()
        alerts = generate_alerts_from_findings(findings)
        annotate_alerts_with_fp_likelihood(alerts)
        profiles = build_entity_profiles(events, findings, alerts)
        return {
            "entities": [p.model_dump() for p in profiles],
            "entity_summary": summarize_entities(profiles),
        }

    @app.post("/entities/analyze")
    def entities_analyze(req: V2AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.log_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        enrich_findings_with_mitre(findings)
        for f in findings:
            score_finding(f)
        alerts = generate_alerts_from_findings(findings)
        annotate_alerts_with_fp_likelihood(alerts)
        profiles = build_entity_profiles(events, findings, alerts)
        return {
            "entities": [p.model_dump() for p in profiles],
            "entity_summary": summarize_entities(profiles),
        }

    @app.get("/kill-chain/sample")
    def kill_chain_sample() -> dict:
        _, findings = _findings_for_all_samples()
        correlated = correlate_findings(findings)
        return build_kill_chain_view(findings, correlated).model_dump()

    @app.post("/kill-chain/analyze")
    def kill_chain_analyze(req: V2AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.log_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        enrich_findings_with_mitre(findings)
        for f in findings:
            score_finding(f)
        correlated = correlate_findings(findings) if req.include_correlation else []
        return build_kill_chain_view(findings, correlated).model_dump()

    @app.get("/coverage/mitre")
    def coverage_mitre() -> dict:
        matrix = build_detection_coverage_matrix()
        return {
            "matrix": [e.model_dump() for e in matrix],
            "coverage_summary": summarize_coverage(matrix),
        }

    @app.post("/report/soc-json")
    def report_soc_json(req: AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.source_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        return build_soc_report(events, findings)

    @app.post("/report/soc-markdown")
    def report_soc_markdown(req: AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.source_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        soc = build_soc_report(events, findings)
        return {"markdown": build_soc_markdown_report(soc)}

    # ---------- v3 endpoints ----------

    @app.get("/datasets")
    def datasets_list() -> dict:
        return {"datasets": list_datasets()}

    @app.get("/datasets/{dataset_id}")
    def dataset_content(dataset_id: str) -> dict:
        meta = get_dataset_metadata(dataset_id)
        if meta is None:
            raise HTTPException(status_code=404, detail="dataset not found")
        try:
            from .config import resolve_dataset
            path = resolve_dataset(dataset_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "metadata": meta,
            "content": path.read_text(encoding="utf-8"),
        }

    @app.post("/datasets/analyze/{dataset_id}")
    def datasets_analyze(dataset_id: str) -> dict:
        try:
            return analyze_dataset(dataset_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="dataset not found")

    @app.get("/detection-engineering/rules")
    def detection_engineering_rules() -> dict:
        rules = load_detection_rules()
        return {
            "rule_quality": [rule_quality_score(r) for r in rules],
            "rule_explanations": [explain_rule(r) for r in rules],
        }

    @app.get("/detection-engineering/report")
    def detection_engineering_report() -> dict:
        return build_detection_engineering_report()

    @app.get("/detection-engineering/metrics")
    def detection_engineering_metrics() -> dict:
        report = build_detection_engineering_report()
        return {
            "rule_count": report["rule_count"],
            "average_quality_score": report["average_quality_score"],
            "quality_distribution": report["quality_distribution"],
            "coverage_summary": report["coverage_summary"],
            "evaluation_metrics": report["evaluation_metrics"],
            "summary": report["summary"],
        }

    @app.get("/metrics/evaluation")
    def metrics_evaluation() -> dict:
        evaluation = run_all_detection_scenarios()
        m = calculate_detection_metrics(evaluation)
        cat = calculate_category_metrics(evaluation)
        return {
            "metrics": m,
            "category_metrics": cat,
            "summary": summarize_metrics(m),
        }

    @app.get("/metrics/rules")
    def metrics_rules() -> dict:
        return {"rule_metrics": calculate_rule_metrics()}

    @app.get("/playbooks")
    def playbooks_list() -> dict:
        return {"playbooks": load_playbooks()}

    @app.post("/playbooks/recommend")
    def playbooks_recommend(req: V2AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.log_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        enrich_findings_with_mitre(findings)
        for f in findings:
            score_finding(f)
        recs = recommend_playbooks(findings)
        return {
            "recommendations": recs,
            "summary": summarize_playbook_recommendations(recs),
        }

    @app.get("/workflow/sample")
    def workflow_sample() -> dict:
        events, findings = _findings_for_all_samples()
        alerts = generate_alerts_from_findings(findings)
        annotate_alerts_with_fp_likelihood(alerts)
        correlated = correlate_findings(findings)
        from .cases import create_cases_from_alerts
        cases = create_cases_from_alerts(alerts, correlated)
        cases, steps = simulate_soc_workflow(cases, alerts)
        return {
            "cases": [c.model_dump() for c in cases],
            "steps": steps,
            "summary": generate_workflow_summary(cases),
        }

    @app.post("/workflow/simulate")
    def workflow_simulate(req: V2AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.log_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        enrich_findings_with_mitre(findings)
        for f in findings:
            score_finding(f)
        alerts = generate_alerts_from_findings(findings)
        annotate_alerts_with_fp_likelihood(alerts)
        correlated = correlate_findings(findings)
        from .cases import create_cases_from_alerts
        cases = create_cases_from_alerts(alerts, correlated)
        cases, steps = simulate_soc_workflow(cases, alerts)
        return {
            "cases": [c.model_dump() for c in cases],
            "steps": steps,
            "summary": generate_workflow_summary(cases),
        }

    @app.post("/report/executive")
    def report_executive(req: AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.source_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        return {"markdown": build_executive_report(events, findings)}

    @app.post("/report/analyst")
    def report_analyst(req: AnalyzeRequest) -> dict:
        try:
            events = parse_raw_logs(req.source_type, req.raw_logs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        findings = detect_events(events)
        return {"markdown": build_analyst_report(events, findings)}

    @app.post("/report/detection-engineering")
    def report_detection_engineering() -> dict:
        report = build_detection_engineering_report()
        return {"markdown": build_detection_engineering_report_markdown(report)}

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
                {"method": "GET", "path": "/triage/sample"},
                {"method": "POST", "path": "/triage/analyze"},
                {"method": "GET", "path": "/cases/sample"},
                {"method": "POST", "path": "/cases/from-analysis"},
                {"method": "POST", "path": "/false-positive/review"},
                {"method": "GET", "path": "/rules/tuning"},
                {"method": "GET", "path": "/entities/sample"},
                {"method": "POST", "path": "/entities/analyze"},
                {"method": "GET", "path": "/kill-chain/sample"},
                {"method": "POST", "path": "/kill-chain/analyze"},
                {"method": "GET", "path": "/coverage/mitre"},
                {"method": "POST", "path": "/report/soc-json"},
                {"method": "POST", "path": "/report/soc-markdown"},
                {"method": "GET", "path": "/datasets"},
                {"method": "GET", "path": "/datasets/{dataset_id}"},
                {"method": "POST", "path": "/datasets/analyze/{dataset_id}"},
                {"method": "GET", "path": "/detection-engineering/rules"},
                {"method": "GET", "path": "/detection-engineering/report"},
                {"method": "GET", "path": "/detection-engineering/metrics"},
                {"method": "GET", "path": "/metrics/evaluation"},
                {"method": "GET", "path": "/metrics/rules"},
                {"method": "GET", "path": "/playbooks"},
                {"method": "POST", "path": "/playbooks/recommend"},
                {"method": "GET", "path": "/workflow/sample"},
                {"method": "POST", "path": "/workflow/simulate"},
                {"method": "POST", "path": "/report/executive"},
                {"method": "POST", "path": "/report/analyst"},
                {"method": "POST", "path": "/report/detection-engineering"},
                {"method": "GET", "path": "/api/surface"},
            ]
        }

    return app


app = create_app()
