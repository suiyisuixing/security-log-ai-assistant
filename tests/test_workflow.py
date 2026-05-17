import pytest

from app.cases import create_cases_from_alerts
from app.correlation import correlate_findings
from app.detectors import detect_events
from app.false_positive import annotate_alerts_with_fp_likelihood
from app.mitre import enrich_findings_with_mitre
from app.parsers import parse_log_file
from app.risk import score_finding
from app.schemas import Case
from app.triage import generate_alerts_from_findings
from app.workflow import (
    VALID_STATUSES,
    create_workflow_from_cases,
    generate_workflow_summary,
    simulate_soc_workflow,
    transition_case_status,
)


def _setup_cases(name="mixed_security_events.log"):
    events = parse_log_file(name)
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    alerts = generate_alerts_from_findings(findings)
    annotate_alerts_with_fp_likelihood(alerts)
    correlated = correlate_findings(findings)
    cases = create_cases_from_alerts(alerts, correlated)
    return cases, alerts


def test_valid_statuses():
    expected = {"new", "triaged", "investigating", "contained", "resolved", "false_positive"}
    assert set(VALID_STATUSES) == expected


def test_create_workflow_from_cases_initializes_status():
    cases, _ = _setup_cases()
    steps = create_workflow_from_cases(cases)
    assert len(steps) == len(cases)
    for c in cases:
        assert c.status == "new"


def test_transition_case_status_valid():
    c = Case(case_id="x", title="t", severity="high", status="new", created_at="now")
    step = transition_case_status(c, "triaged", "valid")
    assert c.status == "triaged"
    assert step["from_status"] == "new"
    assert step["to_status"] == "triaged"


def test_transition_case_status_invalid_status():
    c = Case(case_id="x", title="t", severity="high", status="new", created_at="now")
    with pytest.raises(ValueError):
        transition_case_status(c, "weird", "no")


def test_transition_case_status_invalid_transition():
    c = Case(case_id="x", title="t", severity="high", status="resolved", created_at="now")
    with pytest.raises(ValueError):
        transition_case_status(c, "investigating", "no")


def test_simulate_soc_workflow_high_severity_contained():
    cases, alerts = _setup_cases()
    cases, steps = simulate_soc_workflow(cases, alerts)
    high = [c for c in cases if c.severity in ("critical", "high") and c.status != "false_positive"]
    for c in high:
        assert c.status in ("contained", "false_positive")
    assert len(steps) >= len(cases)


def test_simulate_soc_workflow_steps_have_required_fields():
    cases, alerts = _setup_cases()
    _, steps = simulate_soc_workflow(cases, alerts)
    for s in steps:
        assert "case_id" in s
        assert "to_status" in s
        assert "reason" in s


def test_workflow_summary_shape():
    cases, alerts = _setup_cases()
    cases, _ = simulate_soc_workflow(cases, alerts)
    s = generate_workflow_summary(cases)
    assert s["total_cases"] == len(cases)
    for key in ("new", "triaged", "investigating", "contained", "resolved", "false_positive"):
        assert key in s


def test_workflow_handles_empty_cases():
    cases, steps = simulate_soc_workflow([], [])
    assert cases == []
    assert steps == []
