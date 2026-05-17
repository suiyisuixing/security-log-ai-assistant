from app.detectors import detect_events
from app.mitre import enrich_findings_with_mitre
from app.parsers import parse_log_file
from app.risk import score_finding
from app.schemas import Alert, Finding, ParsedEvent
from app.triage import (
    assign_priority,
    filter_alerts,
    generate_alerts_from_findings,
    summarize_alert_queue,
)


def _full_findings():
    events = []
    for n in ("auth.log", "web_access.log", "firewall.log", "dns.log"):
        events.extend(parse_log_file(n))
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    return findings


def test_generate_alerts_from_findings_basic():
    findings = _full_findings()
    alerts = generate_alerts_from_findings(findings)
    assert len(alerts) == len(findings)
    assert all(a.alert_id.startswith("alert-") for a in alerts)
    assert all(a.status == "open" for a in alerts)


def test_assign_priority_critical():
    alert = Alert(alert_id="x", finding_id="f", rule_id="R", title="t", severity="critical", risk_score=95, created_at="now")
    assert assign_priority(alert) == "P1"


def test_assign_priority_high():
    alert = Alert(alert_id="x", finding_id="f", rule_id="R", title="t", severity="high", risk_score=75, created_at="now")
    assert assign_priority(alert) == "P2"


def test_assign_priority_medium():
    alert = Alert(alert_id="x", finding_id="f", rule_id="R", title="t", severity="medium", risk_score=50, created_at="now")
    assert assign_priority(alert) == "P3"


def test_assign_priority_low():
    alert = Alert(alert_id="x", finding_id="f", rule_id="R", title="t", severity="low", risk_score=10, created_at="now")
    assert assign_priority(alert) == "P4"


def test_assign_priority_score_only_overrides():
    alert = Alert(alert_id="x", finding_id="f", rule_id="R", title="t", severity="low", risk_score=95, created_at="now")
    assert assign_priority(alert) == "P1"


def test_alerts_have_priority_set():
    findings = _full_findings()
    alerts = generate_alerts_from_findings(findings)
    for a in alerts:
        assert a.priority in ("P1", "P2", "P3", "P4")


def test_alerts_carry_mitre():
    findings = _full_findings()
    alerts = generate_alerts_from_findings(findings)
    assert any(a.mitre_techniques for a in alerts)


def test_summarize_alert_queue_shape():
    findings = _full_findings()
    alerts = generate_alerts_from_findings(findings)
    s = summarize_alert_queue(alerts)
    assert s["total_alerts"] == len(alerts)
    assert s["open_alerts"] == len(alerts)
    assert "priority_counts" in s
    assert "severity_counts" in s
    assert isinstance(s["top_source_ips"], list)
    assert isinstance(s["top_mitre_techniques"], list)


def test_summarize_alert_queue_empty():
    s = summarize_alert_queue([])
    assert s["total_alerts"] == 0
    assert s["open_alerts"] == 0


def test_filter_alerts_by_severity():
    findings = _full_findings()
    alerts = generate_alerts_from_findings(findings)
    high = filter_alerts(alerts, severity="high")
    assert all(a.severity == "high" for a in high)


def test_filter_alerts_by_priority():
    findings = _full_findings()
    alerts = generate_alerts_from_findings(findings)
    p2 = filter_alerts(alerts, priority="P2")
    assert all(a.priority == "P2" for a in p2)


def test_filter_alerts_by_status():
    findings = _full_findings()
    alerts = generate_alerts_from_findings(findings)
    open_alerts = filter_alerts(alerts, status="open")
    assert len(open_alerts) == len(alerts)


def test_alerts_recommended_action_nonempty():
    findings = _full_findings()
    alerts = generate_alerts_from_findings(findings)
    assert all(a.recommended_action for a in alerts)
