from app.cases import classify_case_type, create_cases_from_alerts, summarize_cases
from app.correlation import correlate_findings
from app.detectors import detect_events
from app.mitre import enrich_findings_with_mitre
from app.parsers import parse_log_file
from app.risk import score_finding
from app.schemas import Alert
from app.triage import generate_alerts_from_findings


def _alerts_and_correlated(name="mixed_security_events.log"):
    events = parse_log_file(name)
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    alerts = generate_alerts_from_findings(findings)
    correlated = correlate_findings(findings)
    return alerts, correlated


def test_create_cases_basic():
    alerts, corr = _alerts_and_correlated()
    cases = create_cases_from_alerts(alerts, corr)
    assert len(cases) >= 1
    for c in cases:
        assert c.case_id.startswith("case-")


def test_case_summary_shape():
    alerts, corr = _alerts_and_correlated()
    cases = create_cases_from_alerts(alerts, corr)
    s = summarize_cases(cases)
    assert s["total_cases"] == len(cases)
    assert s["open_cases"] == len(cases)
    assert "severity_counts" in s
    assert "case_type_counts" in s
    assert "priority_counts" in s


def test_cases_contain_related_alerts():
    alerts, corr = _alerts_and_correlated()
    cases = create_cases_from_alerts(alerts, corr)
    all_alert_ids = {a.alert_id for a in alerts}
    in_cases = {aid for c in cases for aid in c.related_alert_ids}
    assert in_cases.issubset(all_alert_ids)


def test_classify_case_type_brute_force():
    a = Alert(alert_id="a", finding_id="f", rule_id="R001", title="t", severity="high", created_at="now")
    assert classify_case_type([a]) == "brute_force"


def test_classify_case_type_web_attack():
    a = Alert(alert_id="a", finding_id="f", rule_id="R004", title="t", severity="high", created_at="now")
    assert classify_case_type([a]) == "web_attack"


def test_classify_case_type_network_scan():
    a = Alert(alert_id="a", finding_id="f", rule_id="R010", title="t", severity="high", created_at="now")
    assert classify_case_type([a]) == "network_scan"


def test_classify_case_type_dns_beacon():
    a = Alert(alert_id="a", finding_id="f", rule_id="R015", title="t", severity="high", created_at="now")
    assert classify_case_type([a]) == "dns_beacon"


def test_classify_case_type_privilege_escalation():
    a = Alert(alert_id="a", finding_id="f", rule_id="R003", title="t", severity="high", created_at="now")
    assert classify_case_type([a]) == "privilege_escalation"


def test_classify_case_type_multistage():
    a1 = Alert(alert_id="a1", finding_id="f", rule_id="R001", title="t", severity="high", created_at="now")
    a2 = Alert(alert_id="a2", finding_id="f", rule_id="R004", title="t", severity="high", created_at="now")
    assert classify_case_type([a1, a2]) == "multi_stage_incident"


def test_classify_case_type_unknown():
    assert classify_case_type([]) == "unknown"


def test_cases_have_recommended_actions():
    alerts, corr = _alerts_and_correlated()
    cases = create_cases_from_alerts(alerts, corr)
    for c in cases:
        assert c.recommended_actions


def test_cases_sorted_high_first():
    alerts, corr = _alerts_and_correlated()
    cases = create_cases_from_alerts(alerts, corr)
    sev_order = ["informational", "low", "medium", "high", "critical"]
    ranks = [sev_order.index(c.severity) for c in cases]
    assert ranks == sorted(ranks, reverse=True)
