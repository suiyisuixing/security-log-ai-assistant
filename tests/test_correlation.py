from app.correlation import correlate_findings
from app.detectors import detect_events
from app.parsers import parse_log_file
from app.risk import score_finding


def test_correlate_findings_groups_by_actor():
    events = parse_log_file("web_access.log")
    findings = detect_events(events)
    for f in findings:
        score_finding(f)
    incidents = correlate_findings(findings)
    assert len(incidents) >= 1
    for inc in incidents:
        assert inc.actor
        assert inc.score >= 0


def test_correlated_incidents_have_unique_ids():
    events = parse_log_file("firewall.log")
    findings = detect_events(events)
    for f in findings:
        score_finding(f)
    incidents = correlate_findings(findings)
    ids = [i.incident_id for i in incidents]
    assert len(ids) == len(set(ids))


def test_correlate_findings_empty():
    assert correlate_findings([]) == []


def test_correlation_sorted_by_score_desc():
    events = parse_log_file("auth.log")
    findings = detect_events(events)
    for f in findings:
        score_finding(f)
    incidents = correlate_findings(findings)
    scores = [i.score for i in incidents]
    assert scores == sorted(scores, reverse=True)
