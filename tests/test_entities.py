from app.detectors import detect_events
from app.entities import build_entity_profiles, summarize_entities
from app.mitre import enrich_findings_with_mitre
from app.parsers import parse_log_file
from app.risk import score_finding
from app.triage import generate_alerts_from_findings


def _full_setup(name="mixed_security_events.log"):
    events = parse_log_file(name)
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    alerts = generate_alerts_from_findings(findings)
    return events, findings, alerts


def test_entity_profiles_include_src_ip():
    events, findings, alerts = _full_setup()
    profiles = build_entity_profiles(events, findings, alerts)
    types = {p.entity_type for p in profiles}
    assert "src_ip" in types


def test_entity_profiles_include_username():
    events, findings, alerts = _full_setup("auth.log")
    profiles = build_entity_profiles(events, findings, alerts)
    types = {p.entity_type for p in profiles}
    assert "username" in types


def test_entity_profiles_include_domain():
    events, findings, alerts = _full_setup("dns.log")
    profiles = build_entity_profiles(events, findings, alerts)
    types = {p.entity_type for p in profiles}
    assert "domain" in types


def test_entity_profiles_have_risk_score():
    events, findings, alerts = _full_setup()
    profiles = build_entity_profiles(events, findings, alerts)
    for p in profiles:
        assert 0 <= p.risk_score <= 100
        assert p.severity in ("informational", "low", "medium", "high", "critical")


def test_entity_profiles_sorted_high_first():
    events, findings, alerts = _full_setup()
    profiles = build_entity_profiles(events, findings, alerts)
    scores = [p.risk_score for p in profiles]
    assert scores == sorted(scores, reverse=True)


def test_entity_summary_shape():
    events, findings, alerts = _full_setup()
    profiles = build_entity_profiles(events, findings, alerts)
    s = summarize_entities(profiles)
    assert s["total_entities"] == len(profiles)
    assert s["high_risk_entities"] >= 0
    assert isinstance(s["top_entities"], list)
    assert "by_type" in s


def test_entity_first_last_seen_ordering():
    events, findings, alerts = _full_setup("firewall.log")
    profiles = build_entity_profiles(events, findings, alerts)
    for p in profiles:
        if p.first_seen and p.last_seen:
            assert p.first_seen <= p.last_seen


def test_high_risk_entity_has_findings():
    events, findings, alerts = _full_setup()
    profiles = build_entity_profiles(events, findings, alerts)
    high = [p for p in profiles if p.severity in ("high", "critical")]
    assert all(p.finding_count > 0 for p in high)
