from app.detectors import detect_events
from app.parsers import parse_log_file
from app.risk import (
    score_finding,
    score_incident,
    severity_from_score,
    sort_findings_by_severity,
)
from app.schemas import Finding, ParsedEvent


def test_severity_from_score_thresholds():
    assert severity_from_score(95) == "critical"
    assert severity_from_score(75) == "high"
    assert severity_from_score(50) == "medium"
    assert severity_from_score(20) == "low"
    assert severity_from_score(5) == "informational"


def test_severity_from_score_zero():
    assert severity_from_score(0) == "informational"


def _make_finding(sev, n_events=1, n_tech=0):
    evs = [ParsedEvent(source_type="auth", raw=f"line {i}") for i in range(n_events)]
    return Finding(
        rule_id="X", rule_name="x", description="x", severity=sev,
        source_type="auth", matched_events=evs,
        mitre_techniques=[f"T0{i}" for i in range(n_tech)],
    )


def test_score_finding_low():
    f = _make_finding("low")
    s = score_finding(f)
    assert 15 <= s <= 35
    assert f.score == s


def test_score_finding_high_with_bonuses():
    f = _make_finding("high", n_events=5, n_tech=2)
    s = score_finding(f)
    assert s > 70


def test_score_finding_clamped_to_100():
    f = _make_finding("critical", n_events=20, n_tech=10)
    s = score_finding(f)
    assert s <= 100


def test_score_incident_empty_returns_zero():
    assert score_incident([]) == 0


def test_score_incident_uses_max_and_avg():
    fs = [_make_finding("high"), _make_finding("low"), _make_finding("medium")]
    s = score_incident(fs)
    assert 0 < s <= 100


def test_sort_findings_by_severity_orders_high_first():
    fs = [_make_finding("low"), _make_finding("critical"), _make_finding("medium")]
    for f in fs:
        score_finding(f)
    sorted_fs = sort_findings_by_severity(fs)
    assert sorted_fs[0].severity == "critical"
    assert sorted_fs[-1].severity == "low"


def test_real_findings_get_nonzero_scores():
    events = parse_log_file("web_access.log")
    findings = detect_events(events)
    for f in findings:
        score_finding(f)
    assert all(f.score > 0 for f in findings)
