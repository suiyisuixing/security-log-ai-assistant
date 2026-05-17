from app.detectors import detect_events
from app.false_positive import (
    annotate_alerts_with_fp_likelihood,
    estimate_false_positive_likelihood,
    summarize_false_positive_review,
)
from app.mitre import enrich_findings_with_mitre
from app.parsers import parse_log_file
from app.risk import score_finding
from app.schemas import Finding, ParsedEvent
from app.triage import generate_alerts_from_findings


def _ev(raw, user_agent=None):
    return ParsedEvent(source_type="web", raw=raw, user_agent=user_agent)


def test_sqlmap_ua_low_fp():
    f = Finding(
        rule_id="R008", rule_name="UA", description="x", severity="high",
        source_type="web", matched_events=[_ev("...", user_agent="sqlmap/1.6")],
        mitre_techniques=["T1190"],
    )
    score_finding(f)
    fp = estimate_false_positive_likelihood(f)
    assert fp.likelihood == "low"


def test_single_low_404_higher_fp():
    f = Finding(
        rule_id="R016", rule_name="404 burst", description="x", severity="low",
        source_type="web", matched_events=[_ev("x")],
    )
    score_finding(f)
    fp = estimate_false_positive_likelihood(f)
    assert fp.likelihood in ("medium", "high")


def test_brute_force_low_fp():
    evs = [ParsedEvent(source_type="auth", raw=f"l{i}", source_ip="198.51.100.23") for i in range(6)]
    f = Finding(
        rule_id="R001", rule_name="brute force", description="x", severity="high",
        source_type="auth", matched_events=evs, mitre_techniques=["T1110"],
    )
    score_finding(f)
    fp = estimate_false_positive_likelihood(f)
    assert fp.likelihood == "low"


def test_broad_pattern_medium_fp():
    f = Finding(
        rule_id="R020", rule_name="broad scan", description="x", severity="medium",
        source_type="web", matched_events=[_ev("x")],
    )
    score_finding(f)
    fp = estimate_false_positive_likelihood(f)
    assert fp.likelihood in ("medium", "high")


def test_annotate_alerts_adds_fp():
    events = parse_log_file("web_access.log")
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    alerts = generate_alerts_from_findings(findings)
    annotate_alerts_with_fp_likelihood(alerts)
    for a in alerts:
        assert a.false_positive is not None
        assert a.false_positive.likelihood in ("low", "medium", "high")


def test_summarize_false_positive_review_shape():
    events = parse_log_file("web_access.log")
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    alerts = generate_alerts_from_findings(findings)
    annotate_alerts_with_fp_likelihood(alerts)
    s = summarize_false_positive_review(alerts)
    assert "low_likelihood" in s
    assert "medium_likelihood" in s
    assert "high_likelihood" in s
    assert "review_recommended" in s
    assert s["low_likelihood"] + s["medium_likelihood"] + s["high_likelihood"] == len(alerts)


def test_fp_score_is_clamped():
    f = Finding(rule_id="R001", rule_name="x", description="x", severity="critical",
                source_type="auth", matched_events=[_ev("x")], mitre_techniques=["T1110"])
    score_finding(f)
    fp = estimate_false_positive_likelihood(f)
    assert 0 <= fp.score <= 100
