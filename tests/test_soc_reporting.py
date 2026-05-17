from app.detectors import detect_events
from app.parsers import parse_log_file
from app.reporting import build_soc_markdown_report, build_soc_report


def _setup(name="mixed_security_events.log"):
    events = parse_log_file(name)
    findings = detect_events(events)
    return events, findings


def test_soc_report_top_level_keys():
    events, findings = _setup()
    report = build_soc_report(events, findings)
    for k in (
        "generated_at", "executive_summary", "overall_score", "overall_severity",
        "alerts", "queue_summary", "cases", "case_summary",
        "entities", "entity_summary", "coverage_matrix", "coverage_summary",
        "kill_chain", "timeline", "findings", "correlated_incidents",
        "false_positive_summary", "recommendations", "limitations", "ai_disclosure",
    ):
        assert k in report


def test_soc_report_alerts_carry_fp():
    events, findings = _setup()
    report = build_soc_report(events, findings)
    for a in report["alerts"]:
        assert a["false_positive"] is not None
        assert "likelihood" in a["false_positive"]


def test_soc_markdown_contains_executive_summary():
    events, findings = _setup()
    report = build_soc_report(events, findings)
    md = build_soc_markdown_report(report)
    assert "# SOC Analyst Report" in md
    assert "## Executive Summary" in md
    assert "## Alert Queue Summary" in md
    assert "## Incident Cases" in md
    assert "## Entity Risk Profiles" in md
    assert "## MITRE Coverage" in md
    assert "## Kill Chain View" in md
    assert "## Timeline" in md
    assert "## Findings" in md
    assert "## Recommendations" in md
    assert "## False Positive Notes" in md
    assert "## Limitations" in md


def test_soc_markdown_disclosure_present():
    events, findings = _setup()
    report = build_soc_report(events, findings)
    md = build_soc_markdown_report(report)
    assert "No external LLM" in md


def test_no_api_key_or_real_target_in_soc_report():
    events, findings = _setup()
    md = build_soc_markdown_report(build_soc_report(events, findings))
    for banned in ("sk-ant-", "AIza", "OPENAI_API_KEY", "google.com", "facebook.com"):
        assert banned not in md


def test_empty_findings_soc_report():
    events, _ = _setup()
    report = build_soc_report(events, [])
    assert report["total_findings"] == 0
    assert report["overall_score"] == 0
    assert report["alerts"] == []
    assert report["cases"] == []
