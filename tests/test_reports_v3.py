from app.detection_engineering import build_detection_engineering_report
from app.detectors import detect_events
from app.parsers import parse_log_file
from app.reporting import (
    build_analyst_report,
    build_detection_engineering_report_markdown,
    build_executive_report,
)


def _setup(name="mixed_security_events.log"):
    events = parse_log_file(name)
    findings = detect_events(events)
    return events, findings


def test_executive_report_contains_executive_summary():
    events, findings = _setup()
    md = build_executive_report(events, findings)
    assert "# Executive Security Report" in md
    assert "## Executive Summary" in md
    assert "## Top Risks" in md
    assert "## Business Impact" in md
    assert "## High-Priority Cases" in md
    assert "## Recommended Executive Actions" in md
    assert "## Limitations" in md


def test_analyst_report_contains_required_sections():
    events, findings = _setup()
    md = build_analyst_report(events, findings)
    assert "# SOC Analyst Investigation Report" in md
    assert "## Findings" in md
    assert "## Evidence" in md
    assert "## Timeline" in md
    assert "## Cases" in md
    assert "## Entities" in md
    assert "## MITRE ATT&CK" in md
    assert "## Playbooks" in md
    assert "## Triage Steps" in md


def test_detection_engineering_report_contains_rule_quality():
    rep = build_detection_engineering_report()
    md = build_detection_engineering_report_markdown(rep)
    assert "# Detection Engineering Report" in md
    assert "## Rule Quality" in md
    assert "## Detection Coverage" in md
    assert "## Evaluation Metrics" in md
    assert "## False Positive Notes" in md
    assert "## Rule Tuning Suggestions" in md
    assert "## Detection Gaps" in md


def test_no_api_key_in_v3_reports():
    events, findings = _setup()
    contents = [
        build_executive_report(events, findings),
        build_analyst_report(events, findings),
        build_detection_engineering_report_markdown(
            build_detection_engineering_report()
        ),
    ]
    banned = ["sk-ant-", "AIza", "OPENAI_API_KEY", "Authorization:", "Bearer "]
    for md in contents:
        for b in banned:
            assert b not in md, f"banned token {b} in report"


def test_no_real_target_in_v3_reports():
    events, findings = _setup()
    contents = [
        build_executive_report(events, findings),
        build_analyst_report(events, findings),
    ]
    banned = ["google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com"]
    for md in contents:
        low = md.lower()
        for b in banned:
            assert b not in low


def test_executive_report_says_educational_or_synthetic():
    events, findings = _setup()
    md = build_executive_report(events, findings).lower()
    assert "synthetic" in md or "educational" in md or "no external" in md


def test_detection_engineering_report_disclosure():
    rep = build_detection_engineering_report()
    md = build_detection_engineering_report_markdown(rep)
    for banned in ("Claude", "Anthropic", "OpenAI", "GPT-4", "Gemini", "Ollama"):
        assert banned not in md
