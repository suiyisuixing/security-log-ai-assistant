from app.detectors import detect_events
from app.parsers import parse_log_file
from app.reporting import build_incident_report, build_markdown_report


def test_build_incident_report_full():
    events = parse_log_file("mixed_security_events.log")
    findings = detect_events(events)
    report = build_incident_report(findings, total_events=len(events))
    assert report.total_events == len(events)
    assert report.total_findings == len(findings)
    assert 0 <= report.overall_score <= 100
    assert report.overall_severity in {"informational", "low", "medium", "high", "critical"}
    assert report.ai_summary


def test_build_markdown_report_contains_sections():
    events = parse_log_file("auth.log")
    findings = detect_events(events)
    report = build_incident_report(findings, total_events=len(events))
    md = build_markdown_report(report)
    assert "# Security Incident Report" in md
    assert "## AI Summary" in md
    assert "## Findings" in md
    assert "## Timeline" in md
    assert "## Correlated Incidents" in md


def test_markdown_disclosure_present():
    report = build_incident_report([], total_events=0)
    md = build_markdown_report(report)
    assert "No external LLM" in md


def test_no_external_in_report():
    import inspect
    from app import reporting
    src = inspect.getsource(reporting)
    assert "requests" not in src
    assert "urlopen" not in src


def test_empty_report():
    report = build_incident_report([], total_events=0)
    assert report.total_findings == 0
    assert report.overall_score == 0
    assert report.overall_severity == "informational"
