from app.detectors import detect_events
from app.parsers import parse_log_file
from app.timeline import build_timeline


def test_timeline_builds_from_findings():
    events = parse_log_file("auth.log")
    findings = detect_events(events)
    timeline = build_timeline(findings)
    assert len(timeline) > 0


def test_timeline_entries_have_required_fields():
    events = parse_log_file("web_access.log")
    findings = detect_events(events)
    timeline = build_timeline(findings)
    for e in timeline:
        assert e.summary
        assert e.source_type in {"auth", "web", "firewall", "dns"}


def test_timeline_sorted_by_timestamp():
    events = parse_log_file("firewall.log")
    findings = detect_events(events)
    timeline = build_timeline(findings)
    timestamps = [e.timestamp for e in timeline if e.timestamp]
    assert timestamps == sorted(timestamps)


def test_timeline_empty_for_no_findings():
    assert build_timeline([]) == []
