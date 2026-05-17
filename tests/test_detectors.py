from app.detectors import (
    apply_rule,
    detect_events,
    group_threshold_matches,
    load_detection_rules,
)
from app.parsers import parse_log_file, parse_raw_logs


RULES = load_detection_rules()


def _rule(rule_id):
    for r in RULES:
        if r["id"] == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not found")


def test_load_detection_rules_has_20_rules():
    assert len(RULES) >= 20


def test_rules_all_have_required_fields():
    for r in RULES:
        assert "id" in r and "name" in r and "match_type" in r and "severity" in r


def test_ssh_brute_force_detection():
    events = parse_log_file("auth.log")
    findings = apply_rule(_rule("R001"), events)
    assert len(findings) >= 1
    assert findings[0].rule_id == "R001"
    assert findings[0].severity == "high"


def test_invalid_user_detection():
    events = parse_log_file("auth.log")
    findings = apply_rule(_rule("R002"), events)
    assert len(findings) >= 5


def test_sudo_sensitive_file_detection():
    events = parse_log_file("auth.log")
    findings = apply_rule(_rule("R003"), events)
    assert any("shadow" in f.matched_events[0].raw for f in findings)


def test_sql_injection_detection():
    events = parse_log_file("web_access.log")
    findings = apply_rule(_rule("R004"), events)
    assert len(findings) >= 1


def test_xss_detection():
    events = parse_log_file("web_access.log")
    findings = apply_rule(_rule("R005"), events)
    assert len(findings) >= 1


def test_directory_traversal_detection():
    events = parse_log_file("web_access.log")
    findings = apply_rule(_rule("R006"), events)
    assert len(findings) >= 1


def test_admin_panel_probing_detection():
    events = parse_log_file("web_access.log")
    findings = apply_rule(_rule("R007"), events)
    assert len(findings) >= 1


def test_sqlmap_user_agent_detection():
    events = parse_log_file("web_access.log")
    findings = apply_rule(_rule("R008"), events)
    assert any("sqlmap" in f.matched_events[0].user_agent.lower() for f in findings)


def test_port_scan_detection():
    events = parse_log_file("firewall.log")
    findings = apply_rule(_rule("R010"), events)
    assert len(findings) >= 1
    assert findings[0].severity == "high"


def test_repeated_firewall_deny_detection():
    events = parse_log_file("firewall.log")
    findings = apply_rule(_rule("R011"), events)
    assert len(findings) >= 1


def test_suspicious_outbound_detection():
    events = parse_log_file("firewall.log")
    findings = apply_rule(_rule("R012"), events)
    assert len(findings) >= 1


def test_dga_detection():
    events = parse_log_file("dns.log")
    findings = apply_rule(_rule("R013"), events)
    assert len(findings) >= 1


def test_nxdomain_burst_detection():
    events = parse_log_file("dns.log")
    findings = apply_rule(_rule("R014"), events)
    assert len(findings) >= 1


def test_beacon_detection():
    events = parse_log_file("dns.log")
    findings = apply_rule(_rule("R015"), events)
    assert len(findings) >= 1


def test_web_404_burst_detection():
    events = parse_log_file("web_access.log")
    findings = apply_rule(_rule("R016"), events)
    assert len(findings) >= 1


def test_command_execution_probe_detection():
    events = parse_log_file("web_access.log")
    findings = apply_rule(_rule("R019"), events)
    assert len(findings) >= 1


def test_detect_events_on_all_logs():
    events = []
    for name in ("auth.log", "web_access.log", "firewall.log", "dns.log"):
        events.extend(parse_log_file(name))
    findings = detect_events(events)
    rule_ids = {f.rule_id for f in findings}
    assert "R001" in rule_ids
    assert "R004" in rule_ids
    assert "R010" in rule_ids
    assert "R013" in rule_ids


def test_group_threshold_matches_helper():
    events = parse_log_file("auth.log")
    matches = group_threshold_matches(
        events, pattern="Failed password", group_by="source_ip", threshold=5, window_seconds=120
    )
    assert len(matches) >= 1


def test_no_match_for_clean_logs():
    raw = "2026-05-10T08:00:01Z fw ALLOW src=192.0.2.10 dst=10.0.0.5 proto=TCP sport=1 dport=22"
    events = parse_raw_logs("firewall", raw)
    findings = apply_rule(_rule("R011"), events)
    assert findings == []
