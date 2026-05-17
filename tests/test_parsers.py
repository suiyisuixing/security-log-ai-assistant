from app.parsers import (
    parse_auth_log_line,
    parse_dns_log_line,
    parse_firewall_log_line,
    parse_log_file,
    parse_mixed_log_line,
    parse_raw_logs,
    parse_web_access_log_line,
    source_type_for_sample,
)


def test_parse_auth_failed_login():
    line = "2026-05-10T08:05:11Z sshd[1004]: Failed password for invalid user admin from 198.51.100.23 port 51445 ssh2"
    ev = parse_auth_log_line(line)
    assert ev is not None
    assert ev.source_type == "auth"
    assert ev.user == "admin"
    assert ev.source_ip == "198.51.100.23"
    assert ev.action == "failed_login"


def test_parse_auth_successful_login():
    line = "2026-05-10T08:01:11Z sshd[1001]: Accepted password for alice from 192.0.2.10 port 51322 ssh2"
    ev = parse_auth_log_line(line)
    assert ev is not None
    assert ev.user == "alice"
    assert ev.source_ip == "192.0.2.10"
    assert ev.action == "successful_login"


def test_parse_auth_sudo():
    line = "2026-05-10T08:07:01Z sudo[2001]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    ev = parse_auth_log_line(line)
    assert ev is not None
    assert ev.action == "sudo"
    assert ev.user == "alice"
    assert "shadow" in ev.extras["command"]


def test_parse_auth_empty_returns_none():
    assert parse_auth_log_line("") is None
    assert parse_auth_log_line("   ") is None


def test_parse_auth_unknown_returns_none():
    assert parse_auth_log_line("this is not an ssh line") is None


def test_parse_web_basic():
    line = '192.0.2.10 - - [10/May/2026:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    ev = parse_web_access_log_line(line)
    assert ev is not None
    assert ev.source_ip == "192.0.2.10"
    assert ev.method == "GET"
    assert ev.path == "/index.html"
    assert ev.status_code == 200
    assert ev.user_agent == "Mozilla/5.0"


def test_parse_web_with_sqlmap_ua():
    line = '198.51.100.23 - - [10/May/2026:08:01:12 +0000] "GET /products?id=1 HTTP/1.1" 500 200 "-" "sqlmap/1.6"'
    ev = parse_web_access_log_line(line)
    assert ev is not None
    assert "sqlmap" in ev.user_agent


def test_parse_web_invalid_returns_none():
    assert parse_web_access_log_line("not a web log") is None
    assert parse_web_access_log_line("") is None


def test_parse_firewall_allow():
    line = "2026-05-10T08:00:01Z fw ALLOW src=192.0.2.10 dst=10.0.0.5 proto=TCP sport=51322 dport=22"
    ev = parse_firewall_log_line(line)
    assert ev is not None
    assert ev.action == "ALLOW"
    assert ev.source_ip == "192.0.2.10"
    assert ev.dest_port == 22


def test_parse_firewall_deny():
    line = "2026-05-10T08:01:00Z fw DENY src=198.51.100.23 dst=10.0.0.5 proto=TCP sport=40001 dport=22"
    ev = parse_firewall_log_line(line)
    assert ev is not None
    assert ev.action == "DENY"


def test_parse_dns_normal():
    line = "2026-05-10T08:00:01Z dns client=192.0.2.10 query=example.com type=A response=NOERROR"
    ev = parse_dns_log_line(line)
    assert ev is not None
    assert ev.source_ip == "192.0.2.10"
    assert ev.query == "example.com"
    assert ev.response == "NOERROR"


def test_parse_dns_nxdomain():
    line = "2026-05-10T08:02:00Z dns client=10.0.0.30 query=nonexistent1.example type=A response=NXDOMAIN"
    ev = parse_dns_log_line(line)
    assert ev is not None
    assert ev.response == "NXDOMAIN"


def test_parse_mixed_dispatch_auth():
    line = "AUTH 2026-05-10T08:05:11Z sshd[1004]: Failed password for invalid user admin from 198.51.100.23 port 51445 ssh2"
    ev = parse_mixed_log_line(line)
    assert ev is not None and ev.source_type == "auth"


def test_parse_mixed_dispatch_web():
    line = 'WEB 198.51.100.23 - - [10/May/2026:08:01:12 +0000] "GET / HTTP/1.1" 200 200 "-" "ua"'
    ev = parse_mixed_log_line(line)
    assert ev is not None and ev.source_type == "web"


def test_parse_mixed_dispatch_fw():
    line = "FW 2026-05-10T08:01:00Z fw DENY src=198.51.100.23 dst=10.0.0.5 proto=TCP sport=40001 dport=22"
    ev = parse_mixed_log_line(line)
    assert ev is not None and ev.source_type == "firewall"


def test_parse_mixed_dispatch_dns():
    line = "DNS 2026-05-10T08:00:01Z dns client=192.0.2.10 query=example.com type=A response=NOERROR"
    ev = parse_mixed_log_line(line)
    assert ev is not None and ev.source_type == "dns"


def test_parse_raw_logs_unknown_source_raises():
    import pytest
    with pytest.raises(ValueError):
        parse_raw_logs("bogus", "anything")


def test_parse_raw_logs_skips_blank_lines():
    raw = "\n\n2026-05-10T08:00:01Z fw ALLOW src=192.0.2.10 dst=10.0.0.5 proto=TCP sport=1 dport=22\n\n"
    events = parse_raw_logs("firewall", raw)
    assert len(events) == 1


def test_parse_log_file_auth():
    events = parse_log_file("auth.log")
    assert len(events) > 10
    assert any(ev.action == "failed_login" for ev in events)


def test_parse_log_file_web():
    events = parse_log_file("web_access.log")
    assert len(events) > 10
    assert any(ev.path == "/index.html" for ev in events)


def test_parse_log_file_firewall():
    events = parse_log_file("firewall.log")
    assert len(events) > 10
    assert any(ev.action == "DENY" for ev in events)


def test_parse_log_file_dns():
    events = parse_log_file("dns.log")
    assert len(events) > 5
    assert any(ev.response == "NXDOMAIN" for ev in events)


def test_parse_log_file_mixed():
    events = parse_log_file("mixed_security_events.log")
    assert len(events) > 10
    types = {ev.source_type for ev in events}
    assert {"auth", "web", "firewall", "dns"}.issubset(types)


def test_source_type_for_sample_known():
    assert source_type_for_sample("auth.log") == "auth"
    assert source_type_for_sample("dns.log") == "dns"


def test_source_type_for_sample_unknown_raises():
    import pytest
    with pytest.raises(ValueError):
        source_type_for_sample("does-not-exist.log")
