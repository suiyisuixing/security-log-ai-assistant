from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root():
    r = client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "security-log-ai-assistant"
    assert "ai_disclosure" in data
    assert "Claude" not in data["ai_disclosure"]
    assert "Anthropic" not in data["ai_disclosure"]


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_sample_logs_list():
    r = client.get("/sample-logs")
    assert r.status_code == 200
    names = r.json()["sample_logs"]
    assert "auth.log" in names
    assert "web_access.log" in names
    assert "firewall.log" in names
    assert "dns.log" in names
    assert "mixed_security_events.log" in names


def test_get_sample_log_known():
    r = client.get("/sample-logs/auth.log")
    assert r.status_code == 200
    assert r.json()["source_type"] == "auth"


def test_get_sample_log_unknown_rejected():
    r = client.get("/sample-logs/does-not-exist.log")
    assert r.status_code == 400


def test_get_sample_log_traversal_rejected():
    # A name containing ".." but no path separators still matches the
    # route segment and must be rejected by resolve_sample_log.
    r = client.get("/sample-logs/bad..name")
    assert r.status_code == 400


def test_parse_endpoint():
    r = client.post("/parse", json={
        "source_type": "auth",
        "raw_logs": "2026-05-10T08:01:11Z sshd[1001]: Accepted password for alice from 192.0.2.10 port 51322 ssh2",
    })
    assert r.status_code == 200
    events = r.json()
    assert len(events) == 1
    assert events[0]["user"] == "alice"


def test_parse_endpoint_unknown_source():
    r = client.post("/parse", json={"source_type": "bogus", "raw_logs": ""})
    assert r.status_code == 400


def test_analyze_endpoint():
    raw = "\n".join([
        "2026-05-10T08:05:11Z sshd[1004]: Failed password for invalid user admin from 198.51.100.23 port 51445 ssh2",
        "2026-05-10T08:05:12Z sshd[1005]: Failed password for invalid user admin from 198.51.100.23 port 51446 ssh2",
        "2026-05-10T08:05:13Z sshd[1006]: Failed password for invalid user admin from 198.51.100.23 port 51447 ssh2",
        "2026-05-10T08:05:14Z sshd[1007]: Failed password for invalid user admin from 198.51.100.23 port 51448 ssh2",
        "2026-05-10T08:05:15Z sshd[1008]: Failed password for invalid user admin from 198.51.100.23 port 51449 ssh2",
    ])
    r = client.post("/analyze", json={"source_type": "auth", "raw_logs": raw})
    assert r.status_code == 200
    rep = r.json()
    assert rep["total_findings"] >= 1


def test_analyze_sample_endpoint():
    r = client.post("/analyze-sample/web_access.log")
    assert r.status_code == 200
    assert r.json()["total_findings"] > 0


def test_analyze_sample_unknown():
    r = client.post("/analyze-sample/missing.log")
    assert r.status_code == 400


def test_rules_endpoint():
    r = client.get("/rules")
    assert r.status_code == 200
    assert len(r.json()["rules"]) >= 20


def test_mitre_endpoint():
    r = client.get("/mitre")
    assert r.status_code == 200
    techs = r.json()["techniques"]
    ids = [t["id"] for t in techs]
    assert "T1110" in ids


def test_report_markdown_endpoint():
    r = client.post("/report/markdown", json={"source_type": "auth", "raw_logs": "2026-05-10T08:07:01Z sudo[2001]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"})
    assert r.status_code == 200
    md = r.json()["markdown"]
    assert "Security Incident Report" in md


def test_report_json_endpoint():
    r = client.post("/report/json", json={"source_type": "auth", "raw_logs": "2026-05-10T08:07:01Z sudo[2001]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"})
    assert r.status_code == 200
    body = r.json()
    assert "findings" in body


def test_evaluation_scenarios_endpoint():
    r = client.get("/evaluation/scenarios")
    assert r.status_code == 200
    assert len(r.json()["scenarios"]) >= 12


def test_evaluation_run_endpoint_all_pass():
    r = client.post("/evaluation/run")
    assert r.status_code == 200
    body = r.json()
    assert body["failed"] == 0


def test_evaluation_run_one_endpoint():
    r = client.post("/evaluation/run-one/detect_xss_attempt")
    assert r.status_code == 200
    assert r.json()["passed"] is True


def test_evaluation_run_one_unknown():
    r = client.post("/evaluation/run-one/nope")
    assert r.status_code == 404


def test_dashboard_summary_endpoint():
    r = client.get("/dashboard/summary")
    assert r.status_code == 200
    s = r.json()
    assert s["total_findings"] > 0
    assert "by_severity" in s


def test_api_surface_endpoint():
    r = client.get("/api/surface")
    assert r.status_code == 200
    paths = [e["path"] for e in r.json()["endpoints"]]
    assert "/analyze" in paths
    assert "/health" in paths
