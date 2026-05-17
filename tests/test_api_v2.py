from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


WEB_RAW = (
    '198.51.100.23 - - [10/May/2026:08:01:12 +0000] "GET /products?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 200 "-" "sqlmap/1.6"\n'
    '198.51.100.23 - - [10/May/2026:08:01:14 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 320 "-" "Mozilla/5.0"'
)

AUTH_BRUTE_RAW = "\n".join(
    f"2026-05-10T08:05:1{i}Z sshd[100{i}]: Failed password for invalid user admin from 198.51.100.23 port 5144{i} ssh2"
    for i in range(5)
)


def test_triage_sample_endpoint():
    r = client.get("/triage/sample")
    assert r.status_code == 200
    body = r.json()
    assert "alerts" in body
    assert "queue_summary" in body
    assert body["queue_summary"]["total_alerts"] == len(body["alerts"])


def test_triage_analyze_endpoint():
    r = client.post("/triage/analyze", json={"log_type": "web", "raw_logs": WEB_RAW, "include_correlation": True})
    assert r.status_code == 200
    body = r.json()
    assert "alerts" in body
    assert "queue_summary" in body
    assert "findings" in body
    assert "risk_summary" in body


def test_triage_analyze_bad_source_type():
    r = client.post("/triage/analyze", json={"log_type": "bogus", "raw_logs": "x"})
    assert r.status_code == 400


def test_cases_sample_endpoint():
    r = client.get("/cases/sample")
    assert r.status_code == 200
    body = r.json()
    assert "cases" in body
    assert "case_summary" in body


def test_cases_from_analysis_endpoint():
    r = client.post("/cases/from-analysis", json={"log_type": "auth", "raw_logs": AUTH_BRUTE_RAW, "include_correlation": True})
    assert r.status_code == 200
    body = r.json()
    assert len(body["cases"]) >= 1


def test_false_positive_review_endpoint():
    r = client.post("/false-positive/review", json={"log_type": "web", "raw_logs": WEB_RAW})
    assert r.status_code == 200
    body = r.json()
    assert "alerts" in body
    assert "false_positive_summary" in body
    for a in body["alerts"]:
        assert a["false_positive"] is not None


def test_rules_tuning_endpoint():
    r = client.get("/rules/tuning")
    assert r.status_code == 200
    body = r.json()
    assert "rule_performance" in body
    assert "tuning_recommendations" in body
    assert "detection_gaps" in body


def test_entities_sample_endpoint():
    r = client.get("/entities/sample")
    assert r.status_code == 200
    body = r.json()
    assert "entities" in body
    assert "entity_summary" in body


def test_entities_analyze_endpoint():
    r = client.post("/entities/analyze", json={"log_type": "auth", "raw_logs": AUTH_BRUTE_RAW})
    assert r.status_code == 200
    body = r.json()
    assert len(body["entities"]) >= 1


def test_kill_chain_sample_endpoint():
    r = client.get("/kill-chain/sample")
    assert r.status_code == 200
    body = r.json()
    assert "stages" in body
    assert body["observed_stage_count"] > 0


def test_kill_chain_analyze_endpoint():
    r = client.post("/kill-chain/analyze", json={"log_type": "auth", "raw_logs": AUTH_BRUTE_RAW, "include_correlation": True})
    assert r.status_code == 200
    body = r.json()
    stages = {s["stage"] for s in body["stages"]}
    assert "credential_access" in stages


def test_coverage_mitre_endpoint():
    r = client.get("/coverage/mitre")
    assert r.status_code == 200
    body = r.json()
    assert "matrix" in body
    assert "coverage_summary" in body


def test_report_soc_json_endpoint():
    r = client.post("/report/soc-json", json={"source_type": "web", "raw_logs": WEB_RAW})
    assert r.status_code == 200
    body = r.json()
    assert "executive_summary" in body
    assert "kill_chain" in body
    assert "coverage_matrix" in body


def test_report_soc_markdown_endpoint():
    r = client.post("/report/soc-markdown", json={"source_type": "web", "raw_logs": WEB_RAW})
    assert r.status_code == 200
    md = r.json()["markdown"]
    assert "# SOC Analyst Report" in md
    assert "## MITRE Coverage" in md


def test_api_surface_includes_v2_endpoints():
    r = client.get("/api/surface")
    assert r.status_code == 200
    paths = {(e["method"], e["path"]) for e in r.json()["endpoints"]}
    for needed in (
        ("GET", "/triage/sample"),
        ("POST", "/triage/analyze"),
        ("GET", "/cases/sample"),
        ("POST", "/cases/from-analysis"),
        ("POST", "/false-positive/review"),
        ("GET", "/rules/tuning"),
        ("GET", "/entities/sample"),
        ("POST", "/entities/analyze"),
        ("GET", "/kill-chain/sample"),
        ("POST", "/kill-chain/analyze"),
        ("GET", "/coverage/mitre"),
        ("POST", "/report/soc-json"),
        ("POST", "/report/soc-markdown"),
    ):
        assert needed in paths, f"{needed} missing"


def test_v2_endpoints_path_traversal_blocked():
    # The v2 endpoints that read sample logs share the same resolve_sample_log.
    r = client.get("/sample-logs/bad..name")
    assert r.status_code == 400


def test_v2_no_authorization_header_in_responses():
    for path in ("/triage/sample", "/cases/sample", "/coverage/mitre", "/rules/tuning"):
        r = client.get(path)
        assert "Authorization" not in r.headers
        assert "authorization" not in r.headers


def test_v2_endpoints_no_external_indicators_in_response_text():
    r = client.get("/triage/sample")
    text = r.text
    for banned in ("api.openai.com", "anthropic.com", "googleapis.com"):
        assert banned not in text
