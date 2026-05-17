from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


WEB_RAW = (
    '198.51.100.55 - - [03/Jun/2026:09:00:10 +0000] "GET /products?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 200 "-" "sqlmap/1.6"\n'
    '198.51.100.55 - - [03/Jun/2026:09:00:14 +0000] "GET /../../etc/passwd HTTP/1.1" 404 300 "-" "curl/7.85"'
)

AUTH_BRUTE_RAW = "\n".join(
    f"2026-06-02T08:00:0{i}Z sshd[400{i}]: Failed password for invalid user admin from 198.51.100.40 port 6000{i} ssh2"
    for i in range(6)
)


# --- datasets ---

def test_datasets_list():
    r = client.get("/datasets")
    assert r.status_code == 200
    ids = {d["id"] for d in r.json()["datasets"]}
    assert "brute_force_campaign" in ids
    assert "noisy_false_positive" in ids


def test_dataset_content_known():
    r = client.get("/datasets/web_attack_campaign")
    assert r.status_code == 200
    body = r.json()
    assert body["metadata"]["id"] == "web_attack_campaign"
    assert "content" in body
    assert "sqlmap" in body["content"]


def test_dataset_content_unknown_404():
    r = client.get("/datasets/does-not-exist")
    assert r.status_code == 404


def test_dataset_traversal_rejected():
    # A name containing ".." but no path separators reaches the handler
    # and must be rejected by metadata lookup (returns 404).
    r = client.get("/datasets/bad..name")
    assert r.status_code == 404


def test_dataset_analyze_brute_force():
    r = client.post("/datasets/analyze/brute_force_campaign")
    assert r.status_code == 200
    body = r.json()
    assert body["overall_severity"] in ("high", "critical")


def test_dataset_analyze_unknown_404():
    r = client.post("/datasets/analyze/nope")
    assert r.status_code == 404


# --- detection engineering ---

def test_detection_engineering_rules_endpoint():
    r = client.get("/detection-engineering/rules")
    assert r.status_code == 200
    body = r.json()
    assert "rule_quality" in body
    assert "rule_explanations" in body
    assert len(body["rule_quality"]) >= 20


def test_detection_engineering_report_endpoint():
    r = client.get("/detection-engineering/report")
    assert r.status_code == 200
    body = r.json()
    assert "average_quality_score" in body
    assert "evaluation_metrics" in body


def test_detection_engineering_metrics_endpoint():
    r = client.get("/detection-engineering/metrics")
    assert r.status_code == 200
    body = r.json()
    assert "rule_count" in body
    assert "evaluation_metrics" in body


# --- metrics ---

def test_metrics_evaluation_endpoint():
    r = client.get("/metrics/evaluation")
    assert r.status_code == 200
    body = r.json()
    assert "metrics" in body
    assert "category_metrics" in body
    assert "summary" in body


def test_metrics_rules_endpoint():
    r = client.get("/metrics/rules")
    assert r.status_code == 200
    body = r.json()
    assert "rule_metrics" in body
    assert len(body["rule_metrics"]) > 0


# --- playbooks ---

def test_playbooks_list_endpoint():
    r = client.get("/playbooks")
    assert r.status_code == 200
    body = r.json()
    assert len(body["playbooks"]) >= 8


def test_playbooks_recommend_endpoint_web():
    r = client.post(
        "/playbooks/recommend",
        json={"log_type": "web", "raw_logs": WEB_RAW, "include_correlation": True},
    )
    assert r.status_code == 200
    body = r.json()
    ids = {p["id"] for p in body["recommendations"]}
    assert ids & {"PB_WEB_ATTACK", "PB_SQL_INJECTION", "PB_DIRECTORY_TRAVERSAL"}


def test_playbooks_recommend_bad_log_type():
    r = client.post(
        "/playbooks/recommend",
        json={"log_type": "bogus", "raw_logs": "x"},
    )
    assert r.status_code == 400


# --- workflow ---

def test_workflow_sample_endpoint():
    r = client.get("/workflow/sample")
    assert r.status_code == 200
    body = r.json()
    assert "steps" in body
    assert "cases" in body
    assert "summary" in body


def test_workflow_simulate_endpoint():
    r = client.post(
        "/workflow/simulate",
        json={"log_type": "auth", "raw_logs": AUTH_BRUTE_RAW, "include_correlation": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["cases"]) >= 1


def test_workflow_simulate_bad_log_type():
    r = client.post(
        "/workflow/simulate",
        json={"log_type": "bogus", "raw_logs": "x"},
    )
    assert r.status_code == 400


# --- reports v3 ---

def test_report_executive_endpoint():
    r = client.post("/report/executive", json={"source_type": "web", "raw_logs": WEB_RAW})
    assert r.status_code == 200
    md = r.json()["markdown"]
    assert "# Executive Security Report" in md


def test_report_analyst_endpoint():
    r = client.post("/report/analyst", json={"source_type": "web", "raw_logs": WEB_RAW})
    assert r.status_code == 200
    md = r.json()["markdown"]
    assert "# SOC Analyst Investigation Report" in md


def test_report_detection_engineering_endpoint():
    r = client.post("/report/detection-engineering")
    assert r.status_code == 200
    md = r.json()["markdown"]
    assert "# Detection Engineering Report" in md


def test_report_executive_bad_source_type():
    r = client.post("/report/executive", json={"source_type": "bogus", "raw_logs": "x"})
    assert r.status_code == 400


# --- api surface includes v3 ---

def test_api_surface_includes_v3_endpoints():
    r = client.get("/api/surface")
    assert r.status_code == 200
    paths = {(e["method"], e["path"]) for e in r.json()["endpoints"]}
    for needed in (
        ("GET", "/datasets"),
        ("GET", "/datasets/{dataset_id}"),
        ("POST", "/datasets/analyze/{dataset_id}"),
        ("GET", "/detection-engineering/rules"),
        ("GET", "/detection-engineering/report"),
        ("GET", "/detection-engineering/metrics"),
        ("GET", "/metrics/evaluation"),
        ("GET", "/metrics/rules"),
        ("GET", "/playbooks"),
        ("POST", "/playbooks/recommend"),
        ("GET", "/workflow/sample"),
        ("POST", "/workflow/simulate"),
        ("POST", "/report/executive"),
        ("POST", "/report/analyst"),
        ("POST", "/report/detection-engineering"),
    ):
        assert needed in paths, f"{needed} missing from /api/surface"


# --- security boundaries on v3 endpoints ---

def test_v3_endpoints_no_authorization_header():
    for path in (
        "/datasets",
        "/detection-engineering/rules",
        "/metrics/evaluation",
        "/playbooks",
        "/workflow/sample",
    ):
        r = client.get(path)
        assert "Authorization" not in r.headers
        assert "authorization" not in r.headers


def test_v3_endpoints_no_external_indicators():
    for path in ("/datasets", "/playbooks", "/metrics/evaluation"):
        r = client.get(path)
        text = r.text
        for banned in ("api.openai.com", "anthropic.com", "googleapis.com"):
            assert banned not in text


def test_path_traversal_still_blocked():
    r = client.get("/sample-logs/bad..name")
    assert r.status_code == 400


def test_root_disclosure_no_vendor_names():
    r = client.get("/")
    body = r.json()
    for banned in ("Claude", "Anthropic", "OpenAI", "GPT-4", "Gemini", "Ollama"):
        assert banned not in body["ai_disclosure"]
