from app.detectors import detect_events
from app.mitre import enrich_findings_with_mitre
from app.parsers import parse_log_file
from app.playbooks import (
    load_playbooks,
    recommend_playbooks,
    summarize_playbook_recommendations,
)
from app.risk import score_finding


def _findings(name):
    events = parse_log_file(name)
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    return findings


def test_load_playbooks_has_eight():
    pbs = load_playbooks()
    assert len(pbs) >= 8


def test_playbooks_have_required_fields():
    pbs = load_playbooks()
    for pb in pbs:
        for field in ("id", "title", "mapped_rules", "mapped_mitre", "severity",
                       "steps", "containment", "evidence_to_collect", "limitations"):
            assert field in pb


def test_recommend_playbooks_brute_force():
    findings = _findings("auth.log")
    recs = recommend_playbooks(findings)
    ids = {p["id"] for p in recs}
    assert "PB_BRUTE_FORCE" in ids


def test_recommend_playbooks_web_attack():
    findings = _findings("web_access.log")
    recs = recommend_playbooks(findings)
    ids = {p["id"] for p in recs}
    assert "PB_WEB_ATTACK" in ids or "PB_SQL_INJECTION" in ids
    assert ids & {"PB_XSS", "PB_SQL_INJECTION", "PB_WEB_ATTACK", "PB_DIRECTORY_TRAVERSAL"}


def test_recommend_playbooks_dns_beacon():
    findings = _findings("dns.log")
    recs = recommend_playbooks(findings)
    ids = {p["id"] for p in recs}
    assert "PB_DNS_BEACON" in ids


def test_recommendations_carry_match_reasons():
    findings = _findings("auth.log")
    recs = recommend_playbooks(findings)
    for r in recs:
        assert r["match_reasons"]


def test_summarize_recommendations_shape():
    findings = _findings("mixed_security_events.log")
    recs = recommend_playbooks(findings)
    s = summarize_playbook_recommendations(recs)
    assert s["total_recommended"] == len(recs)
    assert "severity_counts" in s
    assert "top_techniques" in s


def test_playbook_steps_nonempty():
    pbs = load_playbooks()
    for pb in pbs:
        assert pb["steps"]
        assert pb["containment"]


def test_playbook_limitations_says_educational():
    pbs = load_playbooks()
    for pb in pbs:
        assert "educational" in pb["limitations"].lower() or "fake" in pb["limitations"].lower()


def test_no_real_target_in_playbooks():
    pbs = load_playbooks()
    banned = ["google.com", "facebook.com", "microsoft.com", "amazon.com", "apple.com"]
    for pb in pbs:
        text = " ".join(pb["steps"] + pb["containment"] + pb["evidence_to_collect"]).lower()
        for b in banned:
            assert b not in text
