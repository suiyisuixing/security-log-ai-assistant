from app.correlation import correlate_findings
from app.detectors import detect_events
from app.kill_chain import build_kill_chain_view, map_findings_to_kill_chain
from app.mitre import enrich_findings_with_mitre
from app.parsers import parse_log_file
from app.risk import score_finding


def _findings(name="mixed_security_events.log"):
    events = parse_log_file(name)
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    return findings


def test_map_findings_to_kill_chain_has_buckets():
    findings = _findings()
    buckets = map_findings_to_kill_chain(findings)
    # Buckets is a dict with kill chain stage keys.
    assert "reconnaissance" in buckets
    assert "credential_access" in buckets


def test_build_kill_chain_view_observes_stages():
    findings = _findings()
    correlated = correlate_findings(findings)
    view = build_kill_chain_view(findings, correlated)
    assert view.observed_stage_count > 0
    assert view.highest_stage
    assert view.narrative


def test_kill_chain_view_has_all_canonical_stages():
    findings = _findings()
    view = build_kill_chain_view(findings)
    stage_names = [s.stage for s in view.stages]
    for s in ("reconnaissance", "initial_access", "execution", "credential_access", "command_and_control"):
        assert s in stage_names


def test_kill_chain_view_observed_flag_matches_count():
    findings = _findings()
    view = build_kill_chain_view(findings)
    for s in view.stages:
        if s.observed:
            assert s.finding_count > 0
        else:
            assert s.finding_count == 0


def test_empty_findings_view():
    view = build_kill_chain_view([])
    assert view.observed_stage_count == 0
    assert view.highest_stage is None
    assert "No kill-chain" in view.narrative


def test_credential_access_observed_with_brute_force():
    findings = _findings("auth.log")
    view = build_kill_chain_view(findings)
    stage_map = {s.stage: s for s in view.stages}
    assert stage_map["credential_access"].observed
