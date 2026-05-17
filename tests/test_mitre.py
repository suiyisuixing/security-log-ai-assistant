from app.detectors import detect_events
from app.mitre import enrich_findings_with_mitre, list_techniques, load_mitre_mapping
from app.parsers import parse_log_file


def test_load_mitre_mapping_has_minimum_techniques():
    mapping = load_mitre_mapping()
    required = {"T1110", "T1059", "T1190", "T1087", "T1046", "T1021", "T1071", "T1105", "T1003", "T1055", "T1566", "T1595"}
    assert required.issubset(set(mapping.keys()))


def test_list_techniques_sorted():
    techs = list_techniques()
    ids = [t["id"] for t in techs]
    assert ids == sorted(ids)


def test_mitre_enrichment_adds_details():
    events = parse_log_file("auth.log")
    findings = detect_events(events)
    enriched = enrich_findings_with_mitre(findings)
    assert any(f.mitre_details for f in enriched)


def test_each_mitre_technique_has_name_and_tactic():
    mapping = load_mitre_mapping()
    for tid, info in mapping.items():
        assert info["id"] == tid
        assert info["name"]
        assert info["tactic"]
        assert info["description"]


def test_no_internet_fetch_in_mitre_module():
    import inspect
    from app import mitre
    src = inspect.getsource(mitre)
    assert "urllib" not in src
    assert "requests" not in src
    assert "http://" not in src
    assert "https://" not in src
