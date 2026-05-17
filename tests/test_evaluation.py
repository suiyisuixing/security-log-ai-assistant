from app.evaluation import load_scenarios, run_all_detection_scenarios, run_one_scenario


def test_load_scenarios_has_minimum_12():
    scenarios = load_scenarios()
    assert len(scenarios) >= 12


def test_run_all_scenarios_returns_results_for_each():
    resp = run_all_detection_scenarios()
    assert resp.total >= 12
    assert resp.total == len(resp.results)


def test_all_scenarios_pass():
    resp = run_all_detection_scenarios()
    failing = [r for r in resp.results if not r.passed]
    assert not failing, f"failing scenarios: {[(r.scenario_id, r.missing_rule_ids) for r in failing]}"


def test_run_one_scenario_known_id():
    r = run_one_scenario("detect_ssh_bruteforce")
    assert r is not None
    assert r.passed


def test_run_one_scenario_unknown_id_returns_none():
    assert run_one_scenario("nope") is None


def test_scenarios_use_only_known_source_types():
    valid = {"auth", "web", "firewall", "dns", "mixed"}
    for s in load_scenarios():
        assert s["source_type"] in valid
