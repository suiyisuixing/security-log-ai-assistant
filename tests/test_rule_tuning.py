from app.evaluation import run_all_detection_scenarios
from app.rule_tuning import (
    analyze_rule_performance,
    build_rule_tuning_report,
    identify_detection_gaps,
    suggest_rule_tuning,
)


def test_analyze_rule_performance_shape():
    ev = run_all_detection_scenarios()
    perf = analyze_rule_performance(ev)
    assert len(perf) > 0
    for p in perf:
        assert p.rule_id
        assert p.triggered_count >= 0
        assert p.expected_count >= 0
        assert p.missed_count >= 0
        assert p.tuning_recommendation


def test_identify_detection_gaps_empty_when_all_pass():
    ev = run_all_detection_scenarios()
    gaps = identify_detection_gaps(ev)
    # In v1, all scenarios pass; v2 should not regress this.
    assert gaps == []


def test_suggest_rule_tuning_returns_list():
    ev = run_all_detection_scenarios()
    perf = analyze_rule_performance(ev)
    recs = suggest_rule_tuning(perf)
    assert isinstance(recs, list)


def test_build_rule_tuning_report_shape():
    rep = build_rule_tuning_report()
    assert "rule_performance" in rep
    assert "tuning_recommendations" in rep
    assert "detection_gaps" in rep


def test_rule_performance_includes_expected_rules():
    rep = build_rule_tuning_report()
    rule_ids = {p["rule_id"] for p in rep["rule_performance"]}
    for must in ("R001", "R004", "R010"):
        assert must in rule_ids
