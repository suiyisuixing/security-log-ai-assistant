from app.evaluation import run_all_detection_scenarios
from app.metrics import (
    calculate_category_metrics,
    calculate_detection_metrics,
    calculate_rule_metrics,
    summarize_metrics,
)


def test_calculate_detection_metrics_keys():
    m = calculate_detection_metrics()
    for k in (
        "true_positives", "false_positives", "false_negatives",
        "precision", "recall", "f1_score",
        "scenario_count", "scenarios_passed", "scenarios_failed",
    ):
        assert k in m


def test_metrics_within_unit_range():
    m = calculate_detection_metrics()
    assert 0.0 <= m["precision"] <= 1.0
    assert 0.0 <= m["recall"] <= 1.0
    assert 0.0 <= m["f1_score"] <= 1.0


def test_f1_consistency():
    m = calculate_detection_metrics()
    p, r = m["precision"], m["recall"]
    if p + r > 0:
        expected = round(2 * p * r / (p + r), 4)
        assert abs(m["f1_score"] - expected) < 1e-6


def test_evaluation_metrics_recall_complete():
    """All v1 scenarios already pass, so recall must be 1.0 (no false negatives)."""
    m = calculate_detection_metrics()
    assert m["false_negatives"] == 0
    assert m["recall"] == 1.0


def test_calculate_rule_metrics_shape():
    rms = calculate_rule_metrics()
    assert isinstance(rms, list)
    assert len(rms) > 0
    for rm in rms:
        for k in ("rule_id", "true_positives", "false_positives",
                  "false_negatives", "precision", "recall", "f1_score"):
            assert k in rm


def test_calculate_category_metrics_has_known_categories():
    cat = calculate_category_metrics()
    assert isinstance(cat, dict)
    assert len(cat) > 0
    # at least one of these should appear
    keys = set(cat.keys())
    assert keys & {"auth", "web", "firewall", "dns", "mixed"}


def test_summarize_metrics_returns_string():
    m = calculate_detection_metrics()
    s = summarize_metrics(m)
    assert isinstance(s, str)
    assert "precision" in s


def test_metrics_use_passed_evaluation_argument():
    ev = run_all_detection_scenarios()
    m1 = calculate_detection_metrics(ev)
    m2 = calculate_detection_metrics(ev)
    assert m1 == m2
