from app.detection_engineering import (
    build_detection_engineering_report,
    detect_rule_gaps,
    explain_rule,
    generate_rule_improvement_plan,
    rule_quality_score,
    validate_rule_schema,
)
from app.detectors import load_detection_rules


RULES = load_detection_rules()


def test_rule_quality_score_for_real_rules():
    for r in RULES:
        q = rule_quality_score(r)
        assert 0 <= q["quality_score"] <= 100
        assert q["quality_level"] in ("excellent", "strong", "moderate", "weak", "invalid")
        assert q["strengths"] or q["weaknesses"]


def test_rule_quality_score_high_for_complete_rule():
    rule = next(r for r in RULES if r["id"] == "R001")
    q = rule_quality_score(rule)
    assert q["quality_score"] >= 75


def test_rule_quality_score_low_for_empty_rule():
    q = rule_quality_score({"id": "X"})
    assert q["quality_score"] < 50


def test_validate_rule_schema_valid_rule():
    rule = next(r for r in RULES if r["id"] == "R001")
    v = validate_rule_schema(rule)
    assert v["valid"] is True
    assert v["missing_fields"] == []


def test_validate_rule_schema_missing_fields():
    v = validate_rule_schema({"id": "X"})
    assert v["valid"] is False
    assert "name" in v["missing_fields"]
    assert "description" in v["missing_fields"]


def test_validate_rule_schema_warns_unknown_severity():
    v = validate_rule_schema(
        {"id": "X", "name": "x", "description": "y", "source_type": "auth",
         "match_type": "regex", "severity": "weird"}
    )
    assert any("severity" in w for w in v["warnings"])


def test_validate_rule_schema_warns_unknown_match_type():
    v = validate_rule_schema(
        {"id": "X", "name": "x", "description": "y", "source_type": "auth",
         "match_type": "ml-magic", "severity": "high"}
    )
    assert any("match_type" in w for w in v["warnings"])


def test_explain_rule_shape():
    rule = next(r for r in RULES if r["id"] == "R004")
    e = explain_rule(rule)
    assert e["rule_id"] == "R004"
    assert e["plain_english"]
    assert e["what_it_detects"]
    assert e["why_it_matters"]
    assert isinstance(e["likely_false_positives"], list)
    assert isinstance(e["recommended_triage"], list)


def test_detect_rule_gaps_returns_lists():
    gaps = detect_rule_gaps()
    assert "uncovered_techniques" in gaps
    assert "weakly_covered_techniques" in gaps
    assert "scenario_gaps" in gaps
    assert isinstance(gaps["uncovered_techniques"], list)


def test_build_detection_engineering_report_shape():
    rep = build_detection_engineering_report()
    for k in (
        "generated_at", "rule_count", "average_quality_score",
        "quality_distribution", "rule_quality", "rule_explanations",
        "coverage_matrix", "coverage_summary", "coverage_gaps",
        "evaluation_metrics", "rule_metrics", "category_metrics",
        "improvement_plan", "summary", "ai_disclosure",
    ):
        assert k in rep


def test_de_report_average_within_range():
    rep = build_detection_engineering_report()
    assert 0 <= rep["average_quality_score"] <= 100


def test_de_report_summary_nonempty():
    rep = build_detection_engineering_report()
    assert rep["summary"]


def test_de_report_disclosure_no_vendor_names():
    rep = build_detection_engineering_report()
    for banned in ("Claude", "Anthropic", "OpenAI", "GPT-4", "Gemini", "Ollama"):
        assert banned not in rep["ai_disclosure"]


def test_generate_rule_improvement_plan_returns_list():
    plan = generate_rule_improvement_plan()
    assert isinstance(plan, list)
