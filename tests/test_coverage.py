from app.coverage import build_detection_coverage_matrix, summarize_coverage
from app.mitre import load_mitre_mapping


def test_matrix_includes_all_mitre_techniques():
    matrix = build_detection_coverage_matrix()
    mapping_ids = set(load_mitre_mapping().keys())
    matrix_ids = {e.technique_id for e in matrix}
    assert matrix_ids == mapping_ids


def test_coverage_entry_has_strength():
    matrix = build_detection_coverage_matrix()
    for e in matrix:
        assert e.coverage_strength in ("strong", "partial", "none")


def test_covered_when_rules_present():
    matrix = build_detection_coverage_matrix()
    for e in matrix:
        if e.rule_ids:
            assert e.covered is True
            assert e.coverage_strength in ("strong", "partial")
        else:
            assert e.covered is False
            assert e.coverage_strength == "none"


def test_summary_shape():
    matrix = build_detection_coverage_matrix()
    s = summarize_coverage(matrix)
    assert s["total_techniques"] == len(matrix)
    assert 0.0 <= s["coverage_rate"] <= 1.0
    assert s["covered"] + s["uncovered"] == s["total_techniques"]
    assert "by_tactic" in s


def test_t1110_covered():
    matrix = build_detection_coverage_matrix()
    e = next(x for x in matrix if x.technique_id == "T1110")
    assert e.covered


def test_t1190_covered():
    matrix = build_detection_coverage_matrix()
    e = next(x for x in matrix if x.technique_id == "T1190")
    assert e.covered
