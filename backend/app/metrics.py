"""Detection evaluation metrics: precision, recall, F1.

Computed against the synthetic detection scenarios in
data/evaluation/detection_scenarios.json. Definitions:

- TP: a rule_id in expected_rule_ids that also appears in matched_rule_ids
- FP: a rule_id in matched_rule_ids that is NOT in expected_rule_ids
- FN: a rule_id in expected_rule_ids that is NOT in matched_rule_ids

Per-rule, per-scenario, and aggregate metrics are exposed.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Optional

from .evaluation import run_all_detection_scenarios
from .schemas import EvaluationRunResponse


def _precision(tp: int, fp: int) -> float:
    if tp + fp == 0:
        return 0.0
    return round(tp / (tp + fp), 4)


def _recall(tp: int, fn: int) -> float:
    if tp + fn == 0:
        return 0.0
    return round(tp / (tp + fn), 4)


def _f1(p: float, r: float) -> float:
    if p + r == 0:
        return 0.0
    return round(2 * p * r / (p + r), 4)


def calculate_detection_metrics(
    evaluation: Optional[EvaluationRunResponse] = None,
) -> Dict:
    evaluation = evaluation if evaluation is not None else run_all_detection_scenarios()
    tp = fp = fn = 0
    for r in evaluation.results:
        expected = set(r.expected_rule_ids)
        matched = set(r.matched_rule_ids)
        tp += len(expected & matched)
        fp += len(matched - expected)
        fn += len(expected - matched)
    precision = _precision(tp, fp)
    recall = _recall(tp, fn)
    f1 = _f1(precision, recall)
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "scenario_count": evaluation.total,
        "scenarios_passed": evaluation.passed,
        "scenarios_failed": evaluation.failed,
    }


def calculate_rule_metrics(
    evaluation: Optional[EvaluationRunResponse] = None,
) -> List[Dict]:
    evaluation = evaluation if evaluation is not None else run_all_detection_scenarios()
    tp: Counter = Counter()
    fp: Counter = Counter()
    fn: Counter = Counter()
    rules_seen: set = set()
    for r in evaluation.results:
        expected = set(r.expected_rule_ids)
        matched = set(r.matched_rule_ids)
        for rid in expected & matched:
            tp[rid] += 1
            rules_seen.add(rid)
        for rid in matched - expected:
            fp[rid] += 1
            rules_seen.add(rid)
        for rid in expected - matched:
            fn[rid] += 1
            rules_seen.add(rid)
    out: List[Dict] = []
    for rid in sorted(rules_seen):
        p = _precision(tp[rid], fp[rid])
        r = _recall(tp[rid], fn[rid])
        out.append(
            {
                "rule_id": rid,
                "true_positives": tp[rid],
                "false_positives": fp[rid],
                "false_negatives": fn[rid],
                "precision": p,
                "recall": r,
                "f1_score": _f1(p, r),
            }
        )
    return out


def calculate_category_metrics(
    evaluation: Optional[EvaluationRunResponse] = None,
) -> Dict[str, Dict]:
    """Aggregate by source_type / rule prefix derived from scenario source_type."""
    from .evaluation import load_scenarios

    scenarios = {s["id"]: s for s in load_scenarios()}
    evaluation = evaluation if evaluation is not None else run_all_detection_scenarios()
    by_type: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0}
    )
    for r in evaluation.results:
        sc = scenarios.get(r.scenario_id, {})
        source = sc.get("source_type", "unknown")
        expected = set(r.expected_rule_ids)
        matched = set(r.matched_rule_ids)
        by_type[source]["tp"] += len(expected & matched)
        by_type[source]["fp"] += len(matched - expected)
        by_type[source]["fn"] += len(expected - matched)
    out: Dict[str, Dict] = {}
    for source, c in by_type.items():
        p = _precision(c["tp"], c["fp"])
        r = _recall(c["tp"], c["fn"])
        out[source] = {
            "true_positives": c["tp"],
            "false_positives": c["fp"],
            "false_negatives": c["fn"],
            "precision": p,
            "recall": r,
            "f1_score": _f1(p, r),
        }
    return out


def summarize_metrics(metrics: Dict) -> str:
    return (
        f"Detection evaluation over {metrics.get('scenario_count', 0)} scenarios: "
        f"TP={metrics['true_positives']}, FP={metrics['false_positives']}, "
        f"FN={metrics['false_negatives']}, precision={metrics['precision']:.3f}, "
        f"recall={metrics['recall']:.3f}, F1={metrics['f1_score']:.3f}."
    )
