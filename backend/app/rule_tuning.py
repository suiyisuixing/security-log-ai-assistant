"""Detection rule tuning helpers.

Inspects evaluation results to surface rule performance, suggested
tuning, and detection gaps.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List

from .evaluation import run_all_detection_scenarios
from .schemas import (
    DetectionGap,
    EvaluationRunResponse,
    RulePerformance,
    TuningRecommendation,
)


def analyze_rule_performance(
    evaluation: EvaluationRunResponse,
) -> List[RulePerformance]:
    expected: Counter = Counter()
    matched: Counter = Counter()
    missed: Counter = Counter()
    over: Counter = Counter()
    for r in evaluation.results:
        for rid in r.expected_rule_ids:
            expected[rid] += 1
        for rid in r.matched_rule_ids:
            matched[rid] += 1
        for rid in r.missing_rule_ids:
            missed[rid] += 1
        for rid in r.unexpected_rule_ids:
            over[rid] += 1
    all_rule_ids = sorted(
        set(expected) | set(matched) | set(missed) | set(over)
    )
    out: List[RulePerformance] = []
    for rid in all_rule_ids:
        recommendation = ""
        if missed[rid] > 0 and matched[rid] == 0:
            recommendation = (
                "Rule never matched expected scenarios; review pattern, "
                "field extraction, or source_type filter."
            )
        elif missed[rid] > 0:
            recommendation = (
                "Rule fires inconsistently; review thresholds or window."
            )
        elif over[rid] > 0:
            recommendation = (
                "Rule matched in scenarios where it was not expected; "
                "add context filters to reduce noise."
            )
        else:
            recommendation = "Rule performing as expected; keep monitoring."
        out.append(
            RulePerformance(
                rule_id=rid,
                triggered_count=matched[rid],
                expected_count=expected[rid],
                missed_count=missed[rid],
                possible_overtrigger=over[rid],
                tuning_recommendation=recommendation,
            )
        )
    return out


def suggest_rule_tuning(
    performance: List[RulePerformance],
) -> List[TuningRecommendation]:
    recs: List[TuningRecommendation] = []
    for p in performance:
        if p.missed_count > 0 and p.triggered_count == 0:
            recs.append(
                TuningRecommendation(
                    rule_id=p.rule_id,
                    recommendation_type="new_rule_needed",
                    reason="Expected matches not produced by current rule.",
                    suggested_change=(
                        "Verify regex/threshold against the failing scenario(s) "
                        "or split into a more specific rule."
                    ),
                )
            )
        elif p.missed_count > 0:
            recs.append(
                TuningRecommendation(
                    rule_id=p.rule_id,
                    recommendation_type="threshold_adjustment",
                    reason="Rule misses some expected scenarios.",
                    suggested_change="Lower threshold or widen window_seconds.",
                )
            )
        elif p.possible_overtrigger > 0:
            recs.append(
                TuningRecommendation(
                    rule_id=p.rule_id,
                    recommendation_type="context_filter",
                    reason="Rule fires on unexpected scenarios.",
                    suggested_change=(
                        "Add a contextual filter (source_ip allowlist, "
                        "user-agent denylist, or status_code constraint)."
                    ),
                )
            )
    return recs


def identify_detection_gaps(
    evaluation: EvaluationRunResponse,
) -> List[DetectionGap]:
    gaps: List[DetectionGap] = []
    for r in evaluation.results:
        if r.missing_rule_ids:
            gaps.append(
                DetectionGap(
                    scenario_id=r.scenario_id,
                    missing_rule_ids=r.missing_rule_ids,
                    note=(
                        f"Scenario '{r.name}' expected rules "
                        f"{', '.join(r.missing_rule_ids)} but they did not fire."
                    ),
                )
            )
    return gaps


def build_rule_tuning_report() -> Dict:
    evaluation = run_all_detection_scenarios()
    performance = analyze_rule_performance(evaluation)
    recommendations = suggest_rule_tuning(performance)
    gaps = identify_detection_gaps(evaluation)
    return {
        "rule_performance": [p.model_dump() for p in performance],
        "tuning_recommendations": [r.model_dump() for r in recommendations],
        "detection_gaps": [g.model_dump() for g in gaps],
    }
