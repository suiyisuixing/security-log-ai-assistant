"""Detection engineering layer.

Per-rule quality scoring, plain-English explanations, schema
validation, gap analysis, and improvement plans.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .coverage import build_detection_coverage_matrix, summarize_coverage
from .detectors import load_detection_rules
from .evaluation import load_scenarios, run_all_detection_scenarios
from .metrics import (
    calculate_category_metrics,
    calculate_detection_metrics,
    calculate_rule_metrics,
)
from .mitre import load_mitre_mapping
from .rule_tuning import (
    analyze_rule_performance,
    identify_detection_gaps,
    suggest_rule_tuning,
)


_REQUIRED_FIELDS = ("id", "name", "description", "source_type", "match_type", "severity")
_RECOMMENDED_FIELDS = ("mitre", "pattern")
_VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
_VALID_MATCH_TYPES = {"regex", "threshold", "port_scan", "path_scan", "dga", "beacon"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_rule_schema(rule: Dict) -> Dict:
    missing: List[str] = []
    warnings: List[str] = []
    for f in _REQUIRED_FIELDS:
        if not rule.get(f):
            missing.append(f)
    if rule.get("severity") and rule["severity"] not in _VALID_SEVERITIES:
        warnings.append(f"unknown severity: {rule.get('severity')}")
    if rule.get("match_type") and rule["match_type"] not in _VALID_MATCH_TYPES:
        warnings.append(f"unknown match_type: {rule.get('match_type')}")
    for f in _RECOMMENDED_FIELDS:
        if not rule.get(f):
            warnings.append(f"recommended field missing: {f}")
    if rule.get("match_type") == "threshold" and not rule.get("threshold"):
        warnings.append("threshold rules should declare a numeric threshold")
    return {"valid": not missing, "missing_fields": missing, "warnings": warnings}


def rule_quality_score(rule: Dict) -> Dict:
    strengths: List[str] = []
    weaknesses: List[str] = []
    suggestions: List[str] = []
    score = 0

    if rule.get("description"):
        score += 12
        strengths.append("Has a clear description.")
    else:
        weaknesses.append("Missing description.")
        suggestions.append("Add a one-line description explaining what the rule detects.")

    if rule.get("mitre"):
        score += 18
        strengths.append(f"Maps to MITRE {', '.join(rule['mitre'])}.")
    else:
        weaknesses.append("No MITRE technique mapping.")
        suggestions.append("Map this rule to one or more MITRE ATT&CK techniques.")

    if rule.get("severity") in _VALID_SEVERITIES:
        score += 10
        strengths.append(f"Severity '{rule['severity']}' is well defined.")
    else:
        weaknesses.append("Severity is missing or invalid.")
        suggestions.append("Choose one of informational/low/medium/high/critical.")

    if rule.get("match_type") in _VALID_MATCH_TYPES:
        score += 12
        strengths.append(f"Match type '{rule['match_type']}' is recognized.")
    else:
        weaknesses.append("Match type is invalid.")
        suggestions.append("Use one of regex/threshold/port_scan/path_scan/dga/beacon.")

    if rule.get("source_type"):
        score += 8
        strengths.append(f"Specific log source: {rule['source_type']}.")
    else:
        weaknesses.append("No log source specified.")
        suggestions.append("Add a source_type to constrain where the rule applies.")

    pattern = rule.get("pattern") or ""
    if pattern:
        score += 12
        strengths.append("Uses a concrete pattern.")
        if len(pattern) < 6:
            weaknesses.append("Pattern is short and may be overbroad.")
            suggestions.append("Tighten the pattern to reduce false positives.")
        if "(?i)" in pattern:
            score += 4
        if rule.get("match_type") == "regex" and ".*" in pattern and "?" not in pattern:
            weaknesses.append("Greedy '.*' without non-greedy modifier may overmatch.")
            suggestions.append("Prefer non-greedy '.*?' or bounded patterns.")
    elif rule.get("match_type") in {"regex", "threshold"}:
        weaknesses.append("No pattern defined for a pattern-based rule.")
        suggestions.append("Add a regex pattern that matches the attacker behavior.")

    if rule.get("match_type") == "threshold":
        if rule.get("threshold") and rule.get("window_seconds"):
            score += 10
            strengths.append(
                f"Threshold {rule['threshold']} over {rule['window_seconds']}s is explicit."
            )
        else:
            weaknesses.append("Threshold rule missing threshold or window_seconds.")
            suggestions.append("Set explicit threshold and window_seconds.")

    if rule.get("name") and len(rule["name"]) >= 4:
        score += 6
        strengths.append("Rule name is descriptive.")
    else:
        weaknesses.append("Rule name is missing or too short.")
        suggestions.append("Use a descriptive, action-oriented rule name.")

    score = max(0, min(100, score))
    if score >= 90:
        level = "excellent"
    elif score >= 75:
        level = "strong"
    elif score >= 50:
        level = "moderate"
    elif score >= 1:
        level = "weak"
    else:
        level = "invalid"

    return {
        "rule_id": rule.get("id", "?"),
        "quality_score": score,
        "quality_level": level,
        "strengths": strengths,
        "weaknesses": weaknesses,
        "improvement_suggestions": suggestions,
    }


_LOG_TYPE_PHRASE = {
    "auth": "authentication logs",
    "web": "HTTP request logs",
    "firewall": "firewall connection records",
    "dns": "DNS query logs",
    "mixed": "mixed multi-source logs",
}


def explain_rule(rule: Dict) -> Dict:
    log_phrase = _LOG_TYPE_PHRASE.get(rule.get("source_type", ""), "logs")
    mitre = rule.get("mitre", [])
    severity = rule.get("severity", "informational")
    name = rule.get("name", "unnamed rule")
    description = rule.get("description", "")
    plain = (
        f"This rule inspects {log_phrase} and fires when the platform observes the "
        f"following pattern: {description.lower() if description else name.lower()}."
    )
    what = description or "(not described)"
    why = (
        f"It maps to MITRE {', '.join(mitre)}, indicating "
        f"adversary behavior in those phases of an attack."
        if mitre
        else "It signals suspicious behavior, although no MITRE technique is mapped yet."
    )
    likely_fps: List[str] = []
    triage: List[str] = []
    rid = rule.get("id")
    if rid in {"R001", "R002"}:
        likely_fps.append("Forgotten password storms or scripted health checks.")
        triage.append("Confirm the source IP and check for MFA/legitimate retries.")
    if rid in {"R004", "R005", "R006"}:
        likely_fps.append("Internal security scanners or pentest exercises.")
        triage.append("Cross-reference with active engagement schedules.")
    if rid in {"R007", "R016", "R020"}:
        likely_fps.append("Search engine crawlers and benign 404 patterns.")
        triage.append("Cluster by user-agent before action.")
    if rid in {"R013", "R014", "R015"}:
        likely_fps.append("Misconfigured services generating noise.")
        triage.append("Inspect cadence and host process telemetry.")
    if rid in {"R010", "R011"}:
        likely_fps.append("Authorized vulnerability scanning.")
        triage.append("Verify whether the scan is part of a sanctioned program.")
    if not triage:
        triage.append("Triage according to severity and corroborate with other signals.")
    return {
        "rule_id": rid or "?",
        "plain_english": plain,
        "what_it_detects": what,
        "why_it_matters": why + f" Severity classification: {severity}.",
        "likely_false_positives": likely_fps,
        "recommended_triage": triage,
    }


def detect_rule_gaps(
    rules: Optional[List[Dict]] = None,
    mitre_mapping: Optional[Dict] = None,
    scenarios: Optional[List[Dict]] = None,
) -> Dict:
    rules = rules if rules is not None else load_detection_rules()
    matrix = build_detection_coverage_matrix(rules, mitre_mapping)
    uncovered = [e.technique_id for e in matrix if not e.covered]
    weakly = [e.technique_id for e in matrix if e.covered and e.coverage_strength == "partial"]
    evaluation = run_all_detection_scenarios()
    scenario_gaps = [
        {
            "scenario_id": r.scenario_id,
            "missing_rule_ids": r.missing_rule_ids,
        }
        for r in evaluation.results
        if r.missing_rule_ids
    ]
    return {
        "uncovered_techniques": uncovered,
        "weakly_covered_techniques": weakly,
        "scenario_gaps": scenario_gaps,
    }


def generate_rule_improvement_plan(
    rule_metrics: Optional[List[Dict]] = None,
) -> List[Dict]:
    if rule_metrics is None:
        rule_metrics = calculate_rule_metrics()
    plan: List[Dict] = []
    rules = {r["id"]: r for r in load_detection_rules()}
    for rm in rule_metrics:
        rid = rm["rule_id"]
        if rm["false_negatives"] > 0:
            plan.append(
                {
                    "rule_id": rid,
                    "priority": "high",
                    "issue": f"False negatives detected ({rm['false_negatives']}).",
                    "action": "Review pattern or threshold; the rule failed to fire when expected.",
                }
            )
        elif rm["false_positives"] > 0:
            plan.append(
                {
                    "rule_id": rid,
                    "priority": "medium",
                    "issue": f"False positives detected ({rm['false_positives']}).",
                    "action": "Add a contextual filter (UA, status code, IP allowlist) to reduce noise.",
                }
            )
        else:
            q = rule_quality_score(rules.get(rid, {"id": rid}))
            if q["quality_score"] < 75:
                plan.append(
                    {
                        "rule_id": rid,
                        "priority": "low",
                        "issue": f"Quality score below 75 ({q['quality_score']}).",
                        "action": "; ".join(q["improvement_suggestions"]) or "Improve metadata fields.",
                    }
                )
    return plan


def build_detection_engineering_report() -> Dict:
    rules = load_detection_rules()
    qualities = [rule_quality_score(r) for r in rules]
    explanations = [explain_rule(r) for r in rules]
    gaps = detect_rule_gaps(rules)
    evaluation = run_all_detection_scenarios()
    metrics = calculate_detection_metrics(evaluation)
    rule_metrics = calculate_rule_metrics(evaluation)
    category_metrics = calculate_category_metrics(evaluation)
    plan = generate_rule_improvement_plan(rule_metrics)
    distribution: Counter = Counter(q["quality_level"] for q in qualities)
    avg = round(sum(q["quality_score"] for q in qualities) / max(len(qualities), 1), 2)
    perf = analyze_rule_performance(evaluation)
    recommendations = suggest_rule_tuning(perf)
    gaps_from_perf = identify_detection_gaps(evaluation)
    summary = (
        f"Detection engineering report covers {len(rules)} rule(s); "
        f"average quality score {avg} ({distribution.most_common(1)[0][0]} dominant). "
        f"Precision={metrics['precision']:.3f}, recall={metrics['recall']:.3f}, "
        f"F1={metrics['f1_score']:.3f}. "
        f"Coverage gaps: {len(gaps['uncovered_techniques'])} uncovered, "
        f"{len(gaps['weakly_covered_techniques'])} weakly covered. "
        f"Improvement plan items: {len(plan)}."
    )
    return {
        "generated_at": _utc_now_iso(),
        "rule_count": len(rules),
        "average_quality_score": avg,
        "quality_distribution": dict(distribution),
        "rule_quality": qualities,
        "rule_explanations": explanations,
        "coverage_matrix": [e.model_dump() for e in build_detection_coverage_matrix(rules)],
        "coverage_summary": summarize_coverage(build_detection_coverage_matrix(rules)),
        "coverage_gaps": gaps,
        "evaluation_metrics": metrics,
        "rule_metrics": rule_metrics,
        "category_metrics": category_metrics,
        "improvement_plan": plan,
        "rule_performance": [p.model_dump() for p in perf],
        "tuning_recommendations": [r.model_dump() for r in recommendations],
        "detection_gaps": [g.model_dump() for g in gaps_from_perf],
        "summary": summary,
        "ai_disclosure": (
            "This report was produced by a local AI-assisted detection-engineering "
            "platform. The architecture, rules, and review process were directed "
            "by the author. No external LLM service was contacted."
        ),
    }
