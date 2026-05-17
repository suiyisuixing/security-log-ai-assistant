"""Detection evaluation suite. Runs scenarios and reports pass/fail.

v3 additions: dataset manifest loading and per-dataset analysis.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from .config import DATASET_MANIFEST_FILE, EVALUATION_FILE, resolve_dataset
from .detectors import detect_events, load_detection_rules
from .mitre import enrich_findings_with_mitre
from .parsers import parse_raw_logs
from .risk import score_finding, score_incident, severity_from_score
from .schemas import EvaluationRunResponse, ScenarioRunResult


def load_scenarios(path: Optional[Path] = None) -> List[Dict]:
    p = path or EVALUATION_FILE
    return json.loads(p.read_text(encoding="utf-8")).get("scenarios", [])


def _run_one(scenario: Dict, rules: List[Dict]) -> ScenarioRunResult:
    raw = "\n".join(scenario["log_lines"])
    events = parse_raw_logs(scenario["source_type"], raw)
    findings = detect_events(events, rules)
    matched_ids = sorted({f.rule_id for f in findings})
    expected = scenario["expected_rule_ids"]
    missing = sorted(set(expected) - set(matched_ids))
    unexpected = sorted(set(matched_ids) - set(expected))
    passed = not missing
    return ScenarioRunResult(
        scenario_id=scenario["id"],
        name=scenario["name"],
        expected_rule_ids=expected,
        matched_rule_ids=matched_ids,
        missing_rule_ids=missing,
        unexpected_rule_ids=unexpected,
        passed=passed,
    )


def run_all_detection_scenarios(
    scenarios_path: Optional[Path] = None,
) -> EvaluationRunResponse:
    scenarios = load_scenarios(scenarios_path)
    rules = load_detection_rules()
    results = [_run_one(s, rules) for s in scenarios]
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    return EvaluationRunResponse(
        total=len(results), passed=passed, failed=failed, results=results
    )


def run_one_scenario(scenario_id: str) -> Optional[ScenarioRunResult]:
    scenarios = load_scenarios()
    for s in scenarios:
        if s["id"] == scenario_id:
            return _run_one(s, load_detection_rules())
    return None


# --- v3 dataset helpers ---


def load_dataset_manifest(path: Optional[Path] = None) -> Dict:
    p = path or DATASET_MANIFEST_FILE
    return json.loads(p.read_text(encoding="utf-8"))


def list_datasets() -> List[Dict]:
    return load_dataset_manifest().get("datasets", [])


def get_dataset_metadata(dataset_id: str) -> Optional[Dict]:
    for d in list_datasets():
        if d.get("id") == dataset_id:
            return d
    return None


def analyze_dataset(dataset_id: str) -> Dict:
    metadata = get_dataset_metadata(dataset_id)
    if metadata is None:
        raise ValueError(f"unknown dataset: {dataset_id}")
    path = resolve_dataset(dataset_id)
    raw = path.read_text(encoding="utf-8")
    events = parse_raw_logs(metadata["log_type"], raw)
    findings = detect_events(events)
    enrich_findings_with_mitre(findings)
    for f in findings:
        score_finding(f)
    matched_rule_ids = sorted({f.rule_id for f in findings})
    matched_techniques = sorted({t for f in findings for t in f.mitre_techniques})
    expected = metadata.get("expected_findings", [])
    expected_techniques = metadata.get("expected_mitre", [])
    missing_rules = sorted(set(expected) - set(matched_rule_ids))
    unexpected_rules = sorted(set(matched_rule_ids) - set(expected))
    score = score_incident(findings)
    severity = severity_from_score(score)
    return {
        "dataset_id": dataset_id,
        "metadata": metadata,
        "event_count": len(events),
        "finding_count": len(findings),
        "matched_rule_ids": matched_rule_ids,
        "matched_mitre_techniques": matched_techniques,
        "missing_rule_ids": missing_rules,
        "unexpected_rule_ids": unexpected_rules,
        "overall_score": score,
        "overall_severity": severity,
        "expected_severity": metadata.get("expected_severity"),
        "highest_severity": max(
            (f.severity for f in findings),
            default="informational",
            key=lambda s: {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0),
        ),
        "findings": [f.model_dump() for f in findings],
    }


def evaluate_datasets() -> Dict:
    results: List[Dict] = []
    for d in list_datasets():
        results.append(analyze_dataset(d["id"]))
    return {
        "total_datasets": len(results),
        "results": results,
    }
