"""Detection evaluation suite. Runs scenarios and reports pass/fail."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from .config import EVALUATION_FILE
from .detectors import detect_events, load_detection_rules
from .parsers import parse_raw_logs
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
