# Detection Engineering

Detection engineering in this project means treating rules as code:
each rule is named, described, mapped to MITRE ATT&CK, schema-validated,
quality-scored, evaluated against scenarios, and reviewed for tuning
opportunities.

## Rule quality scoring

`detection_engineering.rule_quality_score(rule)` returns:

```json
{
  "rule_id": "R001",
  "quality_score": 86,
  "quality_level": "strong",
  "strengths": ["Maps to MITRE T1110", "..."],
  "weaknesses": ["..."],
  "improvement_suggestions": ["..."]
}
```

Levels: `excellent (>=90)`, `strong (>=75)`, `moderate (>=50)`,
`weak (>=1)`, `invalid (0)`.

Scoring factors:

| Factor | Points |
| ------ | ------ |
| Description present | 12 |
| MITRE mapping | 18 |
| Valid severity | 10 |
| Valid match_type | 12 |
| Source_type set | 8 |
| Pattern present | 12 (+4 case-insensitive) |
| Threshold + window for threshold rules | 10 |
| Descriptive rule name | 6 |

Penalties (logged as weaknesses): short patterns, greedy `.*` without
non-greedy modifier, missing pattern on regex/threshold rules.

## Rule explanation

`explain_rule(rule)` returns a plain-English summary, what the rule
detects, why it matters, likely false positives, and recommended triage
steps. Triage hints are tailored per rule family (auth/web/scan/DNS).

## Schema validation

`validate_rule_schema(rule)` returns `valid`, `missing_fields`, and
`warnings`. Required: `id`, `name`, `description`, `source_type`,
`match_type`, `severity`. Recommended: `mitre`, `pattern`. Threshold
rules must declare numeric `threshold`.

## Coverage analysis

`detect_rule_gaps()` combines MITRE mapping, the rule pack, and
evaluation scenarios to produce:

```json
{
  "uncovered_techniques": ["T1055", "T1566"],
  "weakly_covered_techniques": ["T1021"],
  "scenario_gaps": [{"scenario_id": "...", "missing_rule_ids": [...]}]
}
```

## Evaluation metrics

`metrics.calculate_detection_metrics()` produces precision, recall,
F1, TP, FP, FN aggregated across all scenarios.

## Rule improvement workflow

`generate_rule_improvement_plan(rule_metrics)` reads per-rule TP/FP/FN
and emits prioritized improvements: false negatives → high priority,
false positives → medium, low quality score → low priority.

## Combined report

`build_detection_engineering_report()` packages quality scores,
explanations, coverage matrix, evaluation metrics, per-rule metrics,
category metrics, improvement plan, tuning recommendations, and
detection gaps into a single JSON. The Markdown rendering is in
`reporting.build_detection_engineering_report_markdown`.

## Limitations

- Quality scoring is heuristic; it favors metadata completeness over
  semantic correctness.
- All scoring and evaluation happens against the local synthetic
  scenarios in `data/evaluation/detection_scenarios.json`.
