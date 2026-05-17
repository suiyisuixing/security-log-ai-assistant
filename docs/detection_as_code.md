# Detection-as-Code

This project treats `data/detection_rules/rules.json` as the source of
truth for detections. Every rule has a defined schema, an evaluation
scenario, and is reachable from CI.

## rules.json schema

```json
{
  "id": "R0NN",
  "name": "human readable name",
  "description": "what this rule detects, one sentence",
  "source_type": "auth|web|firewall|dns",
  "match_type": "regex|threshold|port_scan|path_scan|dga|beacon",
  "pattern": "regex (for regex/threshold)",
  "group_by": "field name (for threshold/port_scan/path_scan/beacon)",
  "distinct_field": "field name (for port_scan/path_scan)",
  "threshold": 5,
  "window_seconds": 60,
  "min_length": 15,
  "severity": "informational|low|medium|high|critical",
  "mitre": ["T1110", "T1190"]
}
```

## How to add a rule

1. Pick the next sequential `R0NN` id.
2. Decide on `source_type` and `match_type`.
3. Write the pattern. Prefer non-greedy and bounded regex.
4. Map to MITRE technique IDs from `data/mitre/mitre_mapping.json`.
5. Choose severity using the project severity table.
6. Add a paired evaluation scenario in
   `data/evaluation/detection_scenarios.json` listing the rule in
   `expected_rule_ids`.

## How to write tests for a rule

- Add a positive test in `tests/test_detectors.py` that parses a real
  log line and asserts the rule fires.
- Add a negative test in the same file that parses a benign line and
  asserts the rule does NOT fire.
- Add a row to `data/evaluation/detection_scenarios.json` so the
  evaluation harness covers the rule end-to-end.

## How to tune a rule

- Run `python -m pytest tests/test_metrics.py` to see precision/recall
  per rule.
- If `false_negatives > 0`: review the pattern or threshold/window.
- If `false_positives > 0`: add contextual filters (UA, status, IP).
- Re-run `python tools/run_checks.py` after every change.

## How to avoid overbroad detections

- Anchor regex with explicit prefixes/suffixes when possible.
- Avoid `.*` without non-greedy `?` modifier.
- Prefer threshold + window over pure regex for activity-burst
  detections.
- Use `group_by` to scope thresholds to one actor at a time.

## How to map to MITRE ATT&CK

- Use the technique IDs listed in `data/mitre/mitre_mapping.json`.
- Map to as many techniques as honestly apply; coverage strength
  improves when more rules map to the same technique.

## Safe local-only data policy

- All sample IPs MUST be in RFC 5737 (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) or RFC 1918.
- All domains MUST use `.example` or a clearly synthetic TLD
  (`.top`, `.example`, etc.).
- No real API keys, no real targets, no real customer data.
- `tests/test_security_boundaries.py` enforces these invariants on
  every commit via CI.
