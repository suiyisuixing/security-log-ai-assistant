# Detection Methodology

## Rule schema

Each rule in `data/detection_rules/rules.json` has the following fields:

| Field | Type | Notes |
| ----- | ---- | ----- |
| `id` | string | Unique rule ID (e.g., `R001`) |
| `name` | string | Human-readable name |
| `description` | string | What the rule looks for |
| `source_type` | string | `auth` / `web` / `firewall` / `dns` |
| `match_type` | string | `regex` / `threshold` / `port_scan` / `path_scan` / `dga` / `beacon` |
| `pattern` | string | Regex (for `regex` / `threshold`) |
| `group_by` | string | Field used for grouping (e.g., `source_ip`) |
| `distinct_field` | string | Field used for distinctness (e.g., `dest_port`) |
| `threshold` | int | Minimum count |
| `window_seconds` | int | Sliding window size |
| `severity` | string | `low` / `medium` / `high` / `critical` |
| `mitre` | list[string] | MITRE technique IDs |

## Match types

- **regex**: pattern matched against the raw line of any matching event.
- **threshold**: count events whose raw line matches `pattern`, grouped by
  `group_by`, requiring at least `threshold` events whose timestamps fit in
  a `window_seconds` window.
- **port_scan**: count *distinct* values of `distinct_field` from events
  grouped by `group_by` inside a window.
- **path_scan**: same engine as `port_scan` but parameterized for HTTP
  paths.
- **dga**: heuristic detection of long, high-entropy DNS subdomains.
- **beacon**: detect repeated queries to the same domain at regular
  intervals within a window.

## Scoring

- Each finding starts at a severity baseline (informational=5, low=20,
  medium=45, high=70, critical=90).
- +2 per additional matched event (capped at +20).
- +2 per associated MITRE technique (capped at +10).
- Clamped to `[0, 100]`.

## Severity normalization

```
score >= 90  -> critical
score >= 70  -> high
score >= 40  -> medium
score >= 15  -> low
otherwise    -> informational
```

## Incident scoring

`overall = round(0.7 * max(finding_scores) + 0.3 * mean(finding_scores))`

## v2 additions

- Each finding is converted into an `Alert` with a P1-P4 priority.
- A `false_positive` heuristic produces a `(likelihood, score, reasons)`
  triple per alert.
- `rule_tuning.analyze_rule_performance(evaluation)` aggregates per-rule
  `triggered`, `expected`, `missed`, and `possible_overtrigger` counts.
- `coverage.build_detection_coverage_matrix()` maps each MITRE technique
  to the rule IDs that reference it (`strong` = 2+ rules; `partial` = 1
  rule; `none` = no rule).
- `kill_chain.build_kill_chain_view()` projects findings onto an
  11-stage canonical kill chain via the MITRE tactic of each technique.

## Evaluation

Each scenario in `data/evaluation/detection_scenarios.json` declares an
`expected_rule_ids` list. A scenario passes if every expected rule fires.
Unexpected rule matches are reported as `unexpected_rule_ids` but do not
fail the scenario, because a real piece of attacker traffic typically
trips several rules.
