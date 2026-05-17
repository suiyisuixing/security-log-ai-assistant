# Rule Tuning

The tuning report aggregates evaluation results into per-rule performance,
machine-readable recommendations, and detection gaps.

## Performance entry

```json
{
  "rule_id": "R001",
  "triggered_count": 2,
  "expected_count": 2,
  "missed_count": 0,
  "possible_overtrigger": 0,
  "tuning_recommendation": "Rule performing as expected; keep monitoring."
}
```

## Recommendation types

| Type | Trigger | Suggested change |
| ---- | ------- | ---------------- |
| `new_rule_needed` | expected matches not produced | revise pattern or split into more specific rule |
| `threshold_adjustment` | rule misses some scenarios | lower threshold or widen window |
| `context_filter` | rule fires on unexpected scenarios | add contextual filter (allowlist, UA denylist, status_code) |

## Detection gap

```json
{
  "scenario_id": "detect_xss_attempt",
  "missing_rule_ids": ["R005"],
  "note": "Scenario 'Detect XSS attempt' expected rules R005 but they did not fire."
}
```

## Endpoint

- `GET /rules/tuning` — performance, recommendations, gaps.
