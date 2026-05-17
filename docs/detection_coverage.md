# Detection Coverage Matrix

## Matrix entry

```json
{
  "technique_id": "T1110",
  "technique_name": "Brute Force",
  "tactic": "Credential Access",
  "covered": true,
  "rule_ids": ["R001", "R002"],
  "coverage_strength": "strong"
}
```

## Coverage strength

| Condition | Strength |
| --------- | -------- |
| 2 or more rules map to the technique | `strong` |
| Exactly 1 rule maps to the technique | `partial` |
| No rule maps to the technique        | `none`   |

## Summary shape

```json
{
  "total_techniques": 12,
  "covered": 12,
  "uncovered": 0,
  "coverage_rate": 1.0,
  "by_tactic": {
    "Credential Access": {"covered": 2, "total": 2},
    ...
  }
}
```

## Endpoint

- `GET /coverage/mitre` — matrix + summary.
