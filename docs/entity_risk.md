# Entity Risk Profiles

## Profile shape

```json
{
  "entity_id": "198.51.100.23",
  "entity_type": "src_ip",
  "risk_score": 85,
  "severity": "high",
  "event_count": 12,
  "finding_count": 4,
  "alert_count": 4,
  "mitre_techniques": ["T1190", "T1059"],
  "first_seen": "2026-05-10T08:01:12Z",
  "last_seen": "2026-05-10T08:05:00Z",
  "observations": ["high: SQL injection attempt (R004)", "..."]
}
```

## Entity types

| Type | Source field |
| ---- | ------------ |
| `src_ip` | `ev.source_ip` |
| `username` | `ev.user` |
| `path` | `ev.path` |
| `domain` | derived from `ev.query` (last two labels) |

## Risk scoring

`risk_score = max(finding scores for this entity) + 2 * min(alert_count, 5)`

Capped to `[0, 100]`. Severity is normalized via `severity_from_score`.

## Summary

`summarize_entities(profiles)` returns:

- `total_entities`
- `high_risk_entities`
- `top_entities` (top 5 by risk)
- `by_type` (count per entity type)

## Endpoints

- `GET /entities/sample`
- `POST /entities/analyze`
