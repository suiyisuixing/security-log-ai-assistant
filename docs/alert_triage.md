# Alert Triage

## Alert shape

```json
{
  "alert_id": "alert-001",
  "finding_id": "finding-001",
  "rule_id": "R004",
  "title": "SQL injection attempt",
  "severity": "high",
  "status": "open",
  "priority": "P2",
  "src_ips": ["198.51.100.23"],
  "mitre_techniques": ["T1190"],
  "risk_score": 80,
  "created_at": "2026-05-17T00:00:00Z",
  "recommended_action": "Investigate within the hour; ...",
  "triage_reason": "High-severity rule 'SQL injection attempt' fired; ...",
  "false_positive": {"likelihood": "low", "score": 10, "reasons": ["..."]}
}
```

## Priority mapping

| Condition | Priority |
| --------- | -------- |
| `severity == critical` or `risk_score >= 90` | P1 |
| `severity == high` or `risk_score >= 70`     | P2 |
| `severity == medium` or `risk_score >= 40`   | P3 |
| otherwise (low / informational)              | P4 |

## Queue summary

`summarize_alert_queue(alerts)` returns:

- `total_alerts`, `open_alerts`
- `priority_counts` (P1..P4)
- `severity_counts`
- `top_source_ips` (top 5)
- `top_mitre_techniques` (top 5)

## Filtering

`filter_alerts(alerts, severity=..., priority=..., status=...)` returns the
intersection. All three parameters are optional.

## Endpoints

- `GET /triage/sample` — all bundled sample logs.
- `POST /triage/analyze` — `{log_type, raw_logs, include_correlation}`.
