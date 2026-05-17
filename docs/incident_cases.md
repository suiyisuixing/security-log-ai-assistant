# Incident Cases

## Case shape

```json
{
  "case_id": "case-001",
  "title": "Possible web application attack sequence",
  "severity": "high",
  "status": "open",
  "priority": "P2",
  "src_ips": ["198.51.100.23"],
  "related_alert_ids": ["alert-001", "alert-002"],
  "mitre_techniques": ["T1190", "T1059"],
  "summary": "Actor 198.51.100.23 produced 2 alert(s) ...",
  "recommended_actions": ["...", "..."],
  "created_at": "2026-05-17T00:00:00Z",
  "case_type": "web_attack"
}
```

## Classification

`classify_case_type(alerts)` returns one of:

- `brute_force`
- `web_attack`
- `network_scan`
- `dns_beacon`
- `privilege_escalation`
- `multi_stage_incident` (two or more categories fire)
- `unknown`

## Recommended actions

Per case type, a hard-coded action list is attached. Examples:

- `web_attack`: apply WAF signatures; review DB queries; virtual-patch
  the endpoint.
- `brute_force`: lock targeted accounts; block source IP at edge;
  rotate compromised credentials.
- `multi_stage_incident`: treat as a structured intrusion; assemble IR
  team; contain hosts and accounts.

## Endpoints

- `GET /cases/sample` — cases for all bundled sample logs.
- `POST /cases/from-analysis` — `{log_type, raw_logs, include_correlation}`.
