# Playbooks

v3 adds a local response-playbook library at
`data/playbooks/playbooks.json`. Each playbook is a static, educational
response template — no automation, no real action.

## Playbook shape

```json
{
  "id": "PB_BRUTE_FORCE",
  "title": "SSH Brute Force Response",
  "mapped_rules": ["R001", "R002"],
  "mapped_mitre": ["T1110", "T1087"],
  "severity": "high",
  "steps": ["...", "..."],
  "containment": ["...", "..."],
  "evidence_to_collect": ["...", "..."],
  "limitations": "This is a local educational playbook using fake data."
}
```

## Library

- `PB_BRUTE_FORCE` — SSH brute force response.
- `PB_WEB_ATTACK` — General web application attack response.
- `PB_SQL_INJECTION` — SQL injection-specific response.
- `PB_XSS` — Cross-site scripting response.
- `PB_DIRECTORY_TRAVERSAL` — Path traversal response.
- `PB_DNS_BEACON` — DNS beacon / C2 response.
- `PB_PORT_SCAN` — Port scan / network recon response.
- `PB_PRIVILEGE_ESCALATION` — Privilege escalation response.

## Recommendation engine

`playbooks.recommend_playbooks(findings, cases)` matches each playbook
against findings by:

1. shared `mapped_rules` ↔ `finding.rule_id`, or
2. shared `mapped_mitre` ↔ `finding.mitre_techniques`.

Each recommendation gains a `match_reasons` list explaining why it
fired. Cases with matching MITRE techniques are also considered.

## Endpoints

- `GET /playbooks` — full library.
- `POST /playbooks/recommend` — `{log_type, raw_logs}` → recommended
  playbooks + summary.

## Safety guarantees

- All playbook steps are local educational text.
- No automation; the platform never executes any action.
- All playbooks include a `limitations` field calling out the
  educational nature of the content.
