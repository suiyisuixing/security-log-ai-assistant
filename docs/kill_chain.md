# Kill Chain View

## Stages

The platform uses an 11-stage canonical chain derived from MITRE tactics:

1. `reconnaissance`
2. `initial_access`
3. `execution`
4. `persistence`
5. `privilege_escalation`
6. `credential_access`
7. `discovery`
8. `lateral_movement`
9. `command_and_control`
10. `exfiltration`
11. `impact`

## Tactic -> stage mapping

| MITRE tactic | Stage |
| ------------ | ----- |
| Reconnaissance | reconnaissance |
| Initial Access | initial_access |
| Execution | execution |
| Defense Evasion | execution |
| Persistence | persistence |
| Privilege Escalation | privilege_escalation |
| Credential Access | credential_access |
| Discovery | discovery |
| Lateral Movement | lateral_movement |
| Command and Control | command_and_control |
| Exfiltration | exfiltration |
| Impact | impact |

## Output

```json
{
  "stages": [
    {
      "stage": "reconnaissance",
      "findings": [...],
      "mitre_techniques": ["T1595"],
      "observed": true,
      "finding_count": 1
    },
    ...
  ],
  "observed_stage_count": 4,
  "highest_stage": "command_and_control",
  "narrative": "Observed 4 kill-chain stage(s) ..."
}
```

## Endpoints

- `GET /kill-chain/sample`
- `POST /kill-chain/analyze`
