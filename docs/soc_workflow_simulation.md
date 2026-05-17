# SOC Workflow Simulation

v3 adds an analyst workflow simulator in `backend/app/workflow.py`. It
moves cases through a state machine and records each transition.

## State machine

```
new ── triaged ── investigating ── contained ── resolved
 │        │             │
 │        ├─→ resolved  ├─→ resolved
 │        └─→ false_positive
 └─→ false_positive
```

Defined transitions:

| From | Allowed to |
| ---- | ---------- |
| `new` | `triaged`, `false_positive` |
| `triaged` | `investigating`, `resolved`, `false_positive` |
| `investigating` | `contained`, `resolved`, `false_positive` |
| `contained` | `resolved` |
| `resolved` | (terminal) |
| `false_positive` | (terminal) |

## Simulation policy

`simulate_soc_workflow(cases, alerts)` walks each case:

- If a majority of related alerts have high FP likelihood →
  `new` → `false_positive`.
- Critical/high severity → `new` → `triaged` → `investigating` →
  `contained`.
- Medium severity → `new` → `triaged` → `investigating`.
- Low / informational → `new` → `triaged` → `resolved`.

Each transition records `{case_id, from_status, to_status, reason,
transitioned_at}`.

## Endpoints

- `GET /workflow/sample` — workflow over cases from all bundled
  sample logs.
- `POST /workflow/simulate` — workflow over analyst-supplied raw logs.

## Workflow summary

`generate_workflow_summary(cases)` returns counts per status:
`new`, `triaged`, `investigating`, `contained`, `resolved`,
`false_positive`.

## Limitations

- The simulator is deterministic and based only on severity and FP
  likelihood. A real SOC has human judgment in the loop.
- Cases revisited mid-flow (re-triage after closure) are not modeled
  here.
