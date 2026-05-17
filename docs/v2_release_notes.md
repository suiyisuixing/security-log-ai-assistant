# v2.0-rc Release Notes

Project repositioned from "log analysis assistant" to "local SOC
Operations Evaluation Platform". v1 functionality is preserved
unchanged; v2 adds new modules, endpoints, frontend panels, and tests
on top.

## New backend modules

- `app/triage.py` — alerts + priority + queue summary + filtering.
- `app/cases.py` — case classification and recommended actions.
- `app/false_positive.py` — FP likelihood scoring and review summary.
- `app/rule_tuning.py` — per-rule performance, tuning recommendations,
  and detection gaps based on evaluation results.
- `app/entities.py` — risk-scored entity profiles for IPs, users,
  domains, and paths.
- `app/kill_chain.py` — canonical kill-chain view from MITRE tactics.
- `app/coverage.py` — MITRE coverage matrix + summary.
- `app/reporting.py` — extended with `build_soc_report` and
  `build_soc_markdown_report`.

## New endpoints

- `GET /triage/sample`
- `POST /triage/analyze`
- `GET /cases/sample`
- `POST /cases/from-analysis`
- `POST /false-positive/review`
- `GET /rules/tuning`
- `GET /entities/sample`
- `POST /entities/analyze`
- `GET /kill-chain/sample`
- `POST /kill-chain/analyze`
- `GET /coverage/mitre`
- `POST /report/soc-json`
- `POST /report/soc-markdown`

`GET /api/surface` now lists 29 endpoints in total.

## Frontend additions

The dashboard adds eight new panels above the existing v1 panels:

- SOC Overview (7 KPI tiles)
- Alert Triage Queue
- Incident Cases
- Entity Risk Profiles
- Kill Chain View
- MITRE Coverage Matrix
- Rule Tuning
- SOC Report (JSON + Markdown export with Copy buttons)

No new dependencies. `npm run build` still produces a single bundle.

## Tests

- 9 new test files; total test count increased from 113 to 195.
- All pass with no skips and no xfails.
- New tests cover triage, cases, false-positive scoring, rule tuning,
  entities, kill chain, coverage, SOC report shape and Markdown
  rendering, and all v2 endpoints (including path-traversal protection
  and absence of external indicators).

## Compatibility

All v1 endpoints continue to behave the same. The previous 113 tests
still pass unchanged.
