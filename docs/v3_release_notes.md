# v3.0-rc Release Notes

Project repositioned from "Local SOC Triage and Security Operations
Platform" to "Detection Engineering and SOC Workflow Platform". All
v1 and v2 functionality is preserved unchanged.

## New backend modules

- `app/detection_engineering.py` — per-rule quality scoring,
  plain-English explanations, schema validation, gap analysis,
  improvement plans, combined detection-engineering report.
- `app/metrics.py` — precision, recall, F1, per-rule and per-category
  metrics over the evaluation scenarios.
- `app/workflow.py` — analyst workflow simulator with a six-state
  machine and a deterministic transition policy.
- `app/playbooks.py` — playbook library loader + recommendation
  engine + summary.
- `app/evaluation.py` (extended) — dataset manifest loading and
  per-dataset analysis (`analyze_dataset`, `evaluate_datasets`).
- `app/reporting.py` (extended) — executive, analyst, and
  detection-engineering Markdown report builders.
- `app/config.py` (extended) — `resolve_dataset` with the same
  whitelist guard as `resolve_sample_log`.

## New data

- `data/datasets/dataset_manifest.json` (6 synthetic datasets).
- `data/datasets/benign_baseline.log`
- `data/datasets/brute_force_campaign.log`
- `data/datasets/web_attack_campaign.log`
- `data/datasets/dns_beacon_campaign.log`
- `data/datasets/multi_stage_intrusion.log`
- `data/datasets/noisy_false_positive.log`
- `data/playbooks/playbooks.json` (8 playbooks).

## New endpoints (15)

- `GET /datasets`
- `GET /datasets/{dataset_id}`
- `POST /datasets/analyze/{dataset_id}`
- `GET /detection-engineering/rules`
- `GET /detection-engineering/report`
- `GET /detection-engineering/metrics`
- `GET /metrics/evaluation`
- `GET /metrics/rules`
- `GET /playbooks`
- `POST /playbooks/recommend`
- `GET /workflow/sample`
- `POST /workflow/simulate`
- `POST /report/executive`
- `POST /report/analyst`
- `POST /report/detection-engineering`

`GET /api/surface` now lists 44 endpoints in total.

## Frontend additions

Six new panels on top of the v2 dashboard:

- Detection Metrics (precision/recall/F1 KPI tiles)
- Rule Quality table
- Dataset Evaluation dashboard
- Playbook Recommendations
- Analyst Workflow Simulation
- Report Center v3 (Executive / Analyst / Detection Engineering)

Header updated to "Security Log AI Assistant — Detection Engineering
& SOC Workflow Platform · v3.0-rc". No new dependencies.

## Tests

- 7 new test files; total test count increased from 195 to **284**.
- All pass with no skips and no xfails.

## Compatibility

All v1 and v2 endpoints continue to behave the same. All previous
tests still pass unchanged.
