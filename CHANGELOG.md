# Changelog

## v3.0-rc — 2026-05-17

Repositioned the project as a Detection Engineering and SOC Workflow
Platform. All v1 and v2 functionality is preserved unchanged.

### Added
- `backend/app/detection_engineering.py` — per-rule quality scoring,
  plain-English explanations, schema validation, gap analysis,
  improvement plans, combined DE report.
- `backend/app/metrics.py` — precision, recall, F1, per-rule and
  per-category metrics over evaluation scenarios.
- `backend/app/workflow.py` — analyst workflow simulator with six-state
  machine (new / triaged / investigating / contained / resolved /
  false_positive).
- `backend/app/playbooks.py` — local playbook library loader,
  recommendation engine, and summary.
- Extended `backend/app/evaluation.py` with dataset manifest loading
  and per-dataset analysis (`analyze_dataset`, `evaluate_datasets`,
  `list_datasets`).
- Extended `backend/app/reporting.py` with `build_executive_report`,
  `build_analyst_report`, and
  `build_detection_engineering_report_markdown`.
- Extended `backend/app/config.py` with `resolve_dataset` whitelist
  guard.
- 15 new API endpoints (datasets, detection-engineering, metrics,
  playbooks, workflow, v3 reports).
- 6 new synthetic dataset log files in `data/datasets/` plus a
  manifest declaring expected findings, MITRE techniques, and severity.
- 8-playbook library in `data/playbooks/playbooks.json`.
- 6 new frontend panels (Detection Metrics, Rule Quality, Dataset
  Evaluation, Playbooks, Workflow, Report Center v3).
- 7 new pytest files: `test_detection_engineering.py`, `test_metrics.py`,
  `test_datasets.py`, `test_playbooks.py`, `test_workflow.py`,
  `test_reports_v3.py`, `test_api_v3.py`. Total: 284 tests
  (was 195).
- New docs: `detection_engineering.md`, `detection_as_code.md`,
  `dataset_evaluation.md`, `playbooks.md`, `soc_workflow_simulation.md`,
  `reporting_model.md`, `v3_release_notes.md`.

### Updated
- `README.md` — v3 positioning, 284-test reference, expanded API table.
- `PROJECT_STATUS.md`, `RELEASE_CHECKLIST.md`,
  `reports/SECURITY_REPORT.md`, `docs/architecture.md`,
  `docs/threat_model.md`, `docs/detection_methodology.md`,
  `docs/api_surface.md`, `docs/reviewer_guide.md`,
  `docs/portfolio_summary.md`, `docs/demo_walkthrough.md`,
  `docs/diagrams.md`, `docs/testing_strategy.md`,
  `docs/screenshots/README.md`, `frontend/README.md`.

## v2.0-rc — 2026-05-17

Repositioned the project as a local Security Operations Evaluation
Platform. v1 functionality is preserved unchanged.

### Added
- `backend/app/triage.py` — alert generation with P1-P4 priorities, queue
  summary, and filtering.
- `backend/app/cases.py` — incident case creation, classification
  (brute_force / web_attack / network_scan / dns_beacon /
  privilege_escalation / multi_stage_incident), and recommended actions.
- `backend/app/false_positive.py` — FP likelihood scoring and review
  summary.
- `backend/app/rule_tuning.py` — per-rule performance, tuning
  recommendations, and detection-gap reporting.
- `backend/app/entities.py` — risk-scored entity profiles for IPs,
  usernames, domains, and paths.
- `backend/app/kill_chain.py` — canonical kill-chain view derived from
  MITRE tactics.
- `backend/app/coverage.py` — MITRE coverage matrix + summary.
- Extended `backend/app/reporting.py` with `build_soc_report` and
  `build_soc_markdown_report`.
- 13 new API endpoints (triage, cases, FP review, rule tuning, entities,
  kill chain, coverage, SOC report).
- Eight new frontend panels.
- 9 new pytest files. Total: 195 tests (was 113).
- New docs: `soc_workflow.md`, `alert_triage.md`, `incident_cases.md`,
  `entity_risk.md`, `kill_chain.md`, `detection_coverage.md`,
  `false_positive_review.md`, `rule_tuning.md`, `v2_release_notes.md`.

## v1.0-rc — 2026-05-17

Initial release candidate of the security-log-ai-assistant project.

### Added
- FastAPI backend with 16 endpoints.
- React + Vite analyst dashboard.
- 5 sample log files (auth, web, firewall, dns, mixed).
- 20 detection rules across 5 source types.
- Local MITRE ATT&CK mapping (12 techniques).
- Risk scoring with severity normalization.
- Local mock AI summarizer.
- Incident report builders (JSON + Markdown).
- Timeline reconstruction.
- Per-actor correlation engine.
- Detection evaluation suite (12 named scenarios).
- pytest suite covering parsers, detectors, MITRE, risk, timeline,
  correlation, reporting, evaluation, API, and security boundaries.
- GitHub Actions CI workflow (Python 3.11 + Node 20).
- `tools/run_checks.py` local validation runner.
- Full documentation set under `docs/`.
