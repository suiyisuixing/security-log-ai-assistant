# Changelog

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
- Eight new frontend panels: SOC Overview, Triage Queue, Cases, Entity
  Risk, Kill Chain, MITRE Coverage, Rule Tuning, SOC Report.
- 9 new pytest files: `test_triage.py`, `test_cases.py`,
  `test_false_positive.py`, `test_rule_tuning.py`, `test_entities.py`,
  `test_kill_chain.py`, `test_coverage.py`, `test_soc_reporting.py`,
  `test_api_v2.py`. Total test count: 195 (was 113).
- New docs: `soc_workflow.md`, `alert_triage.md`, `incident_cases.md`,
  `entity_risk.md`, `kill_chain.md`, `detection_coverage.md`,
  `false_positive_review.md`, `rule_tuning.md`, `v2_release_notes.md`.

### Updated
- `README.md` — v2 SOC workflow, expanded API table, 195-test reference.
- `PROJECT_STATUS.md`, `RELEASE_CHECKLIST.md`,
  `reports/SECURITY_REPORT.md`, `docs/architecture.md`,
  `docs/threat_model.md`, `docs/detection_methodology.md`,
  `docs/api_surface.md`, `docs/reviewer_guide.md`,
  `docs/portfolio_summary.md`, `docs/demo_walkthrough.md`,
  `docs/diagrams.md`, `docs/testing_strategy.md`,
  `docs/screenshots/README.md`, `frontend/README.md`.

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
