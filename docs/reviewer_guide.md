# Reviewer Guide

A reading and review path for a hiring manager or technical reviewer.

## 30-second pitch

A local, self-contained, AI-assisted SOC triage demo. Parses synthetic
security logs, applies 20 detection rules, maps to MITRE ATT&CK,
scores risk, builds incident reports, and renders results in a clean
React dashboard.

## 5-minute path

1. Read `README.md` (top to bottom).
2. Skim `docs/architecture.md` for the diagram and module table.
3. Open `data/detection_rules/rules.json` to see how rules are declared.
4. Open `backend/app/detectors.py` to see the rule engine.
5. Run the backend and frontend, click **Analyze** on `mixed_security_events.log`.

## 15-minute path

6. Read `docs/detection_methodology.md` and `docs/mitre_mapping.md`.
7. Read `docs/threat_model.md` and `reports/SECURITY_REPORT.md`.
8. Run `pytest` to see all 195 tests pass.
9. Run `python tools/run_checks.py` to also run `compileall` and `npm run build`.
10. Read `tests/test_security_boundaries.py` for the data hygiene invariants.
11. Read `docs/soc_workflow.md` to understand the v2 SOC pipeline.
12. Open the Triage Queue, Cases, Entities, Kill Chain, Coverage, and Tuning panels in the UI.
13. Generate the SOC Markdown report and read top-to-bottom — it summarizes everything the platform produces.
14. Read `docs/v3_release_notes.md` for the Detection Engineering and SOC Workflow Platform features.
15. Read `docs/detection_engineering.md` and `docs/detection_as_code.md` to see how rules are graded and contributed.
16. Open the Detection Metrics panel — confirm precision/recall/F1 over the synthetic scenarios.
17. Open Dataset Evaluation and analyze each of the six synthetic datasets.
18. Open Playbook Recommendations and Workflow Simulation panels.
19. Generate the Executive, Analyst, and Detection Engineering Markdown reports.

## What to look for

- Clean module boundaries; pure functions where possible.
- No hidden external calls.
- A rule engine that supports multiple match types, not just regex.
- A scoring model that aggregates per-finding into per-incident.
- An evaluation harness that asserts detection coverage.

## Disclosure

AI tools assisted with planning and documentation; all design and code
review decisions were made by the author.
