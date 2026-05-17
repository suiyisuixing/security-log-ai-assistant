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
8. Run `pytest` to see all 70+ tests pass.
9. Run `python tools/run_checks.py` to also run `compileall` and `npm run build`.
10. Read `tests/test_security_boundaries.py` for the data hygiene invariants.

## What to look for

- Clean module boundaries; pure functions where possible.
- No hidden external calls.
- A rule engine that supports multiple match types, not just regex.
- A scoring model that aggregates per-finding into per-incident.
- An evaluation harness that asserts detection coverage.

## Disclosure

AI tools assisted with planning and documentation; all design and code
review decisions were made by the author.
