# Portfolio Summary

## What this project demonstrates

- Python backend design (FastAPI + Pydantic) with clean separation of
  parsing, detection, scoring, and reporting concerns.
- React + Vite frontend with no heavy UI framework, focused on legible
  cards, tables, and badges.
- Practical security engineering knowledge: SSH brute force, SQLi,
  XSS, path traversal, scanning patterns, DGA, beaconing.
- MITRE ATT&CK awareness and structured mapping.
- Testing discipline: 70+ pytest tests, security boundary tests, and
  a detection evaluation harness.
- CI hygiene: GitHub Actions workflow that runs both backend and
  frontend pipelines on every push.

## v2 additions

- A working SOC analyst workflow: triage queue, case classification,
  per-entity risk profiles, kill-chain projection, MITRE coverage
  matrix, rule tuning, and full SOC reports.
- 13 additional FastAPI endpoints with consistent request/response
  shapes.
- 9 new pytest files (82 new tests) bringing the suite to 195 total.
- Eight new frontend panels with no new dependencies.

## v3 additions

- A detection engineering layer: per-rule quality scoring, plain-English
  explanations, schema validation, gap analysis, and improvement plans.
- Precision, recall, and F1 metrics over named evaluation scenarios.
- Six synthetic attack datasets with explicit expected findings.
- A deterministic analyst workflow simulator with six states.
- An eight-playbook educational response library and a recommender.
- Three audience-specific Markdown reports (Executive / Analyst /
  Detection Engineering).
- 7 additional test files (89 new tests) bringing the suite to 284 total.
- 6 additional frontend panels, still zero new dependencies.

## Skills shown

- Designing and documenting an API surface.
- Implementing a small detection engine with multiple match types.
- Modeling risk scoring and severity normalization.
- Writing test fixtures that double as regression detection scenarios.
- Producing readable Markdown incident reports from JSON data.

## Disclosure

This project was developed as an AI-assisted learning and engineering
project. AI tools were used for planning, code review, documentation
support, and debugging guidance. All repository commits and project
decisions were managed by the author.
