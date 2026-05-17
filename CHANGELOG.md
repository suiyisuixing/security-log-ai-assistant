# Changelog

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
