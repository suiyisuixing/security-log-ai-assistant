# Project Status

- Version: v3.0-rc
- Date: 2026-05-17

## Completion

| Area | Status |
| ---- | ------ |
| FastAPI backend (v1) | done |
| FastAPI backend (v2 SOC modules) | done |
| FastAPI backend (v3 DE / metrics / workflow / playbooks / reports) | done |
| React + Vite frontend (v1) | done |
| React + Vite frontend (v2 SOC panels) | done |
| React + Vite frontend (v3 DE / Workflow / Report Center) | done |
| Sample logs (5 files) | done |
| Synthetic datasets (6 files + manifest) | done |
| Detection rules (20) | done |
| Detection-as-code documentation | done |
| MITRE ATT&CK mapping (12 techniques) | done |
| Risk scoring | done |
| Mock AI summarizer | done |
| Incident reports (JSON + Markdown) | done |
| Timeline reconstruction | done |
| Correlation engine | done |
| Detection evaluation suite (12 scenarios) | done |
| Alert triage queue | done |
| Incident case management | done |
| False-positive review | done |
| Rule tuning analyzer | done |
| Entity risk profiles | done |
| Kill-chain view | done |
| MITRE coverage matrix | done |
| SOC analyst report (JSON + Markdown) | done |
| Detection engineering layer | done |
| Precision / Recall / F1 metrics | done |
| Analyst workflow simulation | done |
| Playbook library + recommender (8) | done |
| Executive / Analyst / DE reports | done |
| Pytest suite (284 tests) | done |
| GitHub Actions CI | done |
| Documentation set (v1 + v2 + v3) | done |

## Known limitations

- No persistent database.
- No real LLM API integration; mock summarizer only.
- Synthetic datasets intentionally small.
- Workflow simulator is deterministic; real analyst judgment is not modeled.

## Next step

Optionally extend the playbook library and add screenshot images under `docs/screenshots/`.
