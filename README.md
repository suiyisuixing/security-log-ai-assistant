# security-log-ai-assistant

![CI](https://github.com/suiyisuixing/security-log-ai-assistant/actions/workflows/ci.yml/badge.svg)

A local AI-assisted Security Log Analysis and SOC Triage Platform for parsing
security logs, detecting suspicious activity, mapping findings to MITRE
ATT&CK, scoring risk, generating incident reports, and visualizing results in
a React dashboard.

## Reviewer Quick Path

1. Skim this README for project scope and limitations.
2. Run the backend (`uvicorn app.main:app --reload`) and frontend (`npm run dev`).
3. In the UI, pick `mixed_security_events.log`, click **Analyze**, then explore the dashboard.
4. Run `pytest` to confirm all detection logic, security boundaries, and API tests pass.
5. Run `python tools/run_checks.py` to run the full validation suite (pytest + compileall + frontend build).
6. Read [docs/reviewer_guide.md](docs/reviewer_guide.md) for the structured walkthrough.

## Features

- Parses authentication, web access, firewall, DNS, and mixed log formats.
- 20+ detection rules covering brute force, injection, scanning, beaconing, etc.
- Local MITRE ATT&CK mapping (12 techniques) — no external fetch.
- Risk scoring with severity normalization.
- Local mock AI-style summarizer (no external LLM call).
- Timeline reconstruction and per-actor incident correlation.
- JSON and Markdown incident reports.
- Detection evaluation harness with 12+ named scenarios.
- React + Vite analyst dashboard.
- pytest suite with 70+ tests and GitHub Actions CI.

## Architecture

```
+----------------+        +----------------+        +----------------+
|  Sample Logs   | -----> |  FastAPI App   | <----> |  React Dashboard|
|  (RFC 5737)    |        |  (parsers,     |        |  (Vite, fetch)  |
+----------------+        |   detectors,   |        +----------------+
                          |   MITRE map,   |
                          |   scoring,     |
                          |   reporting)   |
                          +----------------+
```

See [docs/architecture.md](docs/architecture.md) for the full diagram and module layout.

## Quick Start

### Backend

```cmd
cd /d C:\Users\27827\Desktop\security-log-ai-assistant
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

### Frontend

```cmd
cd /d C:\Users\27827\Desktop\security-log-ai-assistant\frontend
npm install
npm run dev
```

Open http://localhost:5173.

## Sample Logs

Five hand-crafted local sample logs live in `data/sample_logs/`:

- `auth.log` — SSH brute force, invalid users, sudo on `/etc/shadow`.
- `web_access.log` — SQLi, XSS, traversal, admin probes, scanner UAs, command injection.
- `firewall.log` — port scans, repeated DENY bursts, suspicious outbound 4444.
- `dns.log` — DGA-style queries, NXDOMAIN bursts, periodic beacon to a fake C2 domain.
- `mixed_security_events.log` — mixed multi-source events for end-to-end demos.

All IPs are RFC 5737 test addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
or RFC 1918 private addresses. No real production targets are referenced.

## API Overview

See [docs/api_surface.md](docs/api_surface.md). Highlights:

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET    | `/health` | liveness |
| GET    | `/sample-logs` | list bundled logs |
| POST   | `/parse` | parse raw logs |
| POST   | `/analyze` | parse + detect + score + report |
| POST   | `/analyze-sample/{name}` | analyze a bundled sample |
| POST   | `/report/markdown` | Markdown incident report |
| POST   | `/evaluation/run` | run all detection scenarios |
| GET    | `/dashboard/summary` | aggregated multi-log summary |

## Detection Rules

20 rules in `data/detection_rules/rules.json`. See [docs/detection_methodology.md](docs/detection_methodology.md).

## MITRE ATT&CK Mapping

Local mapping for 12 techniques in `data/mitre/mitre_mapping.json`. See
[docs/mitre_mapping.md](docs/mitre_mapping.md).

## Risk Scoring

Severity-baseline + event-count bonus + technique-coverage bonus, clamped to
0-100. Overall incident score uses 0.7 * max + 0.3 * avg. See
[docs/detection_methodology.md](docs/detection_methodology.md).

## Incident Reports

Both JSON and Markdown reports are produced by the same builder. The Markdown
report includes the local mock AI summary section.

## Evaluation Suite

12+ scenarios with explicit `expected_rule_ids`. Run via
`POST /evaluation/run` or `python -m pytest tests/test_evaluation.py`.

## Testing

```cmd
.venv\Scripts\python.exe -m pytest
```

All tests must pass with no skips and no xfails.

## Security Boundaries

- All filesystem reads go through `resolve_sample_log`, which whitelists the
  sample filenames and blocks `..`, `/`, and `\`.
- No `subprocess` or `os.system` calls in the backend.
- No external HTTP libraries are imported in the backend.
- `tests/test_security_boundaries.py` enforces these invariants in CI.

See [docs/threat_model.md](docs/threat_model.md) and
[reports/SECURITY_REPORT.md](reports/SECURITY_REPORT.md).

## AI-assisted development disclosure

This project was developed as an AI-assisted learning and engineering project.
The architecture, detection scenarios, testing goals, validation process, and
final review were directed by the author. AI tools were used for planning,
code review, documentation support, and debugging guidance, while all
repository commits and project decisions were managed by the author.

本项目是一个 AI 辅助学习与工程实践项目。项目架构、检测场景、测试目标、验证流程
和最终审查均由作者主导。AI 工具主要用于规划、代码审查、文档支持和调试指导,所有
仓库提交和项目决策均由作者管理。

## Limitations

- Mock AI summarizer only — no real LLM call.
- No persistent storage; analyses run in-memory per request.
- Sample logs are illustrative; production deployments need real ingestion.
- Detection rules are intentionally simple and meant for portfolio review.

## Portfolio Usage

See [docs/portfolio_summary.md](docs/portfolio_summary.md) and
[docs/demo_walkthrough.md](docs/demo_walkthrough.md) for screenshot-friendly
review paths.
