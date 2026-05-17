# security-log-ai-assistant

![CI](https://github.com/suiyisuixing/security-log-ai-assistant/actions/workflows/ci.yml/badge.svg)

A local Security Operations Evaluation Platform for AI-assisted log
analysis, alert triage, MITRE ATT&CK mapping, incident case management,
detection evaluation, false-positive review, and SOC analyst reporting.

## Reviewer Quick Path

1. Skim this README for project scope and limitations.
2. Run the backend (`uvicorn app.main:app --reload`) and frontend (`npm run dev`).
3. In the UI, pick `mixed_security_events.log`, click **Analyze**, then explore the dashboard.
4. Use the v2 panels (Triage, Cases, Entities, Kill Chain, Coverage, Tuning, SOC Report).
5. Run `pytest` to confirm all 195 tests pass.
6. Run `python tools/run_checks.py` to run the full validation suite (pytest + compileall + frontend build).
7. Read [docs/reviewer_guide.md](docs/reviewer_guide.md) for the structured walkthrough.

## v2.0 SOC Workflow

```
Raw logs -> Parse -> Detect -> Findings
                                |
                                v
                Alerts (priority + FP estimate)
                                |
                                v
            Triage queue summary + filters
                                |
                                v
              Cases (per-actor, classified)
                                |
                                v
                Entity profiles (risk-scored)
                                |
                                v
            Kill-chain view + MITRE coverage
                                |
                                v
             SOC report (JSON + Markdown)
```

See [docs/soc_workflow.md](docs/soc_workflow.md).

## Features

### v1 (unchanged)
- Parses authentication, web access, firewall, DNS, and mixed log formats.
- 20+ detection rules covering brute force, injection, scanning, beaconing, etc.
- Local MITRE ATT&CK mapping (12 techniques) — no external fetch.
- Risk scoring with severity normalization.
- Local mock AI-style summarizer (no external LLM call).
- Timeline reconstruction and per-actor incident correlation.
- JSON and Markdown incident reports.
- Detection evaluation harness with 12+ named scenarios.
- React + Vite analyst dashboard.

### v2 (new)
- **Alert triage queue** with P1-P4 priorities, queue summaries, and filtering.
- **Incident case management** classified as brute_force / web_attack /
  network_scan / dns_beacon / privilege_escalation / multi_stage_incident.
- **Entity risk profiles** for IPs, usernames, domains, and paths.
- **Kill-chain view** mapping MITRE tactics to canonical lifecycle stages.
- **Detection coverage matrix** showing per-technique rule mapping.
- **False-positive review** with likelihood scoring.
- **Rule tuning** with performance, recommendations, and detection gaps.
- **SOC analyst report** (JSON + Markdown) combining all the above.
- Frontend SOC Dashboard v2 with eight new panels.
- 195 pytest tests (was 113) + GitHub Actions CI.

## Architecture

See [docs/architecture.md](docs/architecture.md).

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

Five hand-crafted local sample logs live in `data/sample_logs/`. All IPs
are RFC 5737 test addresses or RFC 1918 private addresses. No real
production targets are referenced. See [docs/dataset.md](docs/dataset.md).

## API Overview

See [docs/api_surface.md](docs/api_surface.md). v2 highlights:

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET    | `/triage/sample` | alert queue for all bundled samples |
| POST   | `/triage/analyze` | triage analyst-supplied raw logs |
| GET    | `/cases/sample` | cases for all bundled samples |
| POST   | `/cases/from-analysis` | cases from analyst input |
| POST   | `/false-positive/review` | FP-annotated alerts |
| GET    | `/rules/tuning` | per-rule performance + suggestions |
| GET    | `/entities/sample` | risk-scored entities |
| POST   | `/entities/analyze` | entities from analyst input |
| GET    | `/kill-chain/sample` | kill-chain view |
| POST   | `/kill-chain/analyze` | kill-chain from analyst input |
| GET    | `/coverage/mitre` | MITRE coverage matrix |
| POST   | `/report/soc-json` | SOC report (JSON) |
| POST   | `/report/soc-markdown` | SOC report (Markdown) |

`GET /api/surface` returns the full inventory (29 endpoints).

## Detection Rules

20 rules in `data/detection_rules/rules.json`. See [docs/detection_methodology.md](docs/detection_methodology.md).

## MITRE ATT&CK Mapping

Local mapping for 12 techniques in `data/mitre/mitre_mapping.json`. See
[docs/mitre_mapping.md](docs/mitre_mapping.md) and
[docs/detection_coverage.md](docs/detection_coverage.md).

## Risk Scoring

Severity-baseline + event-count bonus + technique-coverage bonus, clamped to
0-100. Overall incident score uses 0.7 * max + 0.3 * avg. Entity scoring
adds an alert-count multiplier. See [docs/detection_methodology.md](docs/detection_methodology.md).

## Incident Reports

`v1`: per-incident JSON and Markdown reports via `/report/json` and `/report/markdown`.
`v2`: full SOC analyst report via `/report/soc-json` and `/report/soc-markdown`.

## Evaluation Suite

12+ scenarios with explicit `expected_rule_ids`. Run via
`POST /evaluation/run` or `python -m pytest tests/test_evaluation.py`.

## Testing

```cmd
.venv\Scripts\python.exe -m pytest
```

**195 tests** pass with no skips and no xfails.

## Security Boundaries

- All filesystem reads go through `resolve_sample_log`, which whitelists
  the sample filenames and blocks `..`, `/`, and `\`.
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
