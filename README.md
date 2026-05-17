# security-log-ai-assistant

![CI](https://github.com/suiyisuixing/security-log-ai-assistant/actions/workflows/ci.yml/badge.svg)

A local Detection Engineering and SOC Workflow Platform that parses
synthetic security logs, detects suspicious behavior, maps findings to
MITRE ATT&CK, scores risk, builds triage queues and incident cases,
evaluates detection coverage, simulates analyst workflows, recommends
playbooks, and generates executive, analyst, and detection-engineering
reports.

## Reviewer Quick Path

1. Skim this README for project scope and limitations.
2. Run the backend (`uvicorn app.main:app --reload`) and frontend (`npm run dev`).
3. In the UI, pick `mixed_security_events.log`, click **Analyze**, then explore the dashboard.
4. Use the v2 panels (Triage, Cases, Entities, Kill Chain, Coverage, Tuning, SOC Report).
5. Use the v3 panels (Detection Metrics, Rule Quality, Dataset Evaluation, Playbooks, Workflow, Report Center).
6. Run `pytest` to confirm all 284 tests pass.
7. Run `python tools/run_checks.py` to run the full validation suite (pytest + compileall + frontend build).
8. Read [docs/reviewer_guide.md](docs/reviewer_guide.md) for the structured walkthrough.

## v3.0 Detection Engineering and SOC Workflow Platform

```
Synthetic datasets
       │
       v
   Detection rules (rules.json, quality-scored)
       │
       v
   Findings → Alerts → Cases
       │         │       │
       v         v       v
     Risk    Triage   Workflow simulation
                       │
                       v
     Reports: Executive / Analyst / Detection Engineering / SOC
```

See [docs/v3_release_notes.md](docs/v3_release_notes.md).

## Features

### v1 (unchanged)
- Parses authentication, web access, firewall, DNS, and mixed log formats.
- 20+ detection rules; 12 MITRE techniques; local-only mapping.
- Risk scoring, timeline reconstruction, correlation engine.
- JSON and Markdown incident reports.
- Detection evaluation harness (12+ scenarios).
- React + Vite analyst dashboard.

### v2 (unchanged)
- Alert triage queue with P1-P4 priorities and FP scoring.
- Incident case management with classification and recommended actions.
- Entity risk profiles (IP / user / domain / path).
- Kill-chain view mapping MITRE tactics to lifecycle stages.
- Detection coverage matrix.
- Rule tuning with performance + gap analysis.
- SOC analyst report (JSON + Markdown).

### v3 (new)
- **Detection Engineering Layer**: rule quality scoring, plain-English
  explanations, schema validation, gap analysis, improvement plans.
- **Detection-as-Code**: documented schema, contribution flow, and
  safe-data policy in [docs/detection_as_code.md](docs/detection_as_code.md).
- **Synthetic Attack Dataset v3**: six new local datasets covering
  benign baseline, brute-force, web attacks, DNS beacons, multi-stage
  intrusion, and noisy false-positive scenarios.
- **Precision / Recall / F1 metrics** per rule, per scenario category,
  and overall.
- **Analyst Workflow Simulation** with a six-state machine.
- **Playbook Recommendations** from 8 educational response playbooks.
- **Executive / Analyst / Detection Engineering Reports** as Markdown.
- Six new frontend panels.
- 284 pytest tests (was 195) + GitHub Actions CI.

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

## Synthetic Attack Datasets

Six local datasets in `data/datasets/`. All IPs are RFC 5737 test
addresses or RFC 1918 private addresses. See
[docs/dataset_evaluation.md](docs/dataset_evaluation.md).

## API Overview

See [docs/api_surface.md](docs/api_surface.md). v3 highlights:

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET    | `/datasets` | list synthetic datasets |
| POST   | `/datasets/analyze/{id}` | analyze a dataset |
| GET    | `/detection-engineering/report` | full DE report |
| GET    | `/metrics/evaluation` | precision/recall/F1 |
| GET    | `/playbooks` | list playbooks |
| POST   | `/playbooks/recommend` | recommend playbooks |
| GET    | `/workflow/sample` | simulated analyst workflow |
| POST   | `/report/executive` | executive report (MD) |
| POST   | `/report/analyst` | SOC analyst report (MD) |
| POST   | `/report/detection-engineering` | DE report (MD) |

`GET /api/surface` returns the full inventory (44 endpoints).

## Detection Engineering

20 rules in `data/detection_rules/rules.json`, each quality-scored and
explained. See [docs/detection_engineering.md](docs/detection_engineering.md)
and [docs/detection_as_code.md](docs/detection_as_code.md).

## Precision / Recall / F1 Metrics

Computed against scenarios in
`data/evaluation/detection_scenarios.json`. Definitions:

- TP: expected rule id present in matched rule ids.
- FP: matched rule id NOT in expected.
- FN: expected rule id NOT matched.

See [docs/detection_methodology.md](docs/detection_methodology.md).

## Analyst Workflow Simulation

Deterministic state machine over Cases. See
[docs/soc_workflow_simulation.md](docs/soc_workflow_simulation.md).

## Playbook Recommendations

Eight educational SOC response playbooks. See
[docs/playbooks.md](docs/playbooks.md).

## Reports

- v1: Incident JSON + Markdown.
- v2: SOC JSON + Markdown.
- v3: Executive Markdown, Analyst Markdown, Detection Engineering Markdown.

See [docs/reporting_model.md](docs/reporting_model.md).

## Testing

```cmd
.venv\Scripts\python.exe -m pytest
```

**284 tests** pass with no skips and no xfails.

## Security Boundaries

- All filesystem reads go through whitelisted resolvers
  (`resolve_sample_log`, `resolve_dataset`).
- No `subprocess`, `os.system`, or external HTTP libraries.
- `tests/test_security_boundaries.py` and `tests/test_datasets.py`
  enforce these invariants and the RFC 5737 / RFC 1918 IP policy.

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
- Sample logs and datasets are synthetic; production deployments need real ingestion.
- Detection rules and playbooks are educational and intentionally simple.

## Portfolio Usage

See [docs/portfolio_summary.md](docs/portfolio_summary.md) and
[docs/demo_walkthrough.md](docs/demo_walkthrough.md).
