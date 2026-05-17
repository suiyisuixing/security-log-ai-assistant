# API Surface

Base URL during development: `http://127.0.0.1:8000`

| Method | Path | Body | Returns |
| ------ | ---- | ---- | ------- |
| GET    | `/` | - | project metadata + disclosure |
| GET    | `/health` | - | `{"status":"ok"}` |
| GET    | `/sample-logs` | - | list of bundled log filenames |
| GET    | `/sample-logs/{log_name}` | - | name, source_type, content |
| POST   | `/parse` | `{source_type, raw_logs}` | list of `ParsedEvent` |
| POST   | `/analyze` | `{source_type, raw_logs}` | `IncidentReport` |
| POST   | `/analyze-sample/{log_name}` | - | `IncidentReport` |
| GET    | `/rules` | - | full detection rule pack |
| GET    | `/mitre` | - | technique catalog |
| POST   | `/report/json` | `{source_type, raw_logs}` | `IncidentReport` |
| POST   | `/report/markdown` | `{source_type, raw_logs}` | `{"markdown": "..."}` |
| GET    | `/evaluation/scenarios` | - | scenario list |
| POST   | `/evaluation/run` | - | summary + per-scenario results |
| POST   | `/evaluation/run-one/{scenario_id}` | - | one scenario result |
| GET    | `/dashboard/summary` | - | aggregated stats across all sample logs |
| GET    | `/triage/sample` | - | alert queue for all bundled sample logs |
| POST   | `/triage/analyze` | `{log_type, raw_logs, include_correlation}` | alert queue from analyst input |
| GET    | `/cases/sample` | - | cases for all bundled sample logs |
| POST   | `/cases/from-analysis` | `{log_type, raw_logs, include_correlation}` | cases from analyst input |
| POST   | `/false-positive/review` | `{log_type, raw_logs}` | FP-annotated alerts |
| GET    | `/rules/tuning` | - | per-rule performance + tuning + gaps |
| GET    | `/entities/sample` | - | entity risk profiles for all bundled logs |
| POST   | `/entities/analyze` | `{log_type, raw_logs}` | entity profiles from analyst input |
| GET    | `/kill-chain/sample` | - | kill chain view for all bundled logs |
| POST   | `/kill-chain/analyze` | `{log_type, raw_logs, include_correlation}` | kill chain from analyst input |
| GET    | `/coverage/mitre` | - | MITRE coverage matrix + summary |
| POST   | `/report/soc-json` | `{source_type, raw_logs}` | full SOC report (JSON) |
| POST   | `/report/soc-markdown` | `{source_type, raw_logs}` | full SOC report (Markdown) |
| GET    | `/datasets` | - | list synthetic datasets |
| GET    | `/datasets/{dataset_id}` | - | dataset metadata + content |
| POST   | `/datasets/analyze/{dataset_id}` | - | parse + detect + score |
| GET    | `/detection-engineering/rules` | - | per-rule quality + explanation |
| GET    | `/detection-engineering/report` | - | full detection-engineering report (JSON) |
| GET    | `/detection-engineering/metrics` | - | quality + coverage + evaluation summary |
| GET    | `/metrics/evaluation` | - | precision / recall / F1 |
| GET    | `/metrics/rules` | - | per-rule metrics |
| GET    | `/playbooks` | - | playbook library |
| POST   | `/playbooks/recommend` | `{log_type, raw_logs}` | recommended playbooks |
| GET    | `/workflow/sample` | - | analyst workflow over all sample logs |
| POST   | `/workflow/simulate` | `{log_type, raw_logs}` | workflow over analyst input |
| POST   | `/report/executive` | `{source_type, raw_logs}` | executive report (Markdown) |
| POST   | `/report/analyst` | `{source_type, raw_logs}` | analyst report (Markdown) |
| POST   | `/report/detection-engineering` | - | DE report (Markdown) |
| GET    | `/api/surface` | - | this endpoint inventory (44 endpoints) |

## Errors

| Status | Meaning |
| ------ | ------- |
| 400 | Bad input (unknown source type, invalid sample name, path traversal) |
| 404 | Unknown scenario ID |

## Disclosure

API was designed with AI assistance for naming and shape consistency.
All implementation, validation, and review were performed by the author.
