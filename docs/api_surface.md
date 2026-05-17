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
| GET    | `/api/surface` | - | this endpoint inventory |

## Errors

| Status | Meaning |
| ------ | ------- |
| 400 | Bad input (unknown source type, invalid sample name, path traversal) |
| 404 | Unknown scenario ID |

## Disclosure

API was designed with AI assistance for naming and shape consistency.
All implementation, validation, and review were performed by the author.
