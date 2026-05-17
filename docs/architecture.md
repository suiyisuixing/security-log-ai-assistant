# Architecture

## High-level diagram

```
+----------------+   HTTP    +----------------------+   in-process   +-------------------+
| React Frontend |  <--->    |   FastAPI Backend    |  <--------->   |   Local Data:     |
| (Vite, 5173)   |           |   (uvicorn, 8000)    |                |   sample logs,    |
|                |           |                      |                |   rules.json,     |
|                |           |                      |                |   mitre_mapping,  |
+----------------+           +----------+-----------+                |   scenarios.json  |
                                        |                            +-------------------+
                                        | calls
                                        v
+------------------+   +-----------------+   +-----------------+   +------------------+
|   parsers.py     |   |   detectors.py  |   |   mitre.py      |   |   risk.py        |
|   (regex)        |   |   (rule engine) |   |   (local map)   |   |   (scoring)      |
+------------------+   +-----------------+   +-----------------+   +------------------+

+------------------+   +-----------------+   +-----------------+   +------------------+
| summarizer.py    |   |  timeline.py    |   | correlation.py  |   |  reporting.py    |
| (mock AI)        |   |  (sort by ts)   |   | (group by actor)|   |  (JSON+Markdown) |
+------------------+   +-----------------+   +-----------------+   +------------------+
```

## Module responsibilities

| Module | Responsibility |
| ------ | -------------- |
| `config.py` | Project paths, allowlists, severity tables, safe path resolver |
| `schemas.py` | Pydantic models for events, findings, reports, evaluation responses |
| `parsers.py` | Per-source-type line parsers and dispatcher |
| `detectors.py` | Rule engine with regex / threshold / port_scan / path_scan / dga / beacon match types |
| `mitre.py` | Load and attach MITRE technique metadata to findings |
| `risk.py` | Per-finding and per-incident scoring, severity normalization |
| `summarizer.py` | Local rule-based narrative generator (mock AI) |
| `timeline.py` | Chronological timeline construction |
| `correlation.py` | Group findings by source IP into incidents |
| `reporting.py` | Build full `IncidentReport` and render Markdown |
| `evaluation.py` | Run named detection scenarios with expected rule IDs |
| `triage.py` | (v2) Alert generation + priority + queue summary + filtering |
| `cases.py` | (v2) Case classification and recommended actions |
| `false_positive.py` | (v2) FP likelihood scoring + review summary |
| `rule_tuning.py` | (v2) Per-rule performance + tuning + detection gaps |
| `entities.py` | (v2) Entity risk profiles for IP/user/domain/path |
| `kill_chain.py` | (v2) Kill-chain stage mapping from MITRE tactics |
| `coverage.py` | (v2) MITRE coverage matrix + summary |
| `main.py` | FastAPI app, endpoint declarations, CORS, exception mapping |

## Data flow

1. UI fetches the sample log content.
2. UI POSTs the raw text to `/analyze` with a `source_type`.
3. Backend parses lines into `ParsedEvent` records.
4. Backend applies all detection rules and produces `Finding` records.
5. MITRE enrichment attaches technique metadata.
6. Scoring assigns numeric scores and severities.
7. Timeline, correlation, and AI summary are produced.
8. The full `IncidentReport` is returned as JSON for the dashboard.

## No external dependencies at runtime

- No outbound HTTP from the backend.
- No subprocess execution.
- No database connection.
- No real LLM API call.
