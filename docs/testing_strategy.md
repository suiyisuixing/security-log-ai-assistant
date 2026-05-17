# Testing Strategy

## Goals

- Verify each backend module independently.
- Verify end-to-end behavior via the FastAPI test client.
- Enforce security and data-hygiene invariants.

## Test layout

| File | Focus |
| ---- | ----- |
| `tests/test_parsers.py` | Per-source-type parser correctness and rejection of malformed input |
| `tests/test_detectors.py` | Each rule type plus end-to-end rule pack behavior |
| `tests/test_mitre.py` | Mapping loading, enrichment, and no-external-fetch invariant |
| `tests/test_risk.py` | Severity thresholds, finding/incident scoring, sorting |
| `tests/test_timeline.py` | Chronological ordering and field population |
| `tests/test_correlation.py` | Per-actor grouping and incident IDs |
| `tests/test_reporting.py` | Full report builder + Markdown rendering |
| `tests/test_evaluation.py` | All scenarios pass; unknown IDs return None |
| `tests/test_api.py` | FastAPI endpoints (positive and negative cases) |
| `tests/test_security_boundaries.py` | Path traversal, IP whitelist, key/external-call scans |
| `tests/test_triage.py` | (v2) Alert generation, priority mapping, queue summary |
| `tests/test_cases.py` | (v2) Case classification and recommended actions |
| `tests/test_false_positive.py` | (v2) FP likelihood scoring and annotations |
| `tests/test_rule_tuning.py` | (v2) Rule performance, recommendations, gaps |
| `tests/test_entities.py` | (v2) Entity profile shape and risk scoring |
| `tests/test_kill_chain.py` | (v2) Kill chain mapping and view |
| `tests/test_coverage.py` | (v2) MITRE coverage matrix |
| `tests/test_soc_reporting.py` | (v2) SOC report shape and Markdown rendering |
| `tests/test_api_v2.py` | (v2) All v2 endpoints incl. traversal & header checks |
| `tests/test_detection_engineering.py` | (v3) Quality scoring, schema validation, gap analysis, DE report |
| `tests/test_metrics.py` | (v3) Precision/recall/F1 math + per-rule + per-category |
| `tests/test_datasets.py` | (v3) Manifest, RFC 5737 IPs, no real API keys/domains, per-dataset analysis |
| `tests/test_playbooks.py` | (v3) Library shape, recommendations, educational-disclaimer presence |
| `tests/test_workflow.py` | (v3) State machine, transitions, simulator policy |
| `tests/test_reports_v3.py` | (v3) Executive / Analyst / DE Markdown structure + no-secret invariants |
| `tests/test_api_v3.py` | (v3) Every v3 endpoint, surface inventory, traversal block, vendor-name block |

## Targets

- 260+ tests. Current suite: 284 tests.
- 0 skips and 0 xfails.
- 100% pass on both Windows and Linux CI runners.

## Local commands

```cmd
.venv\Scripts\python.exe -m pytest
.venv\Scripts\python.exe -m compileall backend\app tests tools
.venv\Scripts\python.exe tools\run_checks.py
```
