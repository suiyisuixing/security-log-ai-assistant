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

## Targets

- 70+ tests.
- 0 skips and 0 xfails.
- 100% pass on both Windows and Linux CI runners.

## Local commands

```cmd
.venv\Scripts\python.exe -m pytest
.venv\Scripts\python.exe -m compileall backend\app tests tools
.venv\Scripts\python.exe tools\run_checks.py
```
