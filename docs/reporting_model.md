# Reporting Model (v3)

The platform produces four distinct report kinds. They share the same
detection pipeline but target different audiences.

| Report | Format | Audience | Endpoint | Builder |
| ------ | ------ | -------- | -------- | ------- |
| Incident (v1) | JSON + MD | Single-incident review | `/report/json`, `/report/markdown` | `build_incident_report`, `build_markdown_report` |
| SOC (v2) | JSON + MD | SOC dashboard | `/report/soc-json`, `/report/soc-markdown` | `build_soc_report`, `build_soc_markdown_report` |
| Executive (v3) | MD | Management | `/report/executive` | `build_executive_report` |
| Analyst (v3) | MD | SOC analyst | `/report/analyst` | `build_analyst_report` |
| Detection Engineering (v3) | MD | Detection engineer | `/report/detection-engineering` | `build_detection_engineering_report_markdown` |

## Executive report sections

- Header (overall risk)
- Executive Summary
- Top Risks
- Business Impact
- High-Priority Cases
- Recommended Executive Actions (case actions + matched playbooks)
- Limitations
- Disclosure

## Analyst report sections

- Findings
- Evidence (first three matched events per finding)
- Timeline (first 30)
- Cases
- Entities (top 10)
- MITRE ATT&CK (covered techniques + matching rule IDs)
- Playbooks (recommended)
- Triage Steps

## Detection engineering report sections

- Per-rule Quality (score, strengths, weaknesses, suggestions)
- Detection Coverage
- Evaluation Metrics (precision, recall, F1, TP/FP/FN)
- False Positive Notes
- Rule Tuning Suggestions
- Detection Gaps

## Safety properties

- No `Authorization`, `Bearer `, or real API key pattern appears in
  any report (asserted in `tests/test_reports_v3.py`).
- No real production domain appears in any report.
- Every report contains an AI-assisted disclosure that does NOT name
  a specific LLM vendor.
