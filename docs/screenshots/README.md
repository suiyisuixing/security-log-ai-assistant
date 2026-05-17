# Screenshots

This directory is intentionally empty of binaries to keep the repository
small and easy to clone. To regenerate the screenshots:

1. Start the backend (`uvicorn app.main:app --reload`).
2. Start the frontend (`npm run dev`).
3. In Chrome / Edge / Firefox, open http://localhost:5173.
4. Capture the following views:
   - `01_dashboard_overview.png` — initial load with backend status online.
   - `02_findings_table.png` — findings table populated after Analyze.
   - `03_mitre_panel.png` — MITRE mapping table.
   - `04_timeline.png` — timeline panel.
   - `05_evaluation_results.png` — all-scenarios-passed view.

Place the PNG files in this directory.

## v2 additions

For v2, also capture:

- `06_soc_overview.png` — top KPI tiles after a full load.
- `07_triage_queue.png` — alerts with priorities and FP likelihoods.
- `08_cases.png` — classified cases with recommended actions.
- `09_entity_risk.png` — sorted entity profiles.
- `10_kill_chain.png` — observed kill-chain stages.
- `11_coverage_matrix.png` — MITRE coverage at 100%.
- `12_rule_tuning.png` — per-rule performance.
- `13_soc_report.png` — generated SOC Markdown report.

## v3 additions

- `14_detection_metrics.png` — precision/recall/F1 KPI tiles.
- `15_rule_quality.png` — per-rule quality table.
- `16_dataset_evaluation.png` — dataset list + one analysis result.
- `17_playbook_recommendations.png` — playbook recommendations.
- `18_workflow_simulation.png` — case transitions table.
- `19_report_center_executive.png` — executive Markdown report.
- `20_report_center_analyst.png` — analyst Markdown report.
- `21_report_center_de.png` — detection engineering Markdown report.
