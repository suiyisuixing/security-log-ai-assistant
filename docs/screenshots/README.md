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
