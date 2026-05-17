# Release Checklist — v2.0-rc

- [x] All sample logs use RFC 5737 test IP ranges or RFC 1918 private addresses.
- [x] No real API keys committed.
- [x] No external HTTP calls in backend.
- [x] No `subprocess` / `os.system` in backend.
- [x] README, CHANGELOG, LICENSE present and updated for v2.
- [x] `pytest` passes locally (195 tests) with no skips/xfails.
- [x] `python -m compileall backend/app tests tools` succeeds.
- [x] `npm run build` succeeds.
- [x] `tools/run_checks.py` returns exit code 0.
- [x] `.gitignore` excludes `.venv`, `node_modules`, `dist`, `.pytest_cache`, etc.
- [x] AI-assisted development disclosure is present in README and frontend UI.
- [x] No vendor LLM brand names in README or frontend (asserted by tests).
- [x] CI workflow runs backend tests and frontend build on push/PR to main.
- [x] All v1 endpoints continue to function (regression-tested).
- [x] All v2 endpoints listed in `/api/surface`.
- [x] Path-traversal protection enforced on every endpoint that reads sample logs.
- [x] No `Authorization` headers leaked by any v2 endpoint.
