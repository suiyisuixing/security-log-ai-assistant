# Demo Walkthrough

A scripted demo flow for a 5-minute screen recording or live walkthrough.

## Step 1 — Start backend and frontend

Open two terminals.

```cmd
cd /d C:\Users\27827\Desktop\security-log-ai-assistant\backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

```cmd
cd /d C:\Users\27827\Desktop\security-log-ai-assistant\frontend
npm run dev
```

Open http://localhost:5173.

## Step 2 — Confirm backend status

The **Backend Status** card should show `Online` and a version number.

## Step 3 — Pick a sample log

Use the **Sample Log Selector** to choose `mixed_security_events.log`.
The raw input panel fills in automatically.

## Step 4 — Analyze

Click **Analyze**. Confirm:

- **Findings Dashboard** populates with non-zero counts.
- **Findings** table lists rules with severity badges.
- **MITRE ATT&CK Mapping** panel lists techniques.
- **Timeline** shows chronologically ordered events.
- **Correlated Incidents** lists per-actor groupings.
- **AI Summary (local mock)** produces a multi-line narrative.

## Step 5 — Generate Markdown report

In the **Reports** panel, click **Generate Markdown** and review the
output.

## Step 6 — Run detection evaluation

In the **Detection Evaluation** panel, click **Run All Scenarios**.
All scenarios should pass.

## Step 7 — Dashboard summary

Scroll to the **Dashboard Summary** card. It aggregates findings
across every bundled sample log.
