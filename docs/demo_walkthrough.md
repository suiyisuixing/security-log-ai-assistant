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

## v2 — SOC workflow demo

8. Click **Generate Alert Queue** in the Alert Triage Queue panel.
   Confirm that priorities (P1-P4) and false-positive likelihoods are populated.
9. Click **Generate Cases** in the Incident Cases panel. Cases are
   classified (e.g., `web_attack`, `multi_stage_incident`) with
   recommended actions.
10. Click **Build Entity Profiles**. Sort visually by risk score
    descending; confirm high-risk attacker IPs surface to the top.
11. Click **Build Kill Chain**. Observe which stages were reached.
12. Click **Load Coverage Matrix**. Confirm 100% MITRE coverage.
13. Click **Analyze Rule Tuning**. Read the per-rule recommendations
    and confirm there are no detection gaps.
14. In the **SOC Report** panel, click **Generate SOC Markdown Report**
    and **Copy Markdown**. This single document is what a SOC reviewer
    would receive.

## v3 — Detection Engineering & Workflow demo

15. Click **Load Evaluation Metrics** in the Detection Metrics panel.
    Confirm precision/recall/F1 over all scenarios.
16. Click **Load Detection Engineering Report** in the Rule Quality
    panel. Inspect strengths/weaknesses for each rule.
17. Click **Load Datasets** in the Dataset Evaluation panel. Choose
    `multi_stage_intrusion` and click **Analyze Selected Dataset** —
    confirm severity is `critical`.
18. Click **Load Playbooks** and then **Recommend Playbooks**. Confirm
    matching playbooks are listed with steps and containment actions.
19. Click **Build Workflow** in the Analyst Workflow Simulation panel.
    Confirm each high-severity case is walked through new → triaged →
    investigating → contained.
20. In Report Center v3, click each of **Executive Report**, **Analyst
    Report**, and **Detection Engineering Report**. Copy each one with
    the **Copy report** button.
