"""Alert triage queue.

Converts detection findings into actionable alerts with priorities,
queue summaries, and filtering. All in-memory, local-only.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .schemas import Alert, Finding


_PRIORITY_RECOMMENDED_ACTION = {
    "P1": "Immediate containment; escalate to on-call SOC lead and isolate affected host(s).",
    "P2": "Investigate within the hour; correlate with related alerts and lock impacted accounts if confirmed.",
    "P3": "Triage within the shift; document context and review for related activity.",
    "P4": "Review during routine queue sweep; consider rule tuning if recurring.",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def assign_priority(alert: Alert) -> str:
    sev = (alert.severity or "informational").lower()
    score = alert.risk_score or 0
    if sev == "critical" or score >= 90:
        return "P1"
    if sev == "high" or score >= 70:
        return "P2"
    if sev == "medium" or score >= 40:
        return "P3"
    return "P4"


def _triage_reason(finding: Finding) -> str:
    bits = [f"{finding.severity.title()}-severity rule '{finding.rule_name}' fired"]
    if finding.mitre_techniques:
        bits.append(
            f"mapped to MITRE {', '.join(finding.mitre_techniques)}"
        )
    if len(finding.matched_events) > 1:
        bits.append(f"across {len(finding.matched_events)} events")
    return "; ".join(bits) + "."


def generate_alerts_from_findings(findings: List[Finding]) -> List[Alert]:
    alerts: List[Alert] = []
    now = _utc_now_iso()
    for idx, f in enumerate(findings, start=1):
        src_ips = sorted({ev.source_ip for ev in f.matched_events if ev.source_ip})
        alert = Alert(
            alert_id=f"alert-{idx:03d}",
            finding_id=f"finding-{idx:03d}",
            rule_id=f.rule_id,
            title=f.rule_name,
            severity=f.severity,
            status="open",
            priority="P4",
            src_ips=src_ips,
            mitre_techniques=list(f.mitre_techniques),
            risk_score=f.score,
            created_at=now,
            recommended_action="",
            triage_reason=_triage_reason(f),
        )
        alert.priority = assign_priority(alert)
        alert.recommended_action = _PRIORITY_RECOMMENDED_ACTION[alert.priority]
        alerts.append(alert)
    return alerts


def summarize_alert_queue(alerts: List[Alert]) -> Dict:
    priorities = Counter(a.priority for a in alerts)
    severities = Counter(a.severity for a in alerts)
    ip_counts: Counter = Counter()
    tech_counts: Counter = Counter()
    for a in alerts:
        for ip in a.src_ips:
            ip_counts[ip] += 1
        for t in a.mitre_techniques:
            tech_counts[t] += 1
    open_count = sum(1 for a in alerts if a.status == "open")
    return {
        "total_alerts": len(alerts),
        "open_alerts": open_count,
        "priority_counts": dict(priorities),
        "severity_counts": dict(severities),
        "top_source_ips": [
            {"ip": ip, "count": c} for ip, c in ip_counts.most_common(5)
        ],
        "top_mitre_techniques": [
            {"technique_id": t, "count": c} for t, c in tech_counts.most_common(5)
        ],
    }


def filter_alerts(
    alerts: List[Alert],
    severity: Optional[str] = None,
    priority: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Alert]:
    out = alerts
    if severity:
        out = [a for a in out if a.severity == severity]
    if priority:
        out = [a for a in out if a.priority == priority]
    if status:
        out = [a for a in out if a.status == status]
    return out
