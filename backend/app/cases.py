"""Incident case management.

Groups alerts and correlated incidents into investigative cases.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List

from .schemas import Alert, Case, CorrelatedIncident


_CASE_TYPE_RECOMMENDATIONS = {
    "brute_force": [
        "Lock or rate-limit the targeted accounts.",
        "Block the source IP(s) at the edge.",
        "Force credential rotation for confirmed compromised users.",
    ],
    "web_attack": [
        "Apply WAF signatures for the observed payloads.",
        "Review application logs and database query patterns for impact.",
        "Patch or virtual-patch the targeted endpoint.",
    ],
    "network_scan": [
        "Block the scanning source at the perimeter.",
        "Confirm no services were exposed beyond intended ports.",
        "Tune IDS to capture follow-on activity.",
    ],
    "dns_beacon": [
        "Sinkhole the suspicious domain(s).",
        "Investigate the originating host for beaconing malware.",
        "Hunt for related lateral movement.",
    ],
    "privilege_escalation": [
        "Audit sudo / privileged usage for the named user.",
        "Verify the integrity of /etc/shadow and /etc/sudoers.",
        "Rotate root and service credentials if compromise is suspected.",
    ],
    "multi_stage_incident": [
        "Treat as a multi-stage intrusion; assemble an incident response team.",
        "Reconstruct the timeline across alerts and confirm scope.",
        "Engage containment for affected hosts and accounts.",
    ],
    "unknown": [
        "Manually triage the related alerts.",
        "Gather additional context before action.",
    ],
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _severity_rank(sev: str) -> int:
    return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
        sev, 0
    )


def _highest_severity(alerts: List[Alert]) -> str:
    if not alerts:
        return "informational"
    return max((a.severity for a in alerts), key=_severity_rank)


def _highest_priority(alerts: List[Alert]) -> str:
    return min(
        (a.priority for a in alerts),
        default="P4",
        key=lambda p: int(p[1:]) if p and p[1:].isdigit() else 4,
    )


def classify_case_type(alerts: List[Alert]) -> str:
    if not alerts:
        return "unknown"
    rule_ids = {a.rule_id for a in alerts}
    techs = {t for a in alerts for t in a.mitre_techniques}

    auth_rules = {"R001", "R002"}
    web_rules = {"R004", "R005", "R006", "R007", "R008", "R009", "R016", "R017", "R019", "R020"}
    fw_rules = {"R010", "R011", "R012"}
    dns_rules = {"R013", "R014", "R015"}
    priv_rules = {"R003", "R018"}

    fired = []
    if rule_ids & auth_rules:
        fired.append("brute_force")
    if rule_ids & web_rules:
        fired.append("web_attack")
    if rule_ids & fw_rules:
        fired.append("network_scan")
    if rule_ids & dns_rules:
        fired.append("dns_beacon")
    if rule_ids & priv_rules:
        fired.append("privilege_escalation")

    if len(fired) >= 2:
        return "multi_stage_incident"
    if fired:
        return fired[0]
    if "T1110" in techs:
        return "brute_force"
    return "unknown"


def _build_summary(actor: str, case_type: str, alerts: List[Alert]) -> str:
    rule_list = ", ".join(sorted({a.rule_id for a in alerts}))
    return (
        f"Actor {actor} produced {len(alerts)} alert(s) consistent with a "
        f"{case_type.replace('_', ' ')} pattern. Rules involved: {rule_list}."
    )


def create_cases_from_alerts(
    alerts: List[Alert],
    correlated_incidents: List[CorrelatedIncident],
) -> List[Case]:
    """Group alerts by their primary source IP and emit one case per group.

    `correlated_incidents` is accepted for API symmetry; we use it to align
    case IDs and to supplement the actor list when an alert has no src_ips.
    """
    by_actor: Dict[str, List[Alert]] = {}
    for a in alerts:
        actor = a.src_ips[0] if a.src_ips else "unknown"
        by_actor.setdefault(actor, []).append(a)

    incident_lookup = {inc.actor: inc for inc in correlated_incidents}

    cases: List[Case] = []
    now = _utc_now_iso()
    for idx, (actor, group) in enumerate(sorted(by_actor.items()), start=1):
        case_type = classify_case_type(group)
        severity = _highest_severity(group)
        priority = _highest_priority(group)
        techs = sorted({t for a in group for t in a.mitre_techniques})
        inc = incident_lookup.get(actor)
        title_bits = {
            "brute_force": "Brute force activity",
            "web_attack": "Possible web application attack sequence",
            "network_scan": "Network scanning activity",
            "dns_beacon": "Suspicious DNS / beacon activity",
            "privilege_escalation": "Privilege escalation indicators",
            "multi_stage_incident": "Multi-stage incident sequence",
            "unknown": "Unclassified security activity",
        }
        cases.append(
            Case(
                case_id=f"case-{idx:03d}",
                title=title_bits.get(case_type, "Security activity"),
                severity=severity,
                status="open",
                priority=priority,
                src_ips=[actor] if actor != "unknown" else [],
                related_alert_ids=[a.alert_id for a in group],
                mitre_techniques=techs,
                summary=_build_summary(actor, case_type, group)
                + (f" Correlated incident: {inc.incident_id}." if inc else ""),
                recommended_actions=list(_CASE_TYPE_RECOMMENDATIONS[case_type]),
                created_at=now,
                case_type=case_type,
            )
        )
    cases.sort(key=lambda c: (-_severity_rank(c.severity), c.case_id))
    return cases


def summarize_cases(cases: List[Case]) -> Dict:
    severities = Counter(c.severity for c in cases)
    types = Counter(c.case_type for c in cases)
    priorities = Counter(c.priority for c in cases)
    open_count = sum(1 for c in cases if c.status == "open")
    return {
        "total_cases": len(cases),
        "open_cases": open_count,
        "severity_counts": dict(severities),
        "case_type_counts": dict(types),
        "priority_counts": dict(priorities),
    }
