"""Analyst workflow simulation.

Walks a Case through a SOC state machine and records each transition.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from .schemas import Alert, Case


VALID_STATUSES = ["new", "triaged", "investigating", "contained", "resolved", "false_positive"]
_ALLOWED_TRANSITIONS = {
    "new": {"triaged", "false_positive"},
    "triaged": {"investigating", "resolved", "false_positive"},
    "investigating": {"contained", "resolved", "false_positive"},
    "contained": {"resolved"},
    "resolved": set(),
    "false_positive": set(),
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def transition_case_status(
    case: Case, new_status: str, reason: str
) -> Dict:
    if new_status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {new_status}")
    if new_status not in _ALLOWED_TRANSITIONS.get(case.status, set()):
        raise ValueError(
            f"transition not allowed: {case.status} -> {new_status}"
        )
    step = {
        "case_id": case.case_id,
        "from_status": case.status,
        "to_status": new_status,
        "reason": reason,
        "transitioned_at": _utc_now_iso(),
    }
    case.status = new_status
    return step


def create_workflow_from_cases(cases: List[Case]) -> List[Dict]:
    """Initialize each case to status `new` and record an opening step."""
    out: List[Dict] = []
    for c in cases:
        if c.status not in VALID_STATUSES:
            c.status = "new"
        elif c.status == "open":
            c.status = "new"
        out.append(
            {
                "case_id": c.case_id,
                "from_status": None,
                "to_status": c.status,
                "reason": "Case opened from triage pipeline.",
                "transitioned_at": _utc_now_iso(),
            }
        )
    return out


def _likely_false_positive(case: Case, alerts_by_id: Dict[str, Alert]) -> bool:
    related = [alerts_by_id.get(aid) for aid in case.related_alert_ids]
    related = [a for a in related if a is not None]
    if not related:
        return False
    high_fp = sum(
        1
        for a in related
        if a.false_positive and a.false_positive.likelihood == "high"
    )
    return high_fp >= max(1, len(related) // 2)


def simulate_soc_workflow(
    cases: List[Case], alerts: List[Alert] | None = None
) -> Tuple[List[Case], List[Dict]]:
    alerts = alerts or []
    alerts_by_id = {a.alert_id: a for a in alerts}
    steps: List[Dict] = []
    steps.extend(create_workflow_from_cases(cases))
    for c in cases:
        if _likely_false_positive(c, alerts_by_id):
            steps.append(transition_case_status(c, "false_positive", "Majority of related alerts flagged as high FP likelihood."))
            continue
        if c.severity in ("critical", "high"):
            steps.append(transition_case_status(c, "triaged", "High-severity case scheduled for full SOC workflow."))
            steps.append(transition_case_status(c, "investigating", "Analyst assigned; gathering evidence."))
            steps.append(transition_case_status(c, "contained", "Containment actions executed per playbook."))
        elif c.severity == "medium":
            steps.append(transition_case_status(c, "triaged", "Medium-severity case triaged."))
            steps.append(transition_case_status(c, "investigating", "Analyst investigation in progress."))
        else:
            steps.append(transition_case_status(c, "triaged", "Low-severity case triaged for queue sweep."))
            steps.append(transition_case_status(c, "resolved", "No further action required."))
    return cases, steps


def generate_workflow_summary(cases: List[Case]) -> Dict:
    counts = Counter(c.status for c in cases)
    return {
        "total_cases": len(cases),
        "new": counts.get("new", 0),
        "triaged": counts.get("triaged", 0),
        "investigating": counts.get("investigating", 0),
        "contained": counts.get("contained", 0),
        "resolved": counts.get("resolved", 0),
        "false_positive": counts.get("false_positive", 0),
    }
