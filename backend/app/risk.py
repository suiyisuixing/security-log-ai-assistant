"""Risk scoring for findings and incidents."""
from __future__ import annotations

from typing import List

from .config import DEFAULT_RISK_BASELINE, SEVERITY_ORDER
from .schemas import Finding


SEVERITY_FROM_SCORE = [
    (90, "critical"),
    (70, "high"),
    (40, "medium"),
    (15, "low"),
    (0, "informational"),
]


def severity_from_score(score: int) -> str:
    for threshold, sev in SEVERITY_FROM_SCORE:
        if score >= threshold:
            return sev
    return "informational"


def score_finding(finding: Finding) -> int:
    base = DEFAULT_RISK_BASELINE.get(finding.severity, 10)
    bonus_events = min(len(finding.matched_events) - 1, 10) * 2
    bonus_mitre = min(len(finding.mitre_techniques), 5) * 2
    score = base + bonus_events + bonus_mitre
    score = max(0, min(100, score))
    finding.score = score
    return score


def score_incident(findings: List[Finding]) -> int:
    if not findings:
        return 0
    scores = [score_finding(f) for f in findings]
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)
    overall = int(round(0.7 * max_score + 0.3 * avg_score))
    return max(0, min(100, overall))


def sort_findings_by_severity(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -f.score, f.rule_id),
    )
