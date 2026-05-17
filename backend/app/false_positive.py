"""False-positive likelihood estimation for alerts.

Pure heuristics over local data. No external services.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, Union

from .schemas import Alert, FalsePositiveAssessment, Finding


_KNOWN_SCANNER_UAS = ("sqlmap", "nikto", "nmap", "masscan", "acunetix")


def _likelihood_from_score(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def estimate_false_positive_likelihood(
    item: Union[Finding, Alert],
) -> FalsePositiveAssessment:
    """Estimate FP likelihood for a Finding or Alert.

    Higher score = more likely a false positive. Anchored on the rule_id
    and the supporting evidence.
    """
    rule_id = item.rule_id
    severity = item.severity
    score = 40  # neutral baseline
    reasons: List[str] = []

    rule_lower_fp_ids = {
        "R001",  # SSH brute force - threshold-based, strong evidence
        "R002",  # invalid user attempts
        "R003",  # sudo on /etc/shadow - exact match
        "R008",  # scanner user-agent - explicit attacker tooling
        "R010",  # port scan
        "R018",  # credential dumping hint
    }
    rule_higher_fp_ids = {
        "R016",  # 404 burst - benign crawlers also do this
        "R020",  # broad scan - high noise
        "R007",  # admin panel probes - benign monitoring tools do too
    }

    if rule_id in rule_lower_fp_ids:
        score -= 25
        reasons.append(f"Rule {rule_id} relies on strong evidence; FP unlikely.")
    if rule_id in rule_higher_fp_ids:
        score += 20
        reasons.append(f"Rule {rule_id} is noisy and commonly produces benign matches.")

    # Severity influence
    if severity == "critical":
        score -= 10
        reasons.append("Critical severity weighs against a benign explanation.")
    elif severity == "high":
        score -= 5
    elif severity in ("low", "informational"):
        score += 10
        reasons.append("Low severity tolerates a benign explanation.")

    # Scanner user-agent evidence
    if isinstance(item, Finding):
        events = item.matched_events
    else:
        events = []  # Alerts do not carry events; FP from Alert relies on rule_id only

    ua_found = any(
        (ev.user_agent or "").lower().find(scanner) >= 0
        for ev in events
        for scanner in _KNOWN_SCANNER_UAS
    )
    if ua_found:
        score -= 25
        reasons.append("Known scanner user-agent observed; FP unlikely.")

    # Event count influence
    if isinstance(item, Finding):
        if len(item.matched_events) >= 5:
            score -= 10
            reasons.append("Many supporting events; FP unlikely.")
        elif len(item.matched_events) == 1:
            score += 10
            reasons.append("Only a single supporting event; corroborate before action.")

    score = max(0, min(100, score))
    likelihood = _likelihood_from_score(score)
    if not reasons:
        reasons.append("Neutral baseline; no strong indicators either way.")
    return FalsePositiveAssessment(
        likelihood=likelihood, score=score, reasons=reasons
    )


def annotate_alerts_with_fp_likelihood(alerts: List[Alert]) -> List[Alert]:
    for a in alerts:
        a.false_positive = estimate_false_positive_likelihood(a)
    return alerts


def summarize_false_positive_review(alerts: List[Alert]) -> Dict:
    counts = Counter()
    review: List[Dict] = []
    for a in alerts:
        fp = a.false_positive
        if fp is None:
            continue
        counts[fp.likelihood] += 1
        if fp.likelihood in ("medium", "high"):
            review.append(
                {
                    "alert_id": a.alert_id,
                    "rule_id": a.rule_id,
                    "title": a.title,
                    "likelihood": fp.likelihood,
                    "score": fp.score,
                    "reasons": fp.reasons,
                }
            )
    return {
        "low_likelihood": counts.get("low", 0),
        "medium_likelihood": counts.get("medium", 0),
        "high_likelihood": counts.get("high", 0),
        "review_recommended": review,
    }
