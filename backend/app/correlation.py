"""Correlate findings by shared actor (source IP) into incidents."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .schemas import CorrelatedIncident, Finding


def _actor_key(finding: Finding) -> str:
    for ev in finding.matched_events:
        if ev.source_ip:
            return ev.source_ip
    return "unknown"


def correlate_findings(findings: List[Finding]) -> List[CorrelatedIncident]:
    buckets: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        buckets[_actor_key(f)].append(f)
    out: List[CorrelatedIncident] = []
    counter = 1
    for actor, group in buckets.items():
        rule_ids = sorted({f.rule_id for f in group})
        severities = sorted({f.severity for f in group})
        techniques = sorted({t for f in group for t in f.mitre_techniques})
        score = max((f.score for f in group), default=0)
        summary = (
            f"Actor {actor} triggered {len(group)} finding(s) across rule(s) "
            f"{', '.join(rule_ids)}."
        )
        out.append(
            CorrelatedIncident(
                incident_id=f"INC-{counter:04d}",
                actor=actor,
                rule_ids=rule_ids,
                severities=severities,
                techniques=techniques,
                score=score,
                summary=summary,
            )
        )
        counter += 1
    out.sort(key=lambda i: (-i.score, i.incident_id))
    return out
