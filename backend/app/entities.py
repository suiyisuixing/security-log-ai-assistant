"""Entity risk profiles built from events, findings, and alerts."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .detectors import _parse_ts
from .risk import severity_from_score
from .schemas import Alert, EntityProfile, Finding, ParsedEvent


def _ts_iso(ts: Optional[str]) -> Optional[str]:
    dt = _parse_ts(ts)
    if dt is None:
        return ts
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _collect_entities(ev: ParsedEvent) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if ev.source_ip:
        out.append(("src_ip", ev.source_ip))
    if ev.user:
        out.append(("username", ev.user))
    if ev.path:
        out.append(("path", ev.path))
    if ev.query:
        # take only the registrable-ish portion (last two labels)
        labels = ev.query.split(".")
        domain = ".".join(labels[-2:]) if len(labels) >= 2 else ev.query
        out.append(("domain", domain))
    return out


def build_entity_profiles(
    events: List[ParsedEvent],
    findings: List[Finding],
    alerts: List[Alert],
) -> List[EntityProfile]:
    profiles: Dict[Tuple[str, str], Dict] = {}

    def _ensure(kind: str, value: str) -> Dict:
        key = (kind, value)
        if key not in profiles:
            profiles[key] = {
                "kind": kind,
                "value": value,
                "event_count": 0,
                "finding_count": 0,
                "alert_count": 0,
                "score": 0,
                "techs": set(),
                "first_seen": None,
                "last_seen": None,
                "observations": [],
            }
        return profiles[key]

    # Events drive event_count + first/last_seen
    for ev in events:
        for kind, value in _collect_entities(ev):
            p = _ensure(kind, value)
            p["event_count"] += 1
            ts = _ts_iso(ev.timestamp)
            if ts:
                if p["first_seen"] is None or ts < p["first_seen"]:
                    p["first_seen"] = ts
                if p["last_seen"] is None or ts > p["last_seen"]:
                    p["last_seen"] = ts

    # Findings drive finding_count + score + techniques
    for f in findings:
        seen_in_finding: Set[Tuple[str, str]] = set()
        for ev in f.matched_events:
            for kind, value in _collect_entities(ev):
                seen_in_finding.add((kind, value))
        for kind, value in seen_in_finding:
            p = _ensure(kind, value)
            p["finding_count"] += 1
            p["score"] = max(p["score"], f.score)
            for t in f.mitre_techniques:
                p["techs"].add(t)
            p["observations"].append(
                f"{f.severity}: {f.rule_name} ({f.rule_id})"
            )

    # Alerts drive alert_count
    for a in alerts:
        for ip in a.src_ips:
            p = _ensure("src_ip", ip)
            p["alert_count"] += 1

    out: List[EntityProfile] = []
    for (kind, value), p in profiles.items():
        # Boost score by additional MITRE coverage and alert volume
        score = p["score"]
        score = min(100, score + min(p["alert_count"], 5) * 2)
        out.append(
            EntityProfile(
                entity_id=value,
                entity_type=kind,
                risk_score=score,
                severity=severity_from_score(score),
                event_count=p["event_count"],
                finding_count=p["finding_count"],
                alert_count=p["alert_count"],
                mitre_techniques=sorted(p["techs"]),
                first_seen=p["first_seen"],
                last_seen=p["last_seen"],
                observations=p["observations"][:8],
            )
        )
    out.sort(key=lambda p: (-p.risk_score, p.entity_type, p.entity_id))
    return out


def summarize_entities(profiles: List[EntityProfile]) -> Dict:
    high = [p for p in profiles if p.severity in ("high", "critical")]
    top = [
        {
            "entity_id": p.entity_id,
            "entity_type": p.entity_type,
            "risk_score": p.risk_score,
            "severity": p.severity,
            "finding_count": p.finding_count,
        }
        for p in profiles[:5]
    ]
    by_type: Dict[str, int] = defaultdict(int)
    for p in profiles:
        by_type[p.entity_type] += 1
    return {
        "total_entities": len(profiles),
        "high_risk_entities": len(high),
        "top_entities": top,
        "by_type": dict(by_type),
    }
