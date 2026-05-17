"""Detection rule engine.

Supports several rule match types:
- regex: pattern matched against the raw event line
- threshold: count of pattern matches grouped by a field within a window
- port_scan: many distinct destination ports from one source
- path_scan: many distinct paths from one source
- dga: DGA-like DNS query detection
- beacon: repeated queries to the same domain
"""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import RULES_FILE
from .schemas import Finding, ParsedEvent


def load_detection_rules(path: Optional[Path] = None) -> List[Dict]:
    p = path or RULES_FILE
    data = json.loads(p.read_text(encoding="utf-8"))
    return data.get("rules", [])


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.fromisoformat(ts)
    except ValueError:
        pass
    # Apache style: 10/May/2026:08:00:01 +0000
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _event_field(ev: ParsedEvent, field: str) -> Optional[object]:
    mapping = {
        "source_ip": ev.source_ip,
        "dest_ip": ev.dest_ip,
        "dest_port": ev.dest_port,
        "user": ev.user,
        "path": ev.path,
        "user_agent": ev.user_agent,
        "query": ev.query,
        "client": ev.source_ip,
    }
    return mapping.get(field)


def _matches_source(rule: Dict, ev: ParsedEvent) -> bool:
    return rule.get("source_type") == ev.source_type


def _regex_rule(rule: Dict, events: List[ParsedEvent]) -> List[List[ParsedEvent]]:
    pat = re.compile(rule["pattern"])
    return [[ev] for ev in events if _matches_source(rule, ev) and pat.search(ev.raw)]


def _threshold_rule(rule: Dict, events: List[ParsedEvent]) -> List[List[ParsedEvent]]:
    pat = re.compile(rule["pattern"])
    group_by = rule.get("group_by", "source_ip")
    window = int(rule.get("window_seconds", 60))
    threshold = int(rule.get("threshold", 5))
    buckets: Dict[object, List[ParsedEvent]] = {}
    for ev in events:
        if not _matches_source(rule, ev):
            continue
        if not pat.search(ev.raw):
            continue
        key = _event_field(ev, group_by)
        if key is None:
            continue
        buckets.setdefault(key, []).append(ev)
    matches: List[List[ParsedEvent]] = []
    for _key, evs in buckets.items():
        sliced = _window_threshold(evs, window, threshold)
        if sliced:
            matches.append(sliced)
    return matches


def _window_threshold(
    events: List[ParsedEvent], window: int, threshold: int
) -> List[ParsedEvent]:
    if len(events) < threshold:
        return []
    parsed = [(ev, _parse_ts(ev.timestamp)) for ev in events]
    parsed.sort(key=lambda x: (x[1] is None, x[1]))
    timed = [p for p in parsed if p[1] is not None]
    if len(timed) < threshold:
        return [ev for ev, _ in parsed] if len(parsed) >= threshold else []
    for i in range(len(timed) - threshold + 1):
        start = timed[i][1]
        end = timed[i + threshold - 1][1]
        if (end - start).total_seconds() <= window:
            return [ev for ev, _ in timed]
    return []


def _port_scan_rule(rule: Dict, events: List[ParsedEvent]) -> List[List[ParsedEvent]]:
    group_by = rule.get("group_by", "source_ip")
    distinct_field = rule.get("distinct_field", "dest_port")
    threshold = int(rule.get("threshold", 8))
    window = int(rule.get("window_seconds", 60))
    buckets: Dict[object, List[ParsedEvent]] = {}
    for ev in events:
        if not _matches_source(rule, ev):
            continue
        if ev.action and ev.action != "DENY":
            continue
        key = _event_field(ev, group_by)
        if key is None:
            continue
        buckets.setdefault(key, []).append(ev)
    out: List[List[ParsedEvent]] = []
    for _key, evs in buckets.items():
        timed = [(ev, _parse_ts(ev.timestamp)) for ev in evs]
        timed = [(ev, t) for ev, t in timed if t is not None]
        timed.sort(key=lambda x: x[1])
        for i in range(len(timed)):
            window_evs = []
            distinct_vals = set()
            for j in range(i, len(timed)):
                if (timed[j][1] - timed[i][1]).total_seconds() > window:
                    break
                val = _event_field(timed[j][0], distinct_field)
                if val is not None:
                    distinct_vals.add(val)
                window_evs.append(timed[j][0])
            if len(distinct_vals) >= threshold:
                out.append(window_evs)
                break
    return out


def _path_scan_rule(rule: Dict, events: List[ParsedEvent]) -> List[List[ParsedEvent]]:
    return _port_scan_rule(rule, events)


def _dga_rule(rule: Dict, events: List[ParsedEvent]) -> List[List[ParsedEvent]]:
    min_length = int(rule.get("min_length", 15))
    out: List[List[ParsedEvent]] = []
    for ev in events:
        if not _matches_source(rule, ev):
            continue
        if not ev.query:
            continue
        label = ev.query.split(".")[0]
        if len(label) >= min_length and _shannon_entropy(label) >= 3.0:
            out.append([ev])
    return out


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def _beacon_rule(rule: Dict, events: List[ParsedEvent]) -> List[List[ParsedEvent]]:
    group_by = rule.get("group_by", "query")
    threshold = int(rule.get("threshold", 4))
    window = int(rule.get("window_seconds", 600))
    buckets: Dict[object, List[ParsedEvent]] = {}
    for ev in events:
        if not _matches_source(rule, ev):
            continue
        key = _event_field(ev, group_by)
        if key is None:
            continue
        buckets.setdefault(key, []).append(ev)
    out: List[List[ParsedEvent]] = []
    for _key, evs in buckets.items():
        timed = [(ev, _parse_ts(ev.timestamp)) for ev in evs]
        timed = [(ev, t) for ev, t in timed if t is not None]
        timed.sort(key=lambda x: x[1])
        if len(timed) < threshold:
            continue
        for i in range(len(timed) - threshold + 1):
            start = timed[i][1]
            end = timed[i + threshold - 1][1]
            if (end - start).total_seconds() <= window:
                out.append([ev for ev, _ in timed[i : i + threshold]])
                break
    return out


_MATCH_DISPATCH = {
    "regex": _regex_rule,
    "threshold": _threshold_rule,
    "port_scan": _port_scan_rule,
    "path_scan": _path_scan_rule,
    "dga": _dga_rule,
    "beacon": _beacon_rule,
}


def apply_rule(rule: Dict, events: List[ParsedEvent]) -> List[Finding]:
    match_type = rule.get("match_type")
    func = _MATCH_DISPATCH.get(match_type)
    if func is None:
        return []
    grouped = func(rule, events)
    findings: List[Finding] = []
    for matched in grouped:
        if not matched:
            continue
        findings.append(
            Finding(
                rule_id=rule["id"],
                rule_name=rule["name"],
                description=rule.get("description", ""),
                severity=rule.get("severity", "low"),
                source_type=rule.get("source_type", "unknown"),
                matched_events=matched,
                mitre_techniques=list(rule.get("mitre", [])),
            )
        )
    return findings


def detect_events(events: List[ParsedEvent], rules: Optional[List[Dict]] = None) -> List[Finding]:
    rules = rules if rules is not None else load_detection_rules()
    findings: List[Finding] = []
    for rule in rules:
        findings.extend(apply_rule(rule, events))
    return findings


def group_threshold_matches(
    events: List[ParsedEvent],
    pattern: str,
    group_by: str,
    threshold: int,
    window_seconds: int,
) -> List[List[ParsedEvent]]:
    """Public helper used in tests."""
    rule = {
        "match_type": "threshold",
        "source_type": events[0].source_type if events else "auth",
        "pattern": pattern,
        "group_by": group_by,
        "threshold": threshold,
        "window_seconds": window_seconds,
    }
    return _threshold_rule(rule, events)
