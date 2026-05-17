"""Timeline reconstruction from findings."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from .detectors import _parse_ts
from .schemas import Finding, TimelineEntry


def _ts_sort_key(ts: Optional[str]) -> datetime:
    parsed = _parse_ts(ts)
    if parsed is None:
        return datetime.max.replace(tzinfo=None)
    return parsed.replace(tzinfo=None)


def build_timeline(findings: List[Finding]) -> List[TimelineEntry]:
    entries: List[TimelineEntry] = []
    for f in findings:
        for ev in f.matched_events:
            summary_bits = [f.rule_name]
            if ev.source_ip:
                summary_bits.append(f"src={ev.source_ip}")
            if ev.dest_port:
                summary_bits.append(f"dport={ev.dest_port}")
            if ev.path:
                summary_bits.append(f"path={ev.path}")
            if ev.query:
                summary_bits.append(f"query={ev.query}")
            entries.append(
                TimelineEntry(
                    timestamp=ev.timestamp,
                    source_type=ev.source_type,
                    summary=" | ".join(summary_bits),
                    severity=f.severity,
                    rule_id=f.rule_id,
                )
            )
    entries.sort(key=lambda e: _ts_sort_key(e.timestamp))
    return entries
