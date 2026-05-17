"""Mock AI summarizer. Rule-based, no external model API calls.

This module produces a human-readable narrative summary using only local
data. The output deliberately resembles what an LLM might write, but no
external service is contacted.
"""
from __future__ import annotations

from collections import Counter
from typing import List

from .schemas import Finding


def summarize_findings(findings: List[Finding]) -> str:
    if not findings:
        return (
            "No suspicious activity detected in the analyzed logs. "
            "All observed events appear to match normal baseline behavior."
        )
    severities = Counter(f.severity for f in findings)
    techniques = Counter(t for f in findings for t in f.mitre_techniques)
    rule_names = Counter(f.rule_name for f in findings)
    actors = Counter()
    for f in findings:
        for ev in f.matched_events:
            if ev.source_ip:
                actors[ev.source_ip] += 1

    lines = []
    lines.append(
        f"Analysis surfaced {len(findings)} finding(s) across the supplied logs."
    )
    sev_parts = []
    for sev in ("critical", "high", "medium", "low", "informational"):
        if severities.get(sev):
            sev_parts.append(f"{severities[sev]} {sev}")
    if sev_parts:
        lines.append("Severity distribution: " + ", ".join(sev_parts) + ".")
    top_rules = ", ".join(name for name, _ in rule_names.most_common(3))
    if top_rules:
        lines.append(f"Most frequently triggered rules: {top_rules}.")
    if techniques:
        techs = ", ".join(t for t, _ in techniques.most_common(5))
        lines.append(f"MITRE ATT&CK techniques observed: {techs}.")
    if actors:
        top_actors = ", ".join(ip for ip, _ in actors.most_common(3))
        lines.append(f"Top source IP(s) of interest: {top_actors}.")
    crit_or_high = [f for f in findings if f.severity in ("critical", "high")]
    if crit_or_high:
        lines.append(
            "Recommended next steps: prioritize investigation of high-severity "
            "findings, validate against threat intelligence, and consider "
            "containment actions (account lock, IP block) for confirmed activity."
        )
    else:
        lines.append(
            "Recommended next steps: continue monitoring, tune detection "
            "thresholds, and verify there is no associated low-and-slow activity."
        )
    lines.append(
        "Note: this summary was produced by a local rule-based summarizer; "
        "no external LLM was contacted."
    )
    return "\n".join(lines)
