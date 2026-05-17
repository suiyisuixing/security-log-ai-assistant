"""Kill-chain view: map findings to canonical attack-lifecycle stages."""
from __future__ import annotations

from typing import Dict, List

from .mitre import load_mitre_mapping
from .schemas import CorrelatedIncident, Finding, KillChainStage, KillChainView


_KILL_CHAIN_ORDER = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "credential_access",
    "discovery",
    "lateral_movement",
    "command_and_control",
    "exfiltration",
    "impact",
]


_TACTIC_TO_STAGE = {
    "Reconnaissance": "reconnaissance",
    "Initial Access": "initial_access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege_escalation",
    "Defense Evasion": "execution",
    "Credential Access": "credential_access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral_movement",
    "Command and Control": "command_and_control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}


def _technique_stage(tid: str, mapping: Dict[str, Dict]) -> str:
    info = mapping.get(tid)
    if not info:
        return "discovery"
    tactic = info.get("tactic", "")
    return _TACTIC_TO_STAGE.get(tactic, "discovery")


def map_findings_to_kill_chain(
    findings: List[Finding],
) -> Dict[str, List[Finding]]:
    mapping = load_mitre_mapping()
    buckets: Dict[str, List[Finding]] = {s: [] for s in _KILL_CHAIN_ORDER}
    for f in findings:
        if not f.mitre_techniques:
            buckets.setdefault("discovery", []).append(f)
            continue
        seen_stages: set = set()
        for t in f.mitre_techniques:
            stage = _technique_stage(t, mapping)
            if stage in seen_stages:
                continue
            seen_stages.add(stage)
            buckets.setdefault(stage, []).append(f)
    return buckets


def build_kill_chain_view(
    findings: List[Finding],
    correlated_incidents: List[CorrelatedIncident] | None = None,
) -> KillChainView:
    buckets = map_findings_to_kill_chain(findings)
    stages: List[KillChainStage] = []
    observed_count = 0
    highest_stage = None
    for stage_name in _KILL_CHAIN_ORDER:
        finds = buckets.get(stage_name, [])
        observed = bool(finds)
        techs = sorted({t for f in finds for t in f.mitre_techniques})
        if observed:
            observed_count += 1
            highest_stage = stage_name
        stages.append(
            KillChainStage(
                stage=stage_name,
                findings=finds,
                mitre_techniques=techs,
                observed=observed,
                finding_count=len(finds),
            )
        )
    if observed_count == 0:
        narrative = "No kill-chain stages observed in the supplied data."
    else:
        observed_names = [s.stage for s in stages if s.observed]
        narrative = (
            f"Observed {observed_count} kill-chain stage(s): "
            + ", ".join(observed_names)
            + f". Highest reached: {highest_stage}."
        )
        if correlated_incidents:
            narrative += (
                f" {len(correlated_incidents)} correlated incident(s) recorded."
            )
    return KillChainView(
        stages=stages,
        observed_stage_count=observed_count,
        highest_stage=highest_stage,
        narrative=narrative,
    )
