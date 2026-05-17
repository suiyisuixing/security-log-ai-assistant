"""Playbook recommendations.

Loads the local playbook library and recommends playbooks based on
findings and (optionally) cases.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from .config import PLAYBOOKS_FILE
from .schemas import Case, Finding


def load_playbooks(path: Optional[Path] = None) -> List[Dict]:
    p = path or PLAYBOOKS_FILE
    return json.loads(p.read_text(encoding="utf-8")).get("playbooks", [])


def _matches_finding(playbook: Dict, finding: Finding) -> bool:
    if finding.rule_id in playbook.get("mapped_rules", []):
        return True
    if any(t in playbook.get("mapped_mitre", []) for t in finding.mitre_techniques):
        return True
    return False


def _matches_case(playbook: Dict, case: Case) -> bool:
    for rid in case.related_alert_ids:
        # Alert IDs include rule lineage only indirectly; we use mitre instead.
        pass
    return any(t in playbook.get("mapped_mitre", []) for t in case.mitre_techniques)


def recommend_playbooks(
    findings: List[Finding], cases: Optional[List[Case]] = None
) -> List[Dict]:
    library = load_playbooks()
    chosen: Dict[str, Dict] = {}
    for pb in library:
        evidence: List[str] = []
        for f in findings:
            if _matches_finding(pb, f):
                evidence.append(f"rule={f.rule_id}")
        if cases:
            for c in cases:
                if _matches_case(pb, c):
                    evidence.append(f"case={c.case_id}")
        if evidence:
            entry = dict(pb)
            entry["match_reasons"] = sorted(set(evidence))
            chosen[pb["id"]] = entry
    return list(chosen.values())


def summarize_playbook_recommendations(recommendations: List[Dict]) -> Dict:
    severities = Counter(p.get("severity") for p in recommendations)
    techs = Counter(t for p in recommendations for t in p.get("mapped_mitre", []))
    return {
        "total_recommended": len(recommendations),
        "severity_counts": dict(severities),
        "top_techniques": [
            {"technique_id": t, "count": c} for t, c in techs.most_common(5)
        ],
    }
