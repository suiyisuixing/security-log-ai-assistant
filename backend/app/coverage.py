"""Detection coverage matrix over MITRE techniques."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from .detectors import load_detection_rules
from .mitre import load_mitre_mapping
from .schemas import CoverageEntry


def build_detection_coverage_matrix(
    rules: Optional[List[Dict]] = None,
    mitre_mapping: Optional[Dict[str, Dict]] = None,
) -> List[CoverageEntry]:
    rules = rules if rules is not None else load_detection_rules()
    mitre_mapping = mitre_mapping if mitre_mapping is not None else load_mitre_mapping()
    coverage_index: Dict[str, List[str]] = defaultdict(list)
    for r in rules:
        for t in r.get("mitre", []):
            coverage_index[t].append(r["id"])

    out: List[CoverageEntry] = []
    for tid, info in sorted(mitre_mapping.items()):
        rule_ids = sorted(set(coverage_index.get(tid, [])))
        covered = bool(rule_ids)
        if not covered:
            strength = "none"
        elif len(rule_ids) >= 2:
            strength = "strong"
        else:
            strength = "partial"
        out.append(
            CoverageEntry(
                technique_id=tid,
                technique_name=info.get("name", ""),
                tactic=info.get("tactic", ""),
                covered=covered,
                rule_ids=rule_ids,
                coverage_strength=strength,
            )
        )
    return out


def summarize_coverage(matrix: List[CoverageEntry]) -> Dict:
    total = len(matrix)
    covered = sum(1 for e in matrix if e.covered)
    by_tactic: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"covered": 0, "total": 0}
    )
    for e in matrix:
        by_tactic[e.tactic]["total"] += 1
        if e.covered:
            by_tactic[e.tactic]["covered"] += 1
    return {
        "total_techniques": total,
        "covered": covered,
        "uncovered": total - covered,
        "coverage_rate": round(covered / total, 4) if total else 0.0,
        "by_tactic": {k: v for k, v in by_tactic.items()},
    }
