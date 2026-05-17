"""Local MITRE ATT&CK mapping helpers."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from .config import MITRE_FILE
from .schemas import Finding


def load_mitre_mapping(path: Optional[Path] = None) -> Dict[str, Dict]:
    p = path or MITRE_FILE
    data = json.loads(p.read_text(encoding="utf-8"))
    return data.get("techniques", {})


def enrich_findings_with_mitre(
    findings: List[Finding], mapping: Optional[Dict[str, Dict]] = None
) -> List[Finding]:
    mapping = mapping if mapping is not None else load_mitre_mapping()
    for f in findings:
        details = []
        for tid in f.mitre_techniques:
            info = mapping.get(tid)
            if info:
                details.append(info)
        f.mitre_details = details
    return findings


def list_techniques(mapping: Optional[Dict[str, Dict]] = None) -> List[Dict]:
    mapping = mapping if mapping is not None else load_mitre_mapping()
    return sorted(mapping.values(), key=lambda t: t["id"])
