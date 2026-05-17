"""Project configuration and path resolution.

All paths are constrained to the project directory. No external services,
no real API keys, no real targets. Only local fake sample data.
"""
from __future__ import annotations

from pathlib import Path


PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
DATA_DIR: Path = PROJECT_ROOT / "data"
SAMPLE_LOGS_DIR: Path = DATA_DIR / "sample_logs"
MITRE_FILE: Path = DATA_DIR / "mitre" / "mitre_mapping.json"
RULES_FILE: Path = DATA_DIR / "detection_rules" / "rules.json"
EVALUATION_FILE: Path = DATA_DIR / "evaluation" / "detection_scenarios.json"
DATASETS_DIR: Path = DATA_DIR / "datasets"
DATASET_MANIFEST_FILE: Path = DATASETS_DIR / "dataset_manifest.json"
PLAYBOOKS_FILE: Path = DATA_DIR / "playbooks" / "playbooks.json"

ALLOWED_DATASET_IDS = {
    "benign_baseline",
    "brute_force_campaign",
    "web_attack_campaign",
    "dns_beacon_campaign",
    "multi_stage_intrusion",
    "noisy_false_positive",
}

ALLOWED_LOG_NAMES = {
    "auth.log",
    "web_access.log",
    "firewall.log",
    "dns.log",
    "mixed_security_events.log",
}

SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

DEFAULT_RISK_BASELINE = {
    "informational": 5,
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}


def resolve_sample_log(name: str) -> Path:
    """Resolve a sample log filename to a Path, blocking any traversal.

    Raises ValueError on suspicious input.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("log name must be a non-empty string")
    if "/" in name or "\\" in name or ".." in name:
        raise ValueError("invalid log name")
    if name not in ALLOWED_LOG_NAMES:
        raise ValueError(f"unknown sample log: {name}")
    candidate = (SAMPLE_LOGS_DIR / name).resolve()
    try:
        candidate.relative_to(SAMPLE_LOGS_DIR.resolve())
    except ValueError as exc:
        raise ValueError("path escapes sample log directory") from exc
    return candidate


def resolve_dataset(dataset_id: str) -> Path:
    """Resolve a dataset ID to a file path, blocking any traversal."""
    if not isinstance(dataset_id, str) or not dataset_id:
        raise ValueError("dataset_id must be a non-empty string")
    if "/" in dataset_id or "\\" in dataset_id or ".." in dataset_id:
        raise ValueError("invalid dataset_id")
    if dataset_id not in ALLOWED_DATASET_IDS:
        raise ValueError(f"unknown dataset: {dataset_id}")
    candidate = (DATASETS_DIR / f"{dataset_id}.log").resolve()
    try:
        candidate.relative_to(DATASETS_DIR.resolve())
    except ValueError as exc:
        raise ValueError("path escapes datasets directory") from exc
    return candidate
