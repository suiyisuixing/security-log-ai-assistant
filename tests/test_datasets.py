import ipaddress
import re

import pytest

from app.config import DATASETS_DIR, resolve_dataset
from app.evaluation import (
    analyze_dataset,
    evaluate_datasets,
    get_dataset_metadata,
    list_datasets,
    load_dataset_manifest,
)


def test_load_dataset_manifest_has_six_datasets():
    manifest = load_dataset_manifest()
    assert len(manifest["datasets"]) >= 6
    ids = {d["id"] for d in manifest["datasets"]}
    for required in (
        "benign_baseline",
        "brute_force_campaign",
        "web_attack_campaign",
        "dns_beacon_campaign",
        "multi_stage_intrusion",
        "noisy_false_positive",
    ):
        assert required in ids


def test_all_datasets_synthetic():
    for d in list_datasets():
        assert d["contains_real_data"] is False


def test_get_dataset_metadata_known():
    meta = get_dataset_metadata("brute_force_campaign")
    assert meta is not None
    assert meta["log_type"] == "auth"


def test_get_dataset_metadata_unknown_returns_none():
    assert get_dataset_metadata("nope") is None


def test_resolve_dataset_rejects_traversal():
    for bad in ("../etc/passwd", "..", "bogus", "/abs/path"):
        with pytest.raises(ValueError):
            resolve_dataset(bad)


def test_analyze_dataset_brute_force_high():
    res = analyze_dataset("brute_force_campaign")
    assert res["overall_severity"] in ("high", "critical")
    assert "R001" in res["matched_rule_ids"]
    assert "R002" in res["matched_rule_ids"]
    assert res["missing_rule_ids"] == []


def test_analyze_dataset_web_attack_campaign():
    res = analyze_dataset("web_attack_campaign")
    assert res["overall_severity"] in ("high", "critical")
    for rid in ("R004", "R005", "R006", "R008", "R019"):
        assert rid in res["matched_rule_ids"]


def test_analyze_dataset_benign_baseline_low():
    res = analyze_dataset("benign_baseline")
    assert res["overall_severity"] in ("informational", "low")
    assert res["finding_count"] == 0


def test_analyze_dataset_dns_beacon():
    res = analyze_dataset("dns_beacon_campaign")
    assert "R013" in res["matched_rule_ids"] or "R015" in res["matched_rule_ids"]


def test_analyze_dataset_multistage():
    res = analyze_dataset("multi_stage_intrusion")
    assert res["finding_count"] >= 4
    assert res["overall_severity"] in ("high", "critical")


def test_analyze_dataset_unknown_raises():
    with pytest.raises(ValueError):
        analyze_dataset("nope")


def test_dataset_ips_are_in_test_ranges():
    """All non-private IPs in datasets must be in RFC 5737 test ranges."""
    rfc5737 = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for d in list_datasets():
        path = resolve_dataset(d["id"])
        text = path.read_text(encoding="utf-8")
        for ip_str in ip_re.findall(text):
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_unspecified:
                continue
            assert any(ip in net for net in rfc5737), (
                f"non-test IP in {d['id']}: {ip_str}"
            )


def test_no_real_api_keys_in_datasets():
    suspicious = [
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    ]
    for d in list_datasets():
        path = resolve_dataset(d["id"])
        text = path.read_text(encoding="utf-8")
        for pat in suspicious:
            assert not pat.search(text)


def test_no_real_target_domains_in_datasets():
    banned = ["google.com", "facebook.com", "microsoft.com", "amazon.com", "apple.com", "github.com"]
    for d in list_datasets():
        path = resolve_dataset(d["id"])
        text = path.read_text(encoding="utf-8").lower()
        for b in banned:
            assert b not in text, f"real domain {b} in dataset {d['id']}"


def test_evaluate_datasets_returns_all():
    res = evaluate_datasets()
    assert res["total_datasets"] >= 6
    assert len(res["results"]) == res["total_datasets"]
