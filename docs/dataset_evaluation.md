# Dataset Evaluation

v3 adds a synthetic attack dataset layer in `data/datasets/` with a
manifest at `data/datasets/dataset_manifest.json`. Each dataset has
an explicit `expected_findings`, `expected_mitre`, and
`expected_severity` so the platform can evaluate itself.

## Datasets

| ID | Log type | Expected severity | Notable contents |
| -- | -------- | ----------------- | ---------------- |
| `benign_baseline` | auth | informational | Normal successful logins |
| `brute_force_campaign` | auth | high | 12 failed-login attempts from 198.51.100.40 |
| `web_attack_campaign` | web | high | SQLi, XSS, traversal, admin probes, command injection |
| `dns_beacon_campaign` | dns | high | Periodic beacon, DGA-style subdomains, NXDOMAIN burst |
| `multi_stage_intrusion` | mixed | critical | Port scan + admin probes + SQLi + traversal + brute force + sudo + DNS beacon |
| `noisy_false_positive` | web | low | Crawlers, missing pages, legitimate admin |

## Endpoints

- `GET /datasets` — full manifest.
- `GET /datasets/{dataset_id}` — manifest + content for one dataset.
- `POST /datasets/analyze/{dataset_id}` — run parse + detect + score +
  MITRE enrichment and report match vs. expectation.

## Analysis output

```json
{
  "dataset_id": "...",
  "metadata": {...},
  "event_count": 12,
  "finding_count": 5,
  "matched_rule_ids": ["R001", "R002"],
  "matched_mitre_techniques": ["T1110"],
  "missing_rule_ids": [],
  "unexpected_rule_ids": [],
  "overall_score": 84,
  "overall_severity": "high",
  "expected_severity": "high",
  "highest_severity": "high",
  "findings": [...]
}
```

## Safety guarantees

- Every dataset declares `contains_real_data: false`.
- Every IP is in RFC 5737 or RFC 1918 (asserted in `tests/test_datasets.py`).
- No real domains; only `.example`, `.top`, etc.
- No real API key patterns (regex-scanned in tests).
