# Threat Model

## Scope

A locally run, offline log analysis dashboard. The system parses bundled
sample logs (or analyst-pasted text), evaluates detection rules, and
returns structured findings.

## Assets

- The bundled sample logs (informational only, no real data).
- The detection rule set.
- The MITRE mapping reference.

## Trust boundaries

| Boundary | Description |
| -------- | ----------- |
| Analyst -> UI | Analyst types or pastes log text. Untrusted as data, but never executed. |
| UI -> Backend | HTTP over loopback only. CORS restricted to `localhost:5173`. |
| Backend -> Disk | Reads only files under `data/`, gated by `resolve_sample_log`. |

## Threats and mitigations

| ID | Threat | Mitigation |
| -- | ------ | ---------- |
| T01 | Path traversal in `/sample-logs/{name}` | Filename whitelist + `..` / `/` / `\` rejection. Tested. |
| T02 | Arbitrary file read via crafted name | `resolve_sample_log` confines to `SAMPLE_LOGS_DIR`. |
| T03 | XSS via log content reflected to UI | React text rendering is escaped by default; no `dangerouslySetInnerHTML`. |
| T04 | Regex denial of service | Rule patterns are bounded; not user-supplied at runtime. |
| T05 | Real LLM call leaking analyst data | No LLM client in dependencies. Asserted in tests. |
| T06 | Shell injection via summarizer | No `subprocess` in backend. Asserted in tests. |
| T07 | Accidental secret commit | `.gitignore` excludes `.env`, secret scan in security tests. |
| T08 | Sample logs leaking real data | All IPs are RFC 5737; domains are clearly synthetic (`.example`). |

## Out of scope

- Multi-user auth and RBAC.
- Persistence and audit log.
- Real ingestion pipelines.

## AI-assisted disclosure

The threat enumeration was drafted with AI assistance and reviewed by the
author. Final acceptance of risks rests with the author.
