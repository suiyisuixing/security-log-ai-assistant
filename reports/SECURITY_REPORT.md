# Security Report — security-log-ai-assistant

## Scope

Self-review of the security posture of this local-only project.

## Threat model summary

This is an offline log analysis tool. There is no inbound user data from the
internet, no persistent storage, and no remote calls. The primary risks are:

1. Accidentally exposing real customer logs in the sample data.
2. Path traversal via API endpoints that load sample logs from disk.
3. Accidentally introducing a real LLM API key or external HTTP call.
4. The dashboard rendering attacker-controlled text from logs (XSS).

## Controls

- `app/config.resolve_sample_log` whitelists log filenames and refuses any
  string containing `..`, `/`, or `\`. Tests assert this behavior.
- No `subprocess`, `os.system`, `urllib.request`, `requests`, or `httpx`
  in the backend modules (asserted by `tests/test_security_boundaries.py`).
- All IPs in sample logs are in RFC 5737 test ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or RFC 1918
  private ranges. Tests scan every sample log and assert this.
- No API key patterns are present in source files (regex-scanned in tests).
- React renders log content via the JSX text channel, which escapes by
  default. No use of `dangerouslySetInnerHTML`.

## Findings

| ID | Area | Severity | Status |
| -- | ---- | -------- | ------ |
| S1 | CORS allows `localhost:5173` only | informational | accepted |
| S2 | No authentication on the API | informational | accepted (local-only) |
| S3 | Log content reflected in JSON responses | informational | escaped client-side |
| S4 | Regex DoS surface (catastrophic backtracking) | low | rules use bounded patterns; mitigations recommended for production |
| S5 | v2 endpoints accept analyst-supplied raw logs | informational | confined to parsing + detection; no eval, no shell |
| S6 | SOC report includes recommended actions | informational | actions are static templates; never executed |

## AI-assisted disclosure

This security review process was supported by AI tools for analysis and
documentation drafting. The final security posture and acceptance decisions
were made by the author.
