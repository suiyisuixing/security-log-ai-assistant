# Dataset

All sample data is synthetic, local, and small. There is no real
customer data and no real attack target.

## Files

| File | Source type | Notable patterns |
| ---- | ----------- | ---------------- |
| `data/sample_logs/auth.log` | SSH / sudo | brute force from `198.51.100.23`, invalid users, sudo on `/etc/shadow` |
| `data/sample_logs/web_access.log` | HTTP access | SQLi, XSS, traversal, admin probes, `sqlmap`/`Nikto` user agents, command injection |
| `data/sample_logs/firewall.log` | Stateful FW | port scan from `198.51.100.23`, repeated DENY from `198.51.100.50`, ALLOW to port 4444 |
| `data/sample_logs/dns.log` | DNS | DGA-style subdomains, NXDOMAIN burst from `10.0.0.30`, beacon to `beacon.evil-c2.example` |
| `data/sample_logs/mixed_security_events.log` | Multi-source | Curated end-to-end multistage activity for dashboard demos |

## IP space

- `192.0.2.0/24` (RFC 5737 TEST-NET-1) - benign clients
- `198.51.100.0/24` (RFC 5737 TEST-NET-2) - attacker actors
- `203.0.113.0/24` (RFC 5737 TEST-NET-3) - mixed external traffic
- `10.0.0.0/8` (RFC 1918) - internal targets

## Domains

- `*.example`, `*.example.com` — reserved by IANA for documentation.
- `suspicious-domain.top` and `evil-c2.example` — clearly synthetic;
  never resolve to real infrastructure.

## Disclosure

Sample data was hand-crafted for educational purposes. AI tools assisted
in drafting representative log lines; the author reviewed and finalized
every entry.
