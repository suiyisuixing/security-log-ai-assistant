"""Security boundary tests.

These tests assert that the project does not accidentally introduce
real attack surface: no real API keys, no real external targets, only
RFC 5737 test IP ranges in sample logs, and no path traversal.
"""
import ipaddress
import re
from pathlib import Path

import pytest

from app.config import (
    ALLOWED_LOG_NAMES,
    SAMPLE_LOGS_DIR,
    resolve_sample_log,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_resolve_sample_log_known():
    p = resolve_sample_log("auth.log")
    assert p.exists()


@pytest.mark.parametrize("bad", ["../etc/passwd", "..\\windows\\system32", "/etc/passwd", "foo/bar.log", ""])
def test_resolve_sample_log_rejects_traversal(bad):
    with pytest.raises(ValueError):
        resolve_sample_log(bad)


def test_allowed_log_names_match_disk():
    on_disk = {p.name for p in SAMPLE_LOGS_DIR.iterdir() if p.is_file()}
    assert ALLOWED_LOG_NAMES.issubset(on_disk)


def test_sample_ips_are_rfc5737_or_private():
    """All non-private IPs in sample logs must be in RFC 5737 test ranges."""
    rfc5737 = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for log_path in SAMPLE_LOGS_DIR.iterdir():
        if not log_path.is_file():
            continue
        text = log_path.read_text(encoding="utf-8")
        for ip_str in ip_re.findall(text):
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_unspecified:
                continue
            assert any(ip in net for net in rfc5737), f"non-test IP in {log_path.name}: {ip_str}"


def test_no_real_api_key_patterns_in_source():
    """No real API key patterns in repository source files."""
    suspicious_patterns = [
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
        re.compile(r"OPENAI_API_KEY\s*=\s*['\"][A-Za-z0-9_\-]{20,}"),
    ]
    scanned = 0
    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.parts)
        if parts & {".git", "node_modules", ".venv", "__pycache__", "dist", ".pytest_cache", ".vite"}:
            continue
        if path.suffix in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".zip"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue
        scanned += 1
        for pat in suspicious_patterns:
            assert not pat.search(text), f"possible real API key in {path}"
    assert scanned > 0


def test_no_external_http_calls_in_backend():
    backend_dir = PROJECT_ROOT / "backend" / "app"
    for py in backend_dir.glob("*.py"):
        src = py.read_text(encoding="utf-8")
        for pat in ("urllib.request", "urlopen(", "requests.get", "requests.post", "httpx.get", "httpx.post"):
            assert pat not in src, f"{py.name} appears to make external HTTP calls: {pat}"


def test_no_subprocess_in_backend():
    backend_dir = PROJECT_ROOT / "backend" / "app"
    for py in backend_dir.glob("*.py"):
        src = py.read_text(encoding="utf-8")
        assert "subprocess" not in src, f"{py.name} uses subprocess"
        assert "os.system(" not in src, f"{py.name} uses os.system"


def test_no_real_target_domains_in_sample_logs():
    """sample logs must not contain real production domains."""
    banned = ["google.com", "facebook.com", "microsoft.com", "amazon.com", "apple.com", "github.com"]
    for log_path in SAMPLE_LOGS_DIR.iterdir():
        if not log_path.is_file():
            continue
        text = log_path.read_text(encoding="utf-8").lower()
        for b in banned:
            assert b not in text, f"real domain {b} in sample log {log_path.name}"


def test_ai_disclosure_does_not_name_specific_llm_vendor():
    """README disclosure must not name specific LLM vendor brand names."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    banned = ["Claude", "Anthropic", "OpenAI", "GPT-4", "Gemini", "Ollama"]
    for b in banned:
        assert b not in readme, f"README mentions banned LLM vendor name: {b}"
