"""Log parsers for the supported sample log formats.

All parsers are pure functions over text and return ParsedEvent instances.
No external service calls. No shell execution.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from .config import resolve_sample_log
from .schemas import ParsedEvent


_AUTH_RE = re.compile(
    r"^(?P<ts>\S+)\s+sshd\[\d+\]:\s+(?P<rest>.+)$"
)
_AUTH_FAIL_RE = re.compile(
    r"Failed password for(?:\s+invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_AUTH_OK_RE = re.compile(
    r"Accepted (?:password|publickey) for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_SUDO_RE = re.compile(
    r"^(?P<ts>\S+)\s+sudo\[\d+\]:\s+(?P<user>\S+)\s+:\s+.*COMMAND=(?P<cmd>.+)$"
)

_WEB_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>.+?)\s+HTTP/\S+"\s+(?P<status>\d+)\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)

_FW_RE = re.compile(
    r"^(?P<ts>\S+)\s+fw\s+(?P<action>ALLOW|DENY)\s+src=(?P<src>\S+)\s+dst=(?P<dst>\S+)\s+proto=(?P<proto>\S+)\s+sport=(?P<sport>\d+)\s+dport=(?P<dport>\d+)"
)

_DNS_RE = re.compile(
    r"^(?P<ts>\S+)\s+dns\s+client=(?P<client>\S+)\s+query=(?P<query>\S+)\s+type=(?P<type>\S+)\s+response=(?P<response>\S+)"
)


def parse_auth_log_line(line: str) -> Optional[ParsedEvent]:
    line = line.strip()
    if not line:
        return None
    sudo_match = _SUDO_RE.match(line)
    if sudo_match:
        return ParsedEvent(
            source_type="auth",
            timestamp=sudo_match.group("ts"),
            user=sudo_match.group("user"),
            action="sudo",
            raw=line,
            extras={"command": sudo_match.group("cmd")},
        )
    sshd_match = _AUTH_RE.match(line)
    if not sshd_match:
        return None
    ts = sshd_match.group("ts")
    rest = sshd_match.group("rest")
    fail = _AUTH_FAIL_RE.search(rest)
    if fail:
        return ParsedEvent(
            source_type="auth",
            timestamp=ts,
            user=fail.group("user"),
            source_ip=fail.group("ip"),
            action="failed_login",
            raw=line,
        )
    ok = _AUTH_OK_RE.search(rest)
    if ok:
        return ParsedEvent(
            source_type="auth",
            timestamp=ts,
            user=ok.group("user"),
            source_ip=ok.group("ip"),
            action="successful_login",
            raw=line,
        )
    return ParsedEvent(source_type="auth", timestamp=ts, raw=line)


def parse_web_access_log_line(line: str) -> Optional[ParsedEvent]:
    line = line.strip()
    if not line:
        return None
    match = _WEB_RE.match(line)
    if not match:
        return None
    return ParsedEvent(
        source_type="web",
        timestamp=match.group("ts"),
        source_ip=match.group("ip"),
        method=match.group("method"),
        path=match.group("path"),
        status_code=int(match.group("status")),
        user_agent=match.group("ua"),
        raw=line,
    )


def parse_firewall_log_line(line: str) -> Optional[ParsedEvent]:
    line = line.strip()
    if not line:
        return None
    match = _FW_RE.match(line)
    if not match:
        return None
    return ParsedEvent(
        source_type="firewall",
        timestamp=match.group("ts"),
        source_ip=match.group("src"),
        dest_ip=match.group("dst"),
        dest_port=int(match.group("dport")),
        action=match.group("action"),
        raw=line,
        extras={
            "proto": match.group("proto"),
            "sport": int(match.group("sport")),
        },
    )


def parse_dns_log_line(line: str) -> Optional[ParsedEvent]:
    line = line.strip()
    if not line:
        return None
    match = _DNS_RE.match(line)
    if not match:
        return None
    return ParsedEvent(
        source_type="dns",
        timestamp=match.group("ts"),
        source_ip=match.group("client"),
        query=match.group("query"),
        response=match.group("response"),
        raw=line,
        extras={"type": match.group("type")},
    )


def parse_mixed_log_line(line: str) -> Optional[ParsedEvent]:
    line = line.strip()
    if not line:
        return None
    if line.startswith("AUTH "):
        return parse_auth_log_line(line[5:])
    if line.startswith("WEB "):
        return parse_web_access_log_line(line[4:])
    if line.startswith("FW "):
        return parse_firewall_log_line(line[3:])
    if line.startswith("DNS "):
        return parse_dns_log_line(line[4:])
    # Best-effort fallback: try each parser.
    for parser in (
        parse_auth_log_line,
        parse_web_access_log_line,
        parse_firewall_log_line,
        parse_dns_log_line,
    ):
        ev = parser(line)
        if ev is not None:
            return ev
    return None


_PARSER_DISPATCH = {
    "auth": parse_auth_log_line,
    "web": parse_web_access_log_line,
    "firewall": parse_firewall_log_line,
    "dns": parse_dns_log_line,
    "mixed": parse_mixed_log_line,
}


def parse_raw_logs(source_type: str, raw_logs: str) -> List[ParsedEvent]:
    if source_type not in _PARSER_DISPATCH:
        raise ValueError(f"unknown source_type: {source_type}")
    parser = _PARSER_DISPATCH[source_type]
    out: List[ParsedEvent] = []
    for line in raw_logs.splitlines():
        ev = parser(line)
        if ev is not None:
            out.append(ev)
    return out


_NAME_TO_SOURCE_TYPE = {
    "auth.log": "auth",
    "web_access.log": "web",
    "firewall.log": "firewall",
    "dns.log": "dns",
    "mixed_security_events.log": "mixed",
}


def source_type_for_sample(name: str) -> str:
    if name not in _NAME_TO_SOURCE_TYPE:
        raise ValueError(f"unknown sample log: {name}")
    return _NAME_TO_SOURCE_TYPE[name]


def parse_log_file(name: str) -> List[ParsedEvent]:
    path: Path = resolve_sample_log(name)
    source_type = source_type_for_sample(name)
    raw = path.read_text(encoding="utf-8")
    return parse_raw_logs(source_type, raw)
