"""Safety / allowlist enforcement for VulnMapper.

Default policy (no flag needed):
  * 127.0.0.0/8 (localhost), ::1
  * 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (private lab ranges)

Anything else is treated as a PUBLIC / out-of-scope target and is REFUSED
unless BOTH conditions hold:
  1. the operator passes --i-have-authorization, AND
  2. the resolved target IP (or hostname) is listed in an allowlist file
     (one entry per line: IP, CIDR, or hostname; '#' = comment).

This is a deliberate, two-key design: a flag alone is not enough, and a
file entry alone is not enough.  It exists so a typo cannot turn a lab
scan into an unauthorized scan of someone else's infrastructure.
"""
from __future__ import annotations

import ipaddress
import socket

DEFAULT_ALLOWED = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

ETHICAL_WARNING = (
    "LEGAL / ETHICAL NOTICE — VulnMapper is for YOUR OWN lab and for systems\n"
    "you have EXPLICIT WRITTEN AUTHORIZATION to test. Scanning a system\n"
    "without authorization may be illegal (e.g. CFAA, Computer Misuse Act,\n"
    "PECA in Pakistan, and equivalent laws elsewhere). If you are unsure,\n"
    "STOP and get written permission first. No exploit code, brute-force,\n"
    "or payloads are included in this tool."
)


class AuthorizationError(ValueError):
    """Raised when a target is outside the authorized scope."""


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address (IPs pass through unchanged)."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise AuthorizationError(f"Cannot resolve target {target!r}: {exc}") from exc


def is_private_or_loopback(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in DEFAULT_ALLOWED) or ip.is_loopback or ip.is_private


def load_allowlist(path: str | None) -> list[str]:
    """Return allowlist entries (lower-cased, comments/blank lines removed)."""
    if not path:
        return []
    entries: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(line.lower())
    except FileNotFoundError:
        return []
    return entries


def _allowlist_matches(target: str, ip_str: str, entries: list[str]) -> bool:
    for entry in entries:
        if entry in (target.lower(), ip_str.lower()):
            return True
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if ipaddress.ip_address(ip_str) in network:
                return True
        except ValueError:
            continue  # hostname entry that did not match exactly
    return False


def check_target(target: str, *, allowlist_path: str | None = None,
                 i_have_authorization: bool = False) -> str:
    """Validate a target. Returns the resolved IP, or raises AuthorizationError.

    Public/out-of-scope targets require BOTH --i-have-authorization AND
    an allowlist entry.  Private/lab targets pass without either.
    """
    ip_str = resolve_target(target)
    if is_private_or_loopback(ip_str):
        return ip_str
    entries = load_allowlist(allowlist_path)
    if i_have_authorization and _allowlist_matches(target, ip_str, entries):
        return ip_str
    raise AuthorizationError(
        f"REFUSED: {target} ({ip_str}) is outside the default lab scope "
        "(localhost / 10.0.0.0/8 / 172.16.0.0/12 / 192.168.0.0/16).\n"
        "To scan it you need BOTH:\n"
        "  1. --i-have-authorization  (you confirm you hold written authorization), AND\n"
        f"  2. the target listed in your allowlist file"
        + (f" ({allowlist_path})" if allowlist_path else " (--allowlist allowlist.txt)")
        + ".\nIf you do not have authorization, do not scan this target."
    )
