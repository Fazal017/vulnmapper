"""CVE triage: match a fingerprinted service+version against the local
curated database (data/cve_db.json) and order findings by CVSS.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "cve_db.json"


def load_db(path: str | Path | None = None) -> list[dict]:
    db_path = Path(path) if path else DEFAULT_DB
    with open(db_path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["entries"] if isinstance(data, dict) else data


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Info"


def _version_matches(entry: dict, version: str, banner: str) -> bool:
    # A "generic" entry (e.g. Telnet / RDP) matches any banner for that service.
    if entry.get("affected_versions") == ["any"]:
        return True
    if version and version in entry.get("affected_versions", []):
        return True
    pattern = entry.get("version_regex", "")
    if pattern:
        haystack = f"{version} {banner}"
        try:
            if re.search(pattern, haystack, re.IGNORECASE):
                return True
        except re.error:
            pass
    return False


def match_cves(service: str, version: str, banner: str = "",
               entries: list[dict] | None = None) -> list[dict]:
    """Return matching CVE entries for a service, sorted by CVSS desc."""
    if entries is None:
        entries = load_db()
    matches = []
    for entry in entries:
        if entry.get("service", "").lower() != service.lower():
            continue
        if _version_matches(entry, version, banner):
            matches.append(entry)
    return sorted(matches, key=lambda e: (-float(e.get("cvss", 0)),
                                          SEVERITY_ORDER.get(e.get("severity", "Info"), 5)))


def triage(open_ports: list[dict], entries: list[dict] | None = None) -> list[dict]:
    """Attach matched CVEs to each open port and return findings sorted
    by highest CVSS first (ports with no match sort last)."""
    if entries is None:
        entries = load_db()
    findings = []
    for port_info in open_ports:
        cves = match_cves(port_info.get("service", ""), port_info.get("version", ""),
                          port_info.get("banner", ""), entries)
        findings.append({**port_info, "cves": cves,
                         "max_cvss": max((float(c.get("cvss", 0)) for c in cves), default=0.0)})
    return sorted(findings, key=lambda f: -f["max_cvss"])
