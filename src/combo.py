"""Toxic combination detection for VulnMapper v2.

A single medium CVE is a patch ticket.  Several medium findings that
*co-exist in the same estate* can chain into something worse than any one
of them — that is a toxic combination.  Detection is estate-wide (not
limited to one host, and not limited to hosts already on an attack path):
a phishing foothold on a workstation can chain conditions that the
internet-facing scan alone would never connect.

Each combination is a set of conditions; a condition matches when a CVE
(or service) is present on any host in the estate.  No exploit code —
this only reads the CVE matches the v1 triage already produced.
"""
from __future__ import annotations

# Each combo: id, name, severity, description, conditions.
# A condition is {"cve": ...} or {"service": ...} or {"cve": ..., "service": ...}.
TOXIC_COMBOS: list[dict] = [
    {
        "id": "lateral-movement-chain",
        "name": "Lateral-movement chain (SMBv1 + weak SSH + exposed RDP)",
        "severity": "Critical",
        "description": (
            "SMBv1 gives unauthenticated RCE on a file host, weak SSH gives a "
            "second foothold with a known leak, and exposed RDP gives an "
            "interactive desktop. Together they are a lateral-movement chain: "
            "one foothold can spread host-to-host without any new vulnerability."),
        "conditions": [
            {"cve": "CVE-2017-0144"},
            {"cve": "CVE-2016-0777"},
            {"cve": "CVE-2019-0708"},
        ],
    },
    {
        "id": "web-rce-plus-database",
        "name": "Web RCE + reachable database",
        "severity": "High",
        "description": (
            "A remote-code-execution flaw on a web host plus a database with a "
            "known flaw on a host the web tier can reach: compromise the web "
            "tier and the database is one step away, not a separate breach."),
        "conditions": [
            {"cve": "CVE-2021-41773"},
            {"cve": "CVE-2016-6662"},
        ],
    },
    {
        "id": "cleartext-plus-backdoor",
        "name": "Cleartext service + backdoored service",
        "severity": "High",
        "description": (
            "A cleartext service (credentials on the wire) plus a backdoored "
            "service (a known trigger gives a shell): credentials harvested "
            "from one can be tried against the other."),
        "conditions": [
            {"cve": "CVE-2020-10188"},
            {"cve": "CVE-2011-2523"},
        ],
    },
    {
        "id": "mail-rce-plus-web-rce",
        "name": "Two internet-facing RCEs (mail + web)",
        "severity": "High",
        "description": (
            "Two separate internet-facing remote-code-execution flaws: the "
            "estate has two independent front doors, so patching only one "
            "leaves the other open."),
        "conditions": [
            {"cve": "CVE-2019-15846"},
            {"cve": "CVE-2020-1938"},
        ],
    },
]


def _condition_matches(condition: dict, exploitable: dict[str, list[dict]]):
    """Return the host(s) where this condition is present, else []."""
    hosts = []
    for host, cves in exploitable.items():
        for cve in cves:
            if "cve" in condition and cve["cve"] != condition["cve"]:
                continue
            if "service" in condition and cve.get("service") != condition["service"]:
                continue
            hosts.append(host)
            break
    return hosts


def detect_toxic_combinations(exploitable: dict[str, list[dict]]) -> list[dict]:
    """Return every toxic combination whose conditions are all present."""
    found = []
    for combo in TOXIC_COMBOS:
        matched_hosts: list[str] = []
        matched_cves: list[str] = []
        ok = True
        for cond in combo["conditions"]:
            hosts = _condition_matches(cond, exploitable)
            if not hosts:
                ok = False
                break
            matched_hosts.extend(hosts)
            if "cve" in cond:
                matched_cves.append(cond["cve"])
        if ok:
            found.append({
                "id": combo["id"],
                "name": combo["name"],
                "severity": combo["severity"],
                "description": combo["description"],
                "hosts": sorted(set(matched_hosts)),
                "cves": matched_cves,
            })
    return found
