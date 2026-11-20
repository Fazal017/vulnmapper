# VulnMapper — Authorized Network Recon & Vulnerability Triage

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Dependencies](https://img.shields.io/badge/Dependencies-stdlib%20only-brightgreen)
![Status](https://img.shields.io/badge/Status-Active-success)

**Fast port scan + banner grab + service fingerprint + CVE triage + prioritized report — in one tool, with zero dependencies.**

VulnMapper is a defensive-security tool for **your own lab and for systems you have explicit written authorization to test**. Point it at a host, and in seconds it tells you which ports are open, what is (probably) running on them, which known CVEs match the detected versions, and what to fix first — as JSON and as a readable HTML report.

## v2.0 — Advanced: Attack-Path Graph (NEW)

**The original concept: Reachability-Aware Exposure, not CVSS alone.**

v1 ranked vulnerabilities by CVSS. That is how most scanners work — and it is
wrong in a specific, fixable way: a CVSS 9.8 on a host no attacker can reach
is less urgent than a CVSS 7.5 on the one path into your database. v2 models
the network as a graph and ranks by *exposure*, so the patch order changes.

```
Exposure = CVSS × exploitability × reachability × asset criticality
```

- **CVSS** — how bad the flaw is in isolation (0–10, from `data/cve_db.json`).
- **Exploitability** — how likely it is to be exploited in the wild (0–1,
  EPSS-like, from `data/exploitability.json`; public exploit yes/no).
- **Reachability** — 1.0 if the host sits on an attack path to a crown jewel,
  0.3 if it does not.
- **Asset criticality** — 1–5 from the topology (crown jewel = 5).

### What v2 adds

| v2 module | What it does |
|---|---|
| `src/topology.py` | Parses a network topology (`data/topology.yaml`, stdlib YAML subset): hosts, zones, trust edges, firewall rules, crown-jewel assets |
| `src/attack_graph.py` | Enumerates attack paths (BFS/DFS) from internet-facing entry points through exploitable services to crown jewels; shortest path, all paths up to length 4, choke points (hosts in >50% of paths) |
| `src/exposure.py` | Exposure scoring and ranking — see the formula above |
| `src/whatif.py` | Remediation simulation: "patch X → Y paths close", residual exposure, greedy next-best patch |
| `src/combo.py` | Toxic combination detection — medium findings that chain into something worse |

### Run v2 (demo data — no live network)

```bash
python vulnmapper_v2.py --topology samples/topology_enterprise.yaml \
  --scan samples/scan_enterprise.json --output reports/exposure.json --html

python vulnmapper_v2.py --topology samples/topology_enterprise.yaml \
  --scan samples/scan_enterprise.json --output reports/exposure.json \
  --whatif patch_app_internal
```

The enterprise sample is 8 hosts in 3 zones (DMZ, internal, crown-jewel).
v2 finds **7 attack paths** to the crown jewels. Shortest path to the database:
`mail-dmz → app-internal → db-crown` (3 hosts). Choke point:
**app-internal is on 6/7 paths (86%)** — patching or segmenting it closes
the most paths at once.

### Sample exposure ranking — the inversion

| Exposure | Host | CVE | CVSS | On path? |
|---|---|---|---|---|
| 31.00 | dc-crown | CVE-2017-7494 (Samba RCE) | 10.0 | yes |
| 25.34 | file-internal | CVE-2017-0144 (EternalBlue) | 8.8 | yes |
| 21.38 | app-internal | CVE-2024-6387 (regreSSHion) | 8.1 | yes |
| 13.65 | web-dmz | CVE-2021-41773 (Apache RCE) | 7.5 | yes |
| 5.53 | workstation | CVE-2019-0708 (BlueKeep) | 9.8 | no |
| **2.85** | **backup-isolated** | **CVE-2011-2523 (vsFTPd backdoor)** | **9.8** | **no** |

The vsFTPd backdoor is CVSS 9.8 — the highest score in the estate — but it
sits on an isolated backup host with no path to anything that matters, so its
exposure is 2.85 and it ranks **11th of 15**. The Apache flaw is "only" CVSS 7.5,
but it is on the path to the database, so its exposure is 13.65 and it ranks
7th. CVSS-only triage would patch the backup box first. Exposure triage
patches the path first.

### What-if example

Patching SMBv1 alone sounds like the obvious fix — it removes 25.34 exposure —
but it closes **0 of 7 paths**, because the file host is still exploitable
over SSH. The simulator says so, and recommends the next best patch instead:

```
What-if [patch_smbv1]: 0/7 paths closed, residual exposure 138.22 (was 163.56).
Next best patch: patch_app_internal (closes 6 more).
```

Patching `app-internal` (the choke point) closes **6/7 paths** and drops total
exposure from 163.56 to 97.13. That is the difference between "patch the
scariest CVE" and "patch the thing that closes the most attack paths".

### Toxic combinations

v2 also flags findings that are dangerous *together*, even when each one is
only medium on its own. In the enterprise sample it flags three, including:

- **Lateral-movement chain (Critical)** — SMBv1 + weak SSH + exposed RDP
  co-existing in the same estate: one foothold can spread host-to-host.
- **Web RCE + reachable database (High)** — Apache RCE plus a MySQL flaw on
  a host the web tier can reach.
- **Two internet-facing RCEs (High)** — Exim RCE plus Tomcat Ghostcat:
  two independent front doors, so patching only one leaves the other open.

v1 is unchanged and still works exactly as before (`python vulnmapper.py …`).
v2 is a second engine alongside it — `python vulnmapper_v2.py …` — built on
the same CVE database, the same safety rules, and the same demo-only data.
No exploit code, no live scanning beyond localhost/demo data.

> **LEGAL / ETHICAL NOTICE — READ FIRST**
> **Scan only systems you own or have explicit written authorization to test. Scanning without authorization may be illegal (e.g. CFAA, Computer Misuse Act, PECA in Pakistan). VulnMapper refuses public IPs by default, prints this warning on every run, and contains no exploit code, no brute-force, and no payloads.**

---

## What it is

| Step | What VulnMapper does |
|---|---|
| 1. Scope check | Refuses public IPs unless `--i-have-authorization` **and** an allowlist entry are both present |
| 2. Port scan | Threaded TCP connect scan (stdlib sockets only) |
| 3. Banner grab | Reads the service banner; sends a minimal `HEAD /` on HTTP ports |
| 4. Fingerprint | Guesses the service from port + banner, extracts the version with regexes |
| 5. CVE triage | Matches service + version against a local curated DB (`data/cve_db.json`, 25 entries) |
| 6. Report | Prioritized JSON + HTML report, ordered by CVSS, with a fix for every CVE |

## How it differs from nmap

| | nmap | VulnMapper |
|---|---|---|
| Port scan | Yes (SYN, needs root) | Yes (connect scan, no root) |
| Banner / version detection | Yes (`-sV`) | Yes |
| CVE triage | No (needs NSE scripts / Vulners) | **Built in — local curated DB, offline** |
| Prioritized report with fixes | No | **Yes — JSON + HTML, ordered by CVSS** |
| Safety guardrails | None | **Allowlist + authorization flag + warning on every run** |
| Dependencies | System install | **Python stdlib only** |

VulnMapper is not a replacement for nmap — it is the *triage layer on top of a scan*: it answers "what is open, what is it, is it known-vulnerable, and what do I fix first?"

## Install

```bash
git clone https://github.com/<your-username>/vulnmapper.git
cd vulnmapper
# No dependencies to install — Python 3.9+ only.
python3 --version
```

## Usage

```bash
# Scan localhost on specific ports
python vulnmapper.py --target 127.0.0.1 --ports 22,80,443,8080

# Scan a port range on a lab host
python vulnmapper.py --target 192.168.1.10 --ports 1-1024

# Fast scan of the common-ports list
python vulnmapper.py --target 192.168.1.10 --fast

# JSON report (and HTML alongside it)
python vulnmapper.py --target 127.0.0.1 --ports 22,80,443 --output reports/report.json --html

# HTML report only
python vulnmapper.py --target 127.0.0.1 --ports 22,80 --output reports/report.html

# Demo — scan localhost, no server needed
python vulnmapper.py --demo

# Demo data — build a full report from the bundled sample, no network at all
python vulnmapper.py --demo-data --output reports/demo-report.html
```

### Allowlist — how out-of-scope targets work

By default VulnMapper only scans **localhost and private lab ranges**:

- `127.0.0.0/8`, `::1`
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

Anything else is refused:

```bash
$ python vulnmapper.py --target 8.8.8.8 --ports 80
REFUSED: 8.8.8.8 (8.8.8.8) is outside the default lab scope ...
```

To scan an authorized external target you need **both**:

1. Add it to `allowlist.txt` (one IP / CIDR / hostname per line), **and**
2. Pass `--i-have-authorization`:

```bash
echo "203.0.113.10" >> allowlist.txt
python vulnmapper.py --target 203.0.113.10 --ports 22,80 \
  --allowlist allowlist.txt --i-have-authorization
```

One key alone is never enough — that is deliberate, so a typo cannot turn a lab scan into an unauthorized scan.

## Sample report

`--demo-data` produces a report like this (from `samples/scan_localhost.json`):

| Port | Service | Version | CVE triage |
|---|---|---|---|
| 21 | ftp | 2.3.4 | **CVE-2011-2523 — Critical 9.8** — vsFTPd 2.3.4 backdoor. Fix: remove immediately, reinstall from a trusted source. |
| 22 | ssh | 7.2p2 | **CVE-2016-0777 — Medium 6.5** — OpenSSH roaming leak. Fix: upgrade to 7.3+. |
| 80 | http | 2.4.49 | **CVE-2021-41773 — High 7.5** — Apache path traversal / RCE. Fix: upgrade to 2.4.51+. |
| 8080 | http | 1.18.0 | **CVE-2021-23017 — High 7.7** — nginx DNS resolver overflow. Fix: upgrade to 1.20.1+. |

Summary line from the JSON report:

```json
{
  "target": "127.0.0.1",
  "open_ports": 4,
  "summary": {
    "total_cve_matches": 4,
    "critical_cve_matches": 1,
    "highest_cvss": 9.8
  }
}
```

**Remediation priority:** Critical first (patch / upgrade / disable), then High, then Medium. Re-scan after patching to confirm the fix.

## Project structure

```
vulnmapper/
├── vulnmapper.py          # v1 CLI entry point
├── vulnmapper_v2.py       # v2 CLI — attack-path / exposure graph
├── src/
│   ├── safety.py          # allowlist + authorization enforcement
│   ├── scanner.py         # threaded TCP connect scan
│   ├── banner.py          # banner grab, service guess, version regex
│   ├── cve.py             # CVE matching + CVSS ordering
│   ├── report.py          # JSON + HTML report generation (v1)
│   ├── topology.py        # v2: topology YAML parser (stdlib only)
│   ├── attack_graph.py    # v2: attack-path enumeration + choke points
│   ├── exposure.py        # v2: Exposure scoring + HTML report
│   ├── whatif.py          # v2: remediation simulation, next-best patch
│   └── combo.py           # v2: toxic combination detection
├── data/
│   ├── cve_db.json            # curated CVE database (25 entries)
│   ├── exploitability.json    # EPSS-like exploitability per CVE (25 entries)
│   └── topology.yaml          # default enterprise topology
├── samples/
│   ├── scan_localhost.json        # v1 demo scan data
│   ├── scan_enterprise.json       # v2 demo scan (8 hosts)
│   └── topology_enterprise.yaml   # v2 demo topology (8 hosts, 3 zones)
├── tests/
│   ├── test_vulnmapper.py   # v1 unittest suite (22 tests)
│   └── test_v2.py           # v2 unittest suite (19 tests)
├── allowlist.txt          # out-of-scope targets (empty by default)
├── requirements.txt       # stdlib only — no dependencies
└── reports/               # generated reports (git-ignored)
```

## CVE database

`data/cve_db.json` is a **curated, offline** triage database — 25 entries covering OpenSSH, Apache, nginx, vsFTPd, ProFTPD, Samba/SMBv1, MySQL, MariaDB, PostgreSQL, Telnet, RDP, VNC, BIND, Postfix, Exim, Tomcat and IIS. Each entry maps a service + vulnerable version to a CVE ID, CVSS score, severity, description, fix, and NVD reference.

> **Absence of a match does NOT mean a service is safe.** The DB lists *known-vulnerable examples only*. Always verify against [NVD](https://nvd.nist.gov/) before acting, and keep the DB updated.

## Tests

```bash
python -m unittest discover -s tests -v
# Ran 41 tests — OK (22 v1 + 19 v2)
```

v1 covers: allowlist blocking a public IP (with and without the flag), allowlist + flag allowing a listed IP, localhost/private ranges, banner parsing (SSH / Apache / vsFTPd), service guessing, CVE matching (including the vsFTPd backdoor and a patched-version negative), CVSS ordering, port parsing, a live localhost scan against a real TCP listener, and a closed-port negative.

v2 covers: topology parsing (8 hosts, 3 zones, firewall denies), shortest path to the database, all paths ≤ 4 hosts ending at a crown jewel, choke-point detection, isolated host on no path, the exposure formula, the CVSS 9.8-isolated / CVSS 7.5-on-path ranking inversion, exploitability coverage for all 25 CVEs, what-if patching (choke-point patch closes 6/7 paths, single-CVE patch closes a small-topology path, next-best-patch recommendation), toxic-combination detection and its negative, and a CLI end-to-end run.

## Roadmap

- [ ] NVD API sync to refresh `data/cve_db.json` (opt-in, offline by default)
- [ ] Service detection for more protocols (Redis, MongoDB, MSSQL banners)
- [ ] `--top-ports 100` preset and scan-rate limiting
- [ ] CSV export alongside JSON/HTML
- [ ] Diff mode: compare two scans and show only what changed
- [ ] Optional authenticated checks (SSH version only — never credentials)

## License

MIT — see [LICENSE](LICENSE).

## Author

**Fazal Rahman** — CEH, BS Information Technology. Cybersecurity / ethical hacking.
