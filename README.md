# VulnMapper — Authorized Network Recon & Vulnerability Triage

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Dependencies](https://img.shields.io/badge/Dependencies-stdlib%20only-brightgreen)
![Status](https://img.shields.io/badge/Status-Active-success)

**Fast port scan + banner grab + service fingerprint + CVE triage + prioritized report — in one tool, with zero dependencies.**

VulnMapper is a defensive-security tool for **your own lab and for systems you have explicit written authorization to test**. Point it at a host, and in seconds it tells you which ports are open, what is (probably) running on them, which known CVEs match the detected versions, and what to fix first — as JSON and as a readable HTML report.

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
├── vulnmapper.py          # CLI entry point
├── src/
│   ├── safety.py          # allowlist + authorization enforcement
│   ├── scanner.py         # threaded TCP connect scan
│   ├── banner.py          # banner grab, service guess, version regex
│   ├── cve.py             # CVE matching + CVSS ordering
│   └── report.py          # JSON + HTML report generation
├── data/cve_db.json       # curated CVE database (25 entries)
├── samples/scan_localhost.json   # demo scan data
├── tests/test_vulnmapper.py      # unittest suite (20+ tests)
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
```

Covers: allowlist blocking a public IP (with and without the flag), allowlist + flag allowing a listed IP, localhost/private ranges, banner parsing (SSH / Apache / vsFTPd), service guessing, CVE matching (including the vsFTPd backdoor and a patched-version negative), CVSS ordering, port parsing, a live localhost scan against a real TCP listener, and a closed-port negative.

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
