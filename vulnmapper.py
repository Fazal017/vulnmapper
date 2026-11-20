#!/usr/bin/env python3
"""VulnMapper — Authorized Network Recon & Vulnerability Triage Tool.

Usage:
    python vulnmapper.py --target 127.0.0.1 --ports 22,80,443,8080
    python vulnmapper.py --target 192.168.1.10 --ports 1-1024 --fast
    python vulnmapper.py --target 127.0.0.1 --ports 22,80 --output report.json
    python vulnmapper.py --target 127.0.0.1 --ports 22,80 --output report.html
    python vulnmapper.py --demo
    python vulnmapper.py --demo-data --output report.html

Scan ONLY systems you own or have explicit written authorization to test.
Default scope is localhost + private lab ranges. Public IPs need BOTH
--i-have-authorization AND an allowlist entry (see allowlist.txt).
No exploit code, no brute-force, no payloads — connect scan + banner
grab + CVE triage from a local curated database only.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src import __version__  # noqa: E402
from src.banner import parse_banner  # noqa: E402
from src.cve import load_db, triage  # noqa: E402
from src.report import build_report, write_html, write_json  # noqa: E402
from src.safety import (  # noqa: E402
    AuthorizationError, ETHICAL_WARNING, check_target,
)
from src.scanner import COMMON_PORTS, parse_ports, scan  # noqa: E402

DEMO_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]


def print_warning() -> None:
    print("=" * 72)
    print(ETHICAL_WARNING)
    print("=" * 72)


def summarise(findings: list[dict]) -> None:
    if not findings:
        print("\nNo open ports found in the scanned range.")
        return
    print(f"\n{'PORT':<8}{'SERVICE':<12}{'VERSION':<16}{'CVEs':<6}BANNER")
    print("-" * 72)
    for f in findings:
        cves = f.get("cves", [])
        top = f" [TOP: {cves[0]['cve']} CVSS {cves[0]['cvss']}]" if cves else ""
        banner = (f.get("banner") or "").replace("\r", " ").replace("\n", " ")[:60]
        print(f"{f['port']:<8}{f.get('service',''):<12}{f.get('version',''):<16}"
              f"{len(cves):<6}{banner}{top}")
    critical = [c for f in findings for c in f.get("cves", [])
                if c.get("severity") == "Critical"]
    if critical:
        print(f"\n[!] {len(critical)} CRITICAL CVE match(es) — patch / disable first:")
        for c in critical:
            print(f"    {c['cve']} (CVSS {c['cvss']}) — {c['title']}. Fix: {c['fix']}")


def _load_demo_data(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnmapper",
        description="Authorized network recon & vulnerability triage (lab use only).")
    parser.add_argument("--target", default="127.0.0.1",
                        help="Target host/IP (default: 127.0.0.1)")
    parser.add_argument("--ports", default="22,80,443,8080",
                        help="Ports: '22,80,443' or '1-1024' (default: 22,80,443,8080)")
    parser.add_argument("--fast", action="store_true",
                        help="Scan the common-ports list instead of --ports")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port connect timeout in seconds (default: 1.0)")
    parser.add_argument("--workers", type=int, default=50,
                        help="Concurrent scan threads (default: 50)")
    parser.add_argument("--output", default=None,
                        help="Report path: report.json or report.html (extension decides format; "
                             "use --output report.json --html for both)")
    parser.add_argument("--html", action="store_true",
                        help="Also write an HTML report next to a JSON --output")
    parser.add_argument("--allowlist", default="allowlist.txt",
                        help="Allowlist file for out-of-scope targets (default: allowlist.txt)")
    parser.add_argument("--i-have-authorization", action="store_true",
                        help="Confirm you hold written authorization for a non-lab target. "
                             "Required together with an allowlist entry.")
    parser.add_argument("--demo", action="store_true",
                        help="Demo mode: scan localhost on common ports (no server needed)")
    parser.add_argument("--demo-data", action="store_true",
                        help="Demo mode: build a report from samples/scan_localhost.json "
                             "without scanning anything")
    parser.add_argument("--version", action="version", version=f"VulnMapper {__version__}")
    args = parser.parse_args(argv)

    print_warning()

    # --- Demo-data mode: no network at all, reviewers see a full report ---
    if args.demo_data:
        sample = Path(__file__).resolve().parent / "samples" / "scan_localhost.json"
        data = _load_demo_data(sample)
        entries = load_db()
        findings = []
        for raw in data["findings"]:
            parsed = parse_banner(raw["port"], raw.get("banner", ""))
            findings.append({**raw, **parsed})
        findings = triage(findings, entries)
        report = build_report(data.get("target", "127.0.0.1"),
                              data.get("resolved_ip", "127.0.0.1"),
                              findings, data.get("scanned_ports_list", []), 0.0)
        out = Path(args.output) if args.output else Path("reports/demo-report.json")
        if out.suffix.lower() == ".html":
            write_html(report, out)
        else:
            write_json(report, out)
            if args.html:
                write_html(report, out.with_suffix(".html"))
        print(f"[demo-data] Loaded {sample} — {len(findings)} open ports, "
              f"{sum(len(f['cves']) for f in findings)} CVE matches.")
        summarise(findings)
        print(f"\nReport written: {out}")
        return 0

    target = "127.0.0.1" if args.demo else args.target
    ports = DEMO_PORTS if (args.demo or args.fast) else parse_ports(args.ports)

    try:
        resolved = check_target(target, allowlist_path=args.allowlist,
                                i_have_authorization=args.i_have_authorization)
    except AuthorizationError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 2

    print(f"[*] Target: {target} ({resolved}) — scanning {len(ports)} port(s)…")
    start = time.time()
    open_ports = scan(resolved, ports, timeout=args.timeout, workers=args.workers)
    findings = triage(open_ports, load_db())
    duration = time.time() - start
    report = build_report(target, resolved, findings, ports, duration)
    summarise(findings)
    print(f"\n[*] Done in {duration:.2f}s — {len(findings)} open / {len(ports)} scanned, "
          f"{report['summary']['total_cve_matches']} CVE matches, "
          f"highest CVSS {report['summary']['highest_cvss']}.")

    if args.output:
        out = Path(args.output)
        if out.suffix.lower() == ".html":
            write_html(report, out)
            print(f"Report written: {out}")
        else:
            write_json(report, out)
            print(f"Report written: {out}")
            if args.html:
                html_path = out.with_suffix(".html")
                write_html(report, html_path)
                print(f"Report written: {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
