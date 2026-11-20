#!/usr/bin/env python3
"""VulnMapper v2 — Reachability-Aware Exposure Graph.

v1 asked "what is vulnerable?" and ranked by CVSS.  v2 asks "what is
vulnerable *and reachable from the internet on a path to a crown jewel?*"
and ranks by Exposure = CVSS x exploitability x reachability x asset
criticality.  A CVSS 9.8 on an isolated host ranks below a CVSS 7.5 on
the path to the database — patch the path first.

Usage:
    python vulnmapper_v2.py --topology samples/topology_enterprise.yaml \
        --scan samples/scan_enterprise.json --output reports/exposure.json --html
    python vulnmapper_v2.py --topology samples/topology_enterprise.yaml \
        --scan samples/scan_enterprise.json --output reports/exposure.json \
        --whatif patch_app_internal
    python vulnmapper_v2.py --topology samples/topology_enterprise.yaml \
        --scan samples/scan_enterprise.json --output reports/exposure.html \
        --whatif patch_smbv1,CVE-2019-0708

Demo data only: the topology and scan are samples.  No live scanning,
no exploit code, no payloads.  The v1 allowlist / safety rules still
apply to any real scan — v2 never scans a network itself.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src import __version__  # noqa: E402
from src.attack_graph import (  # noqa: E402
    choke_points, enumerate_paths, exploitable_map, load_scan,
    shortest_paths,
)
from src.combo import detect_toxic_combinations  # noqa: E402
from src.exposure import (  # noqa: E402
    load_exploitability, rank_findings, render_html_report, total_exposure,
)
from src.safety import ETHICAL_WARNING  # noqa: E402
from src.topology import load_topology  # noqa: E402
from src.whatif import parse_patch_list, simulate  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnmapper_v2",
        description="Reachability-aware exposure graph (v2) — rank by "
                    "exposure, not CVSS alone.")
    parser.add_argument("--topology", default="samples/topology_enterprise.yaml",
                        help="Topology YAML (default: samples/topology_enterprise.yaml)")
    parser.add_argument("--scan", default="samples/scan_enterprise.json",
                        help="Scan JSON (default: samples/scan_enterprise.json)")
    parser.add_argument("--output", default="reports/exposure.json",
                        help="Report path (.json or .html; default: reports/exposure.json)")
    parser.add_argument("--html", action="store_true",
                        help="Also write an HTML report next to a JSON --output")
    parser.add_argument("--whatif", default=None,
                        help="Patch simulation, comma-separated: named patches "
                             "(patch_smbv1, patch_app_internal, ...) or CVE ids")
    parser.add_argument("--max-path-length", type=int, default=4,
                        help="Maximum hosts in an attack path (default: 4)")
    parser.add_argument("--version", action="version",
                        version=f"VulnMapper {__version__}")
    args = parser.parse_args(argv)

    print("=" * 72)
    print(ETHICAL_WARNING)
    print("=" * 72)

    topology = load_topology(args.topology)
    scan_by_host = load_scan(args.scan)
    exploitable = exploitable_map(topology, scan_by_host)
    paths = enumerate_paths(topology, exploitable, max_length=args.max_path_length)
    ranked = rank_findings(exploitable, topology, paths, load_exploitability())
    chokes = choke_points(paths)
    combos = detect_toxic_combinations(exploitable)
    shortest = shortest_paths(paths, topology.crown_jewels)

    whatif = None
    if args.whatif:
        whatif = simulate(topology, exploitable, paths, ranked,
                          parse_patch_list(args.whatif))

    report = {
        "tool": "VulnMapper",
        "version": __version__,
        "engine": "v2-attack-path",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "topology": topology.name,
        "hosts": len(topology.hosts),
        "zones": sorted(topology.zones),
        "crown_jewels": topology.crown_jewels,
        "entry_points": topology.entry_points,
        "summary": {
            "attack_paths": len(paths),
            "cve_matches": sum(len(v) for v in exploitable.values()),
            "total_exposure": total_exposure(ranked),
            "choke_points": len(chokes),
            "toxic_combinations": len(combos),
        },
        "attack_paths": [{"path": p, "target": p[-1], "length": len(p)}
                         for p in paths],
        "shortest_paths": shortest,
        "choke_points": chokes,
        "exposure_ranking": ranked,
        "toxic_combinations": combos,
        "whatif": whatif,
        "disclaimer": ("Curated offline CVE / exploitability data only. "
                       "Absence of a match does NOT mean a service is safe — "
                       "verify against NVD. Demo topology and scan data only; "
                       "scan only systems you own or are authorized to test."),
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix.lower() == ".html":
        out.write_text(render_html_report(report), encoding="utf-8")
    else:
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        if args.html:
            html_path = out.with_suffix(".html")
            html_path.write_text(render_html_report(report), encoding="utf-8")
            print(f"Report written: {html_path}")
    print(f"Report written: {out}")

    print(f"\n[*] Topology: {topology.name} — {len(topology.hosts)} hosts, "
          f"zones {sorted(topology.zones)}, crown jewels {topology.crown_jewels}")
    print(f"[*] {len(paths)} attack path(s) to a crown jewel, "
          f"{sum(len(v) for v in exploitable.values())} CVE matches, "
          f"total exposure {total_exposure(ranked):.2f}")
    print("\nAttack paths (shortest first):")
    for p in paths:
        print("    " + " -> ".join(p))
    if chokes:
        print("\nChoke points (>50% of paths):")
        for c in chokes:
            print(f"    {c['host']}: {c['paths']}/{c['total_paths']} paths "
                  f"({c['share']:.0%})")
    print("\nTop exposure (not CVSS):")
    print(f"    {'EXPOSURE':<10}{'HOST':<16}{'CVE':<16}{'CVSS':<6}ON PATH?")
    for r in ranked[:8]:
        print(f"    {r['exposure']:<10.2f}{r['host']:<16}{r['cve']:<16}"
              f"{r['cvss']:<6}{'yes' if r['on_attack_path'] else 'no'}")
    if combos:
        print("\nToxic combinations:")
        for c in combos:
            print(f"    [!] {c['name']} ({c['severity']}) — hosts: "
                  f"{', '.join(c['hosts'])}")
    if whatif:
        print(f"\nWhat-if [{', '.join(whatif['patches_applied'])}]: "
              f"{whatif['paths_closed']}/{whatif['paths_before']} paths closed, "
              f"residual exposure {whatif['residual_exposure']:.2f} "
              f"(was {whatif['exposure_before']:.2f}). "
              f"Next best patch: {whatif['next_best_patch']} "
              f"(closes {whatif['next_best_paths_closed']} more).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
