"""Exposure scoring for VulnMapper v2 — rank by *exposure*, not by CVSS.

Exposure = CVSS x exploitability x reachability x asset_criticality

* CVSS — how bad the flaw is in isolation (0–10, from the CVE DB).
* exploitability — how likely it is to be exploited in the wild
  (0–1, EPSS-like, from ``data/exploitability.json``; 0.5 if unknown).
* reachability — 1.0 if the host sits on an attack path to a crown jewel,
  0.3 if it does not.  An isolated host can still be exploited, but it
  cannot be *used* to reach anything that matters, so it scores lower.
* asset_criticality — 1–5 from the topology (crown jewel = 5).

That is the whole point of v2: a CVSS 9.8 on an isolated backup box
(9.8 x 0.97 x 0.3 x 1 = 2.85) ranks *below* a CVSS 7.5 on the path to the
database (7.5 x 0.91 x 1.0 x 2 = 13.65).  CVSS-only triage would patch the
wrong one first.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .attack_graph import hosts_on_paths

DEFAULT_EXPLOITABILITY = (
    Path(__file__).resolve().parent.parent / "data" / "exploitability.json"
)
ISOLATED_REACHABILITY = 0.3
ON_PATH_REACHABILITY = 1.0
DEFAULT_EPSS = 0.5


def load_exploitability(path: str | Path | None = None) -> dict[str, dict]:
    exp_path = Path(path) if path else DEFAULT_EXPLOITABILITY
    with open(exp_path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("entries", {}) if isinstance(data, dict) else {}


def exposure_score(cvss: float, epss: float, reachability: float,
                   criticality: int | float) -> float:
    return round(float(cvss) * float(epss) * float(reachability)
                 * float(criticality), 2)


def rank_findings(exploitable: dict[str, list[dict]], topology,
                  paths: list[list[str]],
                  exploitability: dict[str, dict] | None = None) -> list[dict]:
    """One ranked row per (host, CVE), sorted by Exposure descending."""
    if exploitability is None:
        exploitability = load_exploitability()
    on_path = hosts_on_paths(paths)
    host_by_name = {h.name: h for h in topology.hosts}
    ranked: list[dict] = []
    for host_name, cves in exploitable.items():
        host = host_by_name.get(host_name)
        criticality = host.criticality if host else 1
        reachability = (ON_PATH_REACHABILITY if host_name in on_path
                        else ISOLATED_REACHABILITY)
        for cve in cves:
            info = exploitability.get(cve["cve"], {})
            epss = float(info.get("epss", DEFAULT_EPSS))
            ranked.append({
                "host": host_name,
                "zone": host.zone if host else "",
                "port": cve.get("port"),
                "service": cve.get("service", ""),
                "cve": cve["cve"],
                "title": cve.get("title", ""),
                "cvss": float(cve.get("cvss", 0)),
                "severity": cve.get("severity", ""),
                "epss": epss,
                "public_exploit": bool(info.get("public_exploit", False)),
                "reachability": reachability,
                "on_attack_path": host_name in on_path,
                "asset_criticality": criticality,
                "exposure": exposure_score(float(cve.get("cvss", 0)), epss,
                                           reachability, criticality),
                "fix": cve.get("fix", ""),
            })
    ranked.sort(key=lambda r: (-r["exposure"], -r["cvss"], r["host"], r["cve"]))
    return ranked


def total_exposure(ranked: list[dict]) -> float:
    return round(sum(r["exposure"] for r in ranked), 2)


def render_html_report(report: dict) -> str:
    def esc(v) -> str:
        return html.escape(str(v) if v is not None else "")

    path_rows = ""
    for p in report.get("attack_paths", []):
        path_rows += ("<tr><td>" + " → ".join(esc(h) for h in p["path"])
                      + f"</td><td>{len(p['path'])}</td>"
                      + f"<td>{esc(p['target'])}</td></tr>\n")
    if not path_rows:
        path_rows = "<tr><td colspan='3'>No attack path to a crown jewel found.</td></tr>"

    exp_rows = ""
    for r in report.get("exposure_ranking", []):
        exp_rows += (
            f"<tr><td><b>{r['exposure']:.2f}</b></td><td>{esc(r['host'])}</td>"
            f"<td>{esc(r['cve'])}</td><td>{r['cvss']}</td>"
            f"<td>{r['epss']}</td><td>{'yes' if r['on_attack_path'] else 'no'}</td>"
            f"<td>{r['asset_criticality']}</td>"
            f"<td>{esc(r['title'])}<br><i>Fix: {esc(r['fix'])}</i></td></tr>\n")
    if not exp_rows:
        exp_rows = "<tr><td colspan='8'>No CVE matches.</td></tr>"

    choke = ", ".join(
        f"{c['host']} ({c['share']:.0%} of paths)" for c in report.get("choke_points", []))
    combos = ""
    for c in report.get("toxic_combinations", []):
        combos += (f"<li><b>{esc(c['name'])}</b> ({esc(c['severity'])}) — "
                   f"{esc(c['description'])}<br>Hosts: {esc(', '.join(c['hosts']))}</li>\n")
    if not combos:
        combos = "<li>None detected.</li>"

    wi = report.get("whatif")
    wi_html = ""
    if wi:
        wi_html = (
            f"<h2>What-if: {esc(', '.join(wi['patches_applied']))}</h2>"
            f"<p>Paths closed: <b>{wi['paths_closed']}</b> of "
            f"{wi['paths_before']} (residual: {wi['paths_after']}). "
            f"Residual exposure: <b>{wi['residual_exposure']:.2f}</b> "
            f"(was {wi['exposure_before']:.2f}). "
            f"Next best patch: <b>{esc(wi['next_best_patch'] or '—')}</b> "
            f"(closes {wi['next_best_paths_closed']} more path(s)).</p>")

    s = report.get("summary", {})
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>VulnMapper v2 — Exposure Report</title>
<style>body{{font-family:system-ui,Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#111}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #cbd5e1;padding:8px;text-align:left;vertical-align:top}}
th{{background:#0f172a;color:#fff}}footer{{color:#64748b;font-size:.85rem;margin-top:2rem}}</style></head>
<body>
<h1>VulnMapper v2 — Reachability-Aware Exposure Report</h1>
<p>Topology: <b>{esc(report.get('topology', ''))}</b> &nbsp;·&nbsp;
Generated: {esc(report.get('generated_at_utc', ''))}</p>
<p><b>{s.get('attack_paths', 0)}</b> attack path(s) to a crown jewel, "
<b>{s.get('total_exposure', 0)}</b> total exposure, "
<b>{s.get('cve_matches', 0)}</b> CVE matches. "
Choke points: <b>{esc(choke or 'none')}</b>.</p>
<h2>Exposure ranking (not CVSS)</h2>
<p>Exposure = CVSS × exploitability × reachability × asset criticality.
A CVSS 9.8 on an isolated host can rank below a CVSS 7.5 on the path to the database.</p>
<table><tr><th>Exposure</th><th>Host</th><th>CVE</th><th>CVSS</th><th>EPSS</th>
<th>On path?</th><th>Criticality</th><th>Finding / fix</th></tr>
{exp_rows}</table>
<h2>Attack paths</h2>
<table><tr><th>Path</th><th>Hosts</th><th>Target</th></tr>
{path_rows}</table>
<h2>Toxic combinations</h2>
<ul>{combos}</ul>
{wi_html}
<footer>Curated offline CVE / exploitability data only. Absence of a match does NOT mean a service is safe — verify against NVD. Demo topology and scan data only; scan only systems you own or are authorized to test.</footer>
</body></html>"""
