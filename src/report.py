"""JSON + HTML report generation."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_COLOUR = {"Critical": "#b91c1c", "High": "#ea580c",
                   "Medium": "#ca8a04", "Low": "#2563eb", "Info": "#64748b"}


def build_report(target: str, resolved_ip: str, findings: list[dict],
                 scanned_ports: list[int], duration_s: float) -> dict:
    total_cves = sum(len(f.get("cves", [])) for f in findings)
    critical = sum(1 for f in findings for c in f.get("cves", [])
                   if c.get("severity") == "Critical")
    return {
        "tool": "VulnMapper",
        "version": "1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "resolved_ip": resolved_ip,
        "scanned_ports": len(scanned_ports),
        "open_ports": len(findings),
        "duration_seconds": round(duration_s, 2),
        "summary": {
            "open_ports": len(findings),
            "total_cve_matches": total_cves,
            "critical_cve_matches": critical,
            "highest_cvss": max((f.get("max_cvss", 0.0) for f in findings), default=0.0),
        },
        "findings": findings,
        "disclaimer": ("Curated offline triage DB only. Absence of a match does "
                       "NOT mean a service is safe — verify against NVD. "
                       "Scan only systems you own or are authorized to test."),
    }


def write_json(report: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def _esc(value) -> str:
    return html.escape(str(value) if value is not None else "")


def render_html(report: dict) -> str:
    rows = ""
    for f in report["findings"]:
        if f.get("cves"):
            cve_html = "<br>".join(
                f"<b>{_esc(c['cve'])}</b> "
                f"<span style='color:{SEVERITY_COLOUR.get(c.get('severity'), '#64748b')}'>"
                f"{_esc(c.get('severity'))} {c.get('cvss')}</span> — "
                f"{_esc(c.get('title'))}<br><i>Fix: {_esc(c.get('fix'))}</i>"
                for c in f["cves"])
        else:
            cve_html = "<span style='color:#64748b'>No known CVE in local DB — verify manually</span>"
        rows += (f"<tr><td>{f['port']}</td><td>{_esc(f.get('service'))}</td>"
                 f"<td>{_esc(f.get('version'))}</td><td>{_esc(f.get('banner'))}</td>"
                 f"<td>{cve_html}</td></tr>\n")
    if not rows:
        rows = "<tr><td colspan='5'>No open ports found in the scanned range.</td></tr>"
    s = report["summary"]
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>VulnMapper Report — {_esc(report['target'])}</title>
<style>body{{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#111}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #cbd5e1;padding:8px;text-align:left;vertical-align:top}}
th{{background:#0f172a;color:#fff}}.badge{{display:inline-block;padding:2px 8px;border-radius:999px;background:#fee2e2;color:#991b1b;font-weight:700}}
footer{{color:#64748b;font-size:.85rem;margin-top:2rem}}</style></head>
<body>
<h1>VulnMapper Report</h1>
<p>Target: <b>{_esc(report['target'])}</b> ({_esc(report['resolved_ip'])}) &nbsp;·&nbsp;
Generated: {_esc(report['generated_at_utc'])}</p>
<p>Scanned <b>{report['scanned_ports']}</b> ports in {report['duration_seconds']}s —
<b>{s['open_ports']}</b> open, <b>{s['total_cve_matches']}</b> CVE matches
(<span class="badge">{s['critical_cve_matches']} critical</span>),
highest CVSS <b>{s['highest_cvss']}</b>.</p>
<table><tr><th>Port</th><th>Service</th><th>Version</th><th>Banner</th><th>CVE triage / remediation</th></tr>
{rows}</table>
<p><b>Remediation priority:</b> fix Critical findings first (patch / upgrade /
disable the service), then High, then Medium. Re-scan after patching to confirm.</p>
<footer>{_esc(report['disclaimer'])}</footer>
</body></html>"""


def write_html(report: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
    return path
