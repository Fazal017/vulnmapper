"""Remediation simulation ("what-if") for VulnMapper v2.

Question answered: "if I patch X, how many attack paths close, how much
exposure is left, and what should I patch *next*?"

A patch is named (``patch_smbv1``, ``patch_app_internal`` …) or a raw CVE
id (``CVE-2017-0144``).  Named patches map to the CVEs — or, for a host
patch, to *all* CVEs on that host — they remove.  After removing them, a
host with no CVEs left is no longer traversable, paths are re-enumerated,
exposure is re-ranked, and the greedy next-best patch is the candidate
that closes the most remaining paths (ties broken by exposure removed).
"""
from __future__ import annotations

from .attack_graph import enumerate_paths, exploitable_map
from .exposure import load_exploitability, rank_findings, total_exposure

# Named patch -> (cves removed everywhere, hosts fully patched)
PATCHES: dict[str, dict] = {
    "patch_smbv1": {"cves": ["CVE-2017-0144"]},
    "patch_samba": {"cves": ["CVE-2017-7494"]},
    "patch_apache": {"cves": ["CVE-2021-41773", "CVE-2022-22720"]},
    "patch_tomcat": {"cves": ["CVE-2020-1938"]},
    "patch_ssh": {"cves": ["CVE-2016-0777", "CVE-2021-41617",
                           "CVE-2023-38408", "CVE-2024-6387"]},
    "patch_rdp": {"cves": ["CVE-2019-0708"]},
    "patch_vsftpd": {"cves": ["CVE-2011-2523"]},
    "patch_exim": {"cves": ["CVE-2019-15846"]},
    "patch_mysql": {"cves": ["CVE-2016-6662"]},
    "patch_nginx": {"cves": ["CVE-2021-23017", "CVE-2022-41741"]},
    "patch_app_internal": {"hosts": ["app-internal"]},
    "patch_web_dmz": {"hosts": ["web-dmz"]},
    "patch_file_internal": {"hosts": ["file-internal"]},
    "patch_db_crown": {"hosts": ["db-crown"]},
}


def parse_patch_list(raw: str | list[str]) -> list[str]:
    if isinstance(raw, str):
        return [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
    return [str(p).strip() for p in raw if str(p).strip()]


def resolve_patch(name: str, exploitable: dict[str, list[dict]]):
    """A patch name -> set of (host, cve) pairs it removes."""
    removed: set[tuple[str, str]] = set()
    if name.startswith("CVE-"):
        for host, cves in exploitable.items():
            if any(c["cve"] == name for c in cves):
                removed.add((host, name))
        return removed
    spec = PATCHES.get(name)
    if spec is None:
        raise ValueError(
            f"unknown patch {name!r} — known patches: {sorted(PATCHES)} "
            "or a CVE id such as CVE-2017-0144")
    for cve in spec.get("cves", []):
        for host, cves in exploitable.items():
            if any(c["cve"] == cve for c in cves):
                removed.add((host, cve))
    for host in spec.get("hosts", []):
        for cve in exploitable.get(host, []):
            removed.add((host, cve["cve"]))
    return removed


def _patched_exploitable(exploitable, removed: set[tuple[str, str]]):
    out = {}
    for host, cves in exploitable.items():
        kept = [c for c in cves if (host, c["cve"]) not in removed]
        if kept:
            out[host] = kept
    return out


def simulate(topology, exploitable, paths_before, ranked_before,
             patch_names: list[str]) -> dict:
    """Run a what-if: apply patches, recompute paths + exposure, and
    greedily find the next best patch."""
    exploitability = load_exploitability()
    removed: set[tuple[str, str]] = set()
    for name in patch_names:
        removed |= resolve_patch(name, exploitable)
    patched = _patched_exploitable(exploitable, removed)
    paths_after = enumerate_paths(topology, patched)
    ranked_after = rank_findings(patched, topology, paths_after, exploitability)
    before_set = {tuple(p) for p in paths_before}
    after_set = {tuple(p) for p in paths_after}
    closed = sorted(before_set - after_set)
    exposure_before = total_exposure(ranked_before)
    exposure_after = total_exposure(ranked_after)

    # Greedy next-best patch: try every remaining named patch and every
    # remaining CVE, pick the one closing the most paths (then most exposure).
    candidates: set[str] = set(PATCHES)
    candidates |= {c["cve"] for cves in patched.values() for c in cves}
    best_name, best_closed, best_exp_removed = None, 0, 0.0
    for cand in sorted(candidates):
        if cand in patch_names:
            continue
        try:
            extra = resolve_patch(cand, patched)
        except ValueError:
            continue
        if not extra:
            continue
        trial = _patched_exploitable(patched, extra)
        trial_paths = enumerate_paths(topology, trial)
        trial_ranked = rank_findings(trial, topology, trial_paths, exploitability)
        closed_n = len(after_set - {tuple(p) for p in trial_paths})
        exp_removed = round(exposure_after - total_exposure(trial_ranked), 2)
        if (closed_n, exp_removed) > (best_closed, best_exp_removed):
            best_name, best_closed, best_exp_removed = cand, closed_n, exp_removed
    return {
        "patches_applied": list(patch_names),
        "cves_removed": sorted({cve for _, cve in removed}),
        "hosts_fully_patched": sorted({h for h, cves in exploitable.items()
                                       if h not in patched}),
        "paths_before": len(paths_before),
        "paths_after": len(paths_after),
        "paths_closed": len(closed),
        "paths_closed_list": [list(p) for p in closed],
        "exposure_before": exposure_before,
        "residual_exposure": exposure_after,
        "exposure_removed": round(exposure_before - exposure_after, 2),
        "next_best_patch": best_name,
        "next_best_paths_closed": best_closed,
        "next_best_exposure_removed": best_exp_removed,
    }
