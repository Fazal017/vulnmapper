"""Attack-path enumeration for VulnMapper v2.

Model: a directed graph.  Nodes are hosts.  An edge A -> B exists when a
trust relationship allows it AND no firewall rule denies it.  A node is
*traversable* when it has at least one matched CVE — an attacker who can
exploit a service on that host can (in this model) use it as a stepping
stone.  Paths start at an internet-facing entry point and end at a
crown-jewel host.  Paths are capped at ``max_length`` hosts so enumeration
stays finite on cyclic estates.

This is a *reachability* model, not an exploit chain: it says "an attacker
could get here", never "here is how to exploit it".  No exploit code,
no payloads, no live traffic.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from .cve import load_db, match_cves
from .topology import Topology

INTERNET = "internet"


def load_scan(path) -> dict[str, list[dict]]:
    """Scan file -> {host_name: [finding, ...]}.

    Accepts the v2 enterprise format ``{"hosts": [{"host": ..., "findings":
    [...]}, ...]}`` and the v1 flat format (single host, findings list).
    """
    import json
    from pathlib import Path

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: dict[str, list[dict]] = {}
    if "hosts" in data:
        for entry in data["hosts"]:
            out[str(entry.get("host", ""))] = list(entry.get("findings", []))
    elif "findings" in data:
        out[str(data.get("target", "127.0.0.1"))] = list(data["findings"])
    return out


def cves_for_host(host, scan_findings: list[dict] | None = None,
                  entries: list[dict] | None = None) -> list[dict]:
    """All CVE matches for a host — from scan findings if given, else from
    the services declared in the topology."""
    if entries is None:
        entries = load_db()
    findings = scan_findings
    if findings is None:
        findings = [{"port": s.port, "service": s.service,
                     "version": s.version, "banner": s.banner}
                    for s in host.services]
    seen: dict[str, dict] = {}
    for f in findings:
        for cve in match_cves(f.get("service", ""), f.get("version", ""),
                              f.get("banner", ""), entries):
            seen[cve["cve"]] = {**cve, "host": host.name,
                                "port": f.get("port"),
                                "service": f.get("service", "")}
    return sorted(seen.values(), key=lambda c: -float(c.get("cvss", 0)))


def exploitable_map(topology: Topology,
                    scan_by_host: dict[str, list[dict]] | None = None,
                    entries: list[dict] | None = None) -> dict[str, list[dict]]:
    """{host_name: [matched CVE, ...]} for every host with a match."""
    result = {}
    for host in topology.hosts:
        findings = (scan_by_host or {}).get(host.name)
        cves = cves_for_host(host, findings, entries)
        if cves:
            result[host.name] = cves
    return result


def adjacency(topology: Topology) -> dict[str, list[str]]:
    """Allowed edges, firewall denies applied.  'internet' is a pseudo-node."""
    adj: dict[str, list[str]] = defaultdict(list)
    for src, dst in topology.trust:
        if topology.is_firewall_denied(src, dst):
            continue
        if dst not in adj[src]:
            adj[src].append(dst)
    return dict(adj)


def enumerate_paths(topology: Topology,
                    exploitable: dict[str, list[dict]],
                    max_length: int = 4) -> list[list[str]]:
    """All attack paths, as host-name lists.

    A path starts at an internet-facing, exploitable entry point, visits
    only exploitable hosts, never repeats a host, is at most ``max_length``
    hosts long, and ends the first time it reaches a crown jewel.
    """
    adj = adjacency(topology)
    crowns = set(topology.crown_jewels)
    paths: list[list[str]] = []

    def dfs(current: str, path: list[str]) -> None:
        if current in crowns:
            paths.append(list(path))
            return
        if len(path) >= max_length:
            return
        for nxt in adj.get(current, []):
            if nxt in path or nxt not in exploitable:
                continue
            path.append(nxt)
            dfs(nxt, path)
            path.pop()

    for entry in topology.entry_points:
        if entry in exploitable:
            dfs(entry, [entry])
    # Deduplicate, keep deterministic order (shortest first, then lexical).
    unique = sorted({tuple(p) for p in paths}, key=lambda p: (len(p), p))
    return [list(p) for p in unique]


def shortest_paths(paths: list[list[str]],
                   crowns: list[str]) -> dict[str, list[str]]:
    """Shortest path to each crown jewel reached, if any."""
    best: dict[str, list[str]] = {}
    for path in sorted(paths, key=lambda p: (len(p), p)):
        target = path[-1]
        if target in crowns and target not in best:
            best[target] = path
    return best


def hosts_on_paths(paths: list[list[str]]) -> set[str]:
    return {h for p in paths for h in p}


def choke_points(paths: list[list[str]], threshold: float = 0.5) -> list[dict]:
    """Hosts appearing in more than ``threshold`` of all paths.

    A choke point is the highest-leverage place to defend: patching /
    segmenting it closes the most paths at once.
    """
    if not paths:
        return []
    counts = Counter(h for p in paths for h in set(p))
    total = len(paths)
    out = []
    for host, count in counts.most_common():
        share = count / total
        if share > threshold:
            out.append({"host": host, "paths": count,
                        "total_paths": total, "share": round(share, 3)})
    return out


def reachable_from_internet(topology: Topology) -> set[str]:
    """Hosts reachable from the internet over allowed edges, ignoring
    exploitability — the raw blast radius of the trust graph."""
    adj = adjacency(topology)
    seen, stack = set(), ["internet"]
    while stack:
        cur = stack.pop()
        for nxt in adj.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen
