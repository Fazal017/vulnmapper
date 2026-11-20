"""Network topology input for VulnMapper v2.

A topology describes the estate the scan is triaged *in*: hosts, zones,
trust relationships, firewall rules, and crown-jewel assets.  v1 answered
"what is vulnerable?"; v2 answers "what is vulnerable *and reachable from
the internet on a path to something that matters?*"

Format — a small YAML subset, parsed here with stdlib only (no PyYAML):
top-level keys, ``key: value`` scalars, inline lists ``[a, b]``,
block lists (``- name: ...``) and nested block maps / lists, with
``#`` comments.  Anything outside that subset raises ValueError.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TOPOLOGY = Path(__file__).resolve().parent.parent / "data" / "topology.yaml"

_SCALAR_INT = re.compile(r"^-?\d+$")
_SCALAR_FLOAT = re.compile(r"^-?\d+\.\d+$")


def _parse_scalar(raw: str):
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(p) for p in _split_inline(inner)]
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    if raw in ("true", "True"):
        return True
    if raw in ("false", "False"):
        return False
    if raw in ("null", "Null", "~"):
        return None
    if _SCALAR_INT.match(raw):
        return int(raw)
    if _SCALAR_FLOAT.match(raw):
        return float(raw)
    return raw


def _split_inline(text: str) -> list[str]:
    parts, buf, quote = [], "", None
    for ch in text:
        if quote:
            buf += ch
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote, buf = ch, buf + ch
        elif ch == ",":
            parts.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    return parts


def _split_key(content: str) -> tuple[str, str]:
    """Split 'key: value' / 'key:' — first colon followed by space or EOL."""
    for i, ch in enumerate(content):
        if ch == ":" and (i + 1 == len(content) or content[i + 1] == " "):
            return content[:i].strip(), content[i + 1:].strip()
    raise ValueError(f"not a key/value line: {content!r}")


def _parse_block(lines: list[tuple[int, str]], i: int, indent: int):
    """Parse one block (list or dict) starting at lines[i] (indent given)."""
    if i >= len(lines):
        return None, i
    first = lines[i][1]
    if first == "-" or first.startswith("- "):
        result: list = []
        while i < len(lines) and lines[i][0] == indent and (
            lines[i][1] == "-" or lines[i][1].startswith("- ")
        ):
            content = lines[i][1][1:].strip()
            if not content:
                i += 1
                if i < len(lines) and lines[i][0] > indent:
                    item, i = _parse_block(lines, i, lines[i][0])
                    result.append(item)
                else:
                    result.append(None)
                continue
            if ":" in content:
                item: dict = {}
                key, val = _split_key(content)
                i += 1
                if val == "":
                    if i < len(lines) and lines[i][0] > indent:
                        item[key], i = _parse_block(lines, i, lines[i][0])
                    else:
                        item[key] = None
                else:
                    item[key] = _parse_scalar(val)
                # Remaining keys of this dict item live at a deeper indent.
                while i < len(lines) and lines[i][0] > indent:
                    sub, i = _parse_block(lines, i, lines[i][0])
                    if isinstance(sub, dict):
                        item.update(sub)
                    else:
                        break
                result.append(item)
            else:
                result.append(_parse_scalar(content))
                i += 1
        return result, i
    result_dict: dict = {}
    while i < len(lines) and lines[i][0] == indent and not (
        lines[i][1] == "-" or lines[i][1].startswith("- ")
    ):
        key, val = _split_key(lines[i][1])
        i += 1
        if val == "":
            if i < len(lines) and lines[i][0] > indent:
                result_dict[key], i = _parse_block(lines, i, lines[i][0])
            else:
                result_dict[key] = None
        else:
            result_dict[key] = _parse_scalar(val)
    return result_dict, i


def parse_yaml_subset(text: str) -> dict:
    """Parse the small YAML subset used by topology files."""
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        stripped = raw.strip()
        # A '#' starts a comment only when preceded by a space (so URLs
        # and quoted strings survive); strip it for parsing.
        if " #" in stripped:
            stripped = stripped.split(" #", 1)[0].rstrip()
            if not stripped:
                continue
        lines.append((len(raw) - len(raw.lstrip(" ")), stripped))
    if not lines:
        return {}
    obj, _ = _parse_block(lines, 0, lines[0][0])
    if not isinstance(obj, dict):
        raise ValueError("topology file must be a top-level mapping")
    return obj


@dataclass
class Service:
    port: int
    service: str
    version: str = ""
    banner: str = ""


@dataclass
class Host:
    name: str
    ip: str = ""
    zone: str = "internal"
    internet_facing: bool = False
    criticality: int = 1
    isolated: bool = False
    services: list[Service] = field(default_factory=list)


@dataclass
class Topology:
    name: str = ""
    hosts: list[Host] = field(default_factory=list)
    trust: list[tuple[str, str]] = field(default_factory=list)
    firewall_rules: list[dict] = field(default_factory=list)
    crown_jewels: list[str] = field(default_factory=list)

    def host(self, name: str) -> Host | None:
        return next((h for h in self.hosts if h.name == name), None)

    @property
    def zones(self) -> set[str]:
        return {h.zone for h in self.hosts}

    @property
    def entry_points(self) -> list[str]:
        return [h.name for h in self.hosts if h.internet_facing]

    def is_firewall_denied(self, src: str, dst: str) -> bool:
        return any(
            r.get("from") == src and r.get("to") == dst
            and str(r.get("action", "")).lower() == "deny"
            for r in self.firewall_rules
        )


def topology_from_dict(data: dict) -> Topology:
    hosts = []
    for raw in data.get("hosts", []) or []:
        services = [
            Service(port=int(s.get("port", 0)), service=str(s.get("service", "")),
                    version=str(s.get("version", "")), banner=str(s.get("banner", "")))
            for s in (raw.get("services", []) or [])
        ]
        hosts.append(Host(
            name=str(raw.get("name", "")), ip=str(raw.get("ip", "")),
            zone=str(raw.get("zone", "internal")),
            internet_facing=bool(raw.get("internet_facing", False)),
            criticality=int(raw.get("criticality", 1)),
            isolated=bool(raw.get("isolated", False)),
            services=services))
    trust = [(str(t.get("from", "")), str(t.get("to", "")))
             for t in (data.get("trust", []) or [])]
    crown = [str(c) for c in (data.get("crown_jewels", []) or [])]
    return Topology(
        name=str(data.get("name", "")),
        hosts=hosts, trust=trust,
        firewall_rules=list(data.get("firewall_rules", []) or []),
        crown_jewels=crown)


def load_topology(path: str | Path | None = None) -> Topology:
    topo_path = Path(path) if path else DEFAULT_TOPOLOGY
    return topology_from_dict(parse_yaml_subset(topo_path.read_text(encoding="utf-8")))
