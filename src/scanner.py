"""Threaded TCP connect scanner (stdlib sockets only).

Connect scan only: a completed TCP handshake tells us the port is open.
No SYN scan (needs raw sockets / root), no brute-force, no exploits.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from .banner import grab_banner, parse_banner

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379,
                8000, 8080, 8443, 27017]


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or '22,80,8000-8010' into sorted ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Invalid port range: {part!r}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port: {port}")
            ports.add(port)
    if not ports:
        raise ValueError("No ports specified")
    if len(ports) > 10000:
        raise ValueError("Refusing to scan more than 10,000 ports in one run")
    return sorted(ports)


def _scan_one(target: str, port: int, timeout: float) -> dict | None:
    """Return a result dict for an open port, or None if closed/filtered."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            banner = grab_banner(sock, port, timeout=timeout)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    parsed = parse_banner(port, banner)
    return {"port": port, "state": "open", "banner": banner, **parsed}


def scan(target: str, ports: list[int], timeout: float = 1.0,
         workers: int = 50) -> list[dict]:
    """Scan ports concurrently. Returns open-port results, sorted by port."""
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_one, target, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)
    return sorted(results, key=lambda r: r["port"])
