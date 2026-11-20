"""Banner grabbing, service fingerprinting and version extraction.

Pure stdlib.  No payloads: the only bytes sent are a bare CRLF (and a
minimal HTTP HEAD request on HTTP-like ports, which is what any browser
or curl would send when fetching a page).
"""
from __future__ import annotations

import re
import socket

# Well-known ports -> (service, default probe)
KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb",
}

# service -> regexes that extract a version string from a banner
VERSION_PATTERNS: dict[str, list[str]] = {
    "ssh": [r"OpenSSH_([\d\.]+p\d+)", r"OpenSSH_([\d\.]+)", r"SSH-2\.0-(\S+)"],
    "http": [r"Apache/([\d\.]+)", r"nginx/([\d\.]+)", r"Microsoft-IIS/([\d\.]+)",
             r"Server: ([^\r\n]+)"],
    "https": [r"Apache/([\d\.]+)", r"nginx/([\d\.]+)", r"Microsoft-IIS/([\d\.]+)"],
    "ftp": [r"vsFTPd ([\d\.]+)", r"ProFTPD ([\d\.]+)", r"FileZilla Server ([\d\.]+)",
            r"FTP Server \(Version ([\d\.]+)\)"],
    "smb": [r"Samba ([\d\.]+)", r"SMBv1"],
    "smtp": [r"Postfix ([\d\.]+)", r"Exim ([\d\.]+)", r"Microsoft ESMTP MAIL Service"],
    "mysql": [r"([\d\.]+)-MariaDB", r"([\d\.]+)-MySQL", r"mysql-([\d\.]+)"],
    "postgres": [r"PostgreSQL ([\d\.]+)"],
    "dns": [r"BIND ([\d\.]+)"],
}


def guess_service(port: int, banner: str = "") -> str:
    """Guess a service from the port, refined by banner keywords."""
    banner_l = banner.lower()
    if "ssh" in banner_l or "openssh" in banner_l:
        return "ssh"
    if "apache" in banner_l or "nginx" in banner_l or "http/" in banner_l:
        return "http" if port != 443 else "https"
    if "vsftpd" in banner_l or "proftpd" in banner_l or banner_l.startswith("220"):
        if port == 21:
            return "ftp"
    if "samba" in banner_l or "smb" in banner_l:
        return "smb"
    if "mysql" in banner_l or "mariadb" in banner_l:
        return "mysql"
    if "postgresql" in banner_l:
        return "postgres"
    if "postfix" in banner_l or "exim" in banner_l:
        return "smtp"
    if "microsoft terminal services" in banner_l or "rdp" in banner_l:
        return "rdp"
    if "rfb" in banner_l:
        return "vnc"
    return KNOWN_PORTS.get(port, "unknown")


def extract_version(service: str, banner: str) -> str:
    """Extract a version string from a banner, or '' if none is found."""
    for pattern in VERSION_PATTERNS.get(service, []):
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    # Generic fallback: first x.y[.z] token in the banner
    match = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
    return match.group(1) if match else ""


def parse_banner(port: int, banner: str) -> dict:
    """Return {service, version, product} for one open port."""
    service = guess_service(port, banner)
    version = extract_version(service, banner)
    product = ""
    if service == "ssh":
        m = re.search(r"SSH-2\.0-([^\r\n]+)", banner)
        product = m.group(1).strip() if m else banner.strip().splitlines()[0] if banner.strip() else ""
    elif service in ("http", "https"):
        m = re.search(r"Server: ([^\r\n]+)", banner, re.IGNORECASE)
        product = m.group(1).strip() if m else ""
    elif service == "ftp":
        product = banner.strip().splitlines()[0] if banner.strip() else ""
    else:
        product = banner.strip().splitlines()[0] if banner.strip() else ""
    return {"service": service, "version": version, "product": product}


def grab_banner(sock: socket.socket, port: int, timeout: float = 2.0) -> str:
    """Read (and, for HTTP, politely request) a banner from an open socket."""
    sock.settimeout(timeout)
    try:
        if port in (80, 8080, 8000, 8443, 443):
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            except OSError:
                pass
        else:
            try:
                sock.sendall(b"\r\n")
            except OSError:
                pass
        data = sock.recv(1024)
        return data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError):
        return ""
