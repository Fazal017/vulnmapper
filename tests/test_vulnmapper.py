"""Tests for VulnMapper — run with:  python -m unittest discover -s tests -v"""
import json
import socket
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.banner import extract_version, guess_service, parse_banner  # noqa: E402
from src.cve import load_db, match_cves, severity_from_cvss, triage  # noqa: E402
from src.safety import AuthorizationError, check_target  # noqa: E402
from src.scanner import parse_ports, scan  # noqa: E402


class TestSafety(unittest.TestCase):
    def test_allowlist_blocks_public_ip(self):
        """A public IP is refused without flag + allowlist entry."""
        with self.assertRaises(AuthorizationError):
            check_target("8.8.8.8")

    def test_allowlist_blocks_public_ip_even_with_flag_alone(self):
        """--i-have-authorization alone is NOT enough — allowlist entry also required."""
        with self.assertRaises(AuthorizationError):
            check_target("8.8.8.8", i_have_authorization=True,
                         allowlist_path=str(ROOT / "allowlist.txt"))

    def test_allowlist_allows_public_ip_with_flag_and_entry(self):
        allow = ROOT / "tests" / "_tmp_allowlist.txt"
        allow.write_text("8.8.8.8\n", encoding="utf-8")
        try:
            self.assertEqual(check_target("8.8.8.8", i_have_authorization=True,
                                          allowlist_path=str(allow)), "8.8.8.8")
        finally:
            allow.unlink(missing_ok=True)

    def test_localhost_and_private_ranges_allowed(self):
        for target in ("127.0.0.1", "localhost", "10.0.0.5", "192.168.1.10", "172.16.0.9"):
            self.assertTrue(check_target(target), target)


class TestBannerParsing(unittest.TestCase):
    def test_parse_openssh_banner(self):
        parsed = parse_banner(22, "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8")
        self.assertEqual(parsed["service"], "ssh")
        self.assertEqual(parsed["version"], "7.2p2")

    def test_parse_apache_banner(self):
        parsed = parse_banner(80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)")
        self.assertEqual(parsed["service"], "http")
        self.assertEqual(parsed["version"], "2.4.49")

    def test_parse_vsftpd_banner(self):
        parsed = parse_banner(21, "220 (vsFTPd 2.3.4)")
        self.assertEqual(parsed["service"], "ftp")
        self.assertEqual(parsed["version"], "2.3.4")

    def test_guess_service_from_port_only(self):
        self.assertEqual(guess_service(22, ""), "ssh")
        self.assertEqual(guess_service(3306, ""), "mysql")
        self.assertEqual(guess_service(9999, ""), "unknown")

    def test_extract_version_empty_banner(self):
        self.assertEqual(extract_version("ssh", ""), "")


class TestCveMatching(unittest.TestCase):
    def test_cve_match_openssh_72(self):
        matches = match_cves("ssh", "7.2p2", "SSH-2.0-OpenSSH_7.2p2")
        self.assertTrue(any(m["cve"] == "CVE-2016-0777" for m in matches))

    def test_cve_match_apache_2449(self):
        matches = match_cves("http", "2.4.49", "Server: Apache/2.4.49")
        self.assertTrue(any(m["cve"] == "CVE-2021-41773" for m in matches))

    def test_cve_match_vsftpd_backdoor(self):
        matches = match_cves("ftp", "2.3.4", "220 (vsFTPd 2.3.4)")
        self.assertTrue(any(m["cve"] == "CVE-2011-2523" for m in matches))
        self.assertEqual(matches[0]["severity"], "Critical")

    def test_no_match_for_patched_version(self):
        self.assertEqual(match_cves("ssh", "9.8p1", "SSH-2.0-OpenSSH_9.8p1"), [])

    def test_matches_sorted_by_cvss_desc(self):
        matches = match_cves("ssh", "9.6p1", "SSH-2.0-OpenSSH_9.6p1")
        cvss = [m["cvss"] for m in matches]
        self.assertEqual(cvss, sorted(cvss, reverse=True))

    def test_db_has_at_least_25_entries(self):
        self.assertGreaterEqual(len(load_db()), 25)

    def test_severity_from_cvss(self):
        self.assertEqual(severity_from_cvss(9.8), "Critical")
        self.assertEqual(severity_from_cvss(7.5), "High")
        self.assertEqual(severity_from_cvss(5.0), "Medium")
        self.assertEqual(severity_from_cvss(2.0), "Low")

    def test_triage_orders_by_max_cvss(self):
        findings = triage([
            {"port": 80, "service": "http", "version": "2.4.49",
             "banner": "Server: Apache/2.4.49"},
            {"port": 22, "service": "ssh", "version": "7.2p2",
             "banner": "SSH-2.0-OpenSSH_7.2p2"},
        ])
        self.assertEqual(findings[0]["port"], 80)  # CVE-2021-41773 CVSS 7.5 > 6.5


class TestScanner(unittest.TestCase):
    def test_parse_ports_list_and_range(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(parse_ports("8000-8002"), [8000, 8001, 8002])
        self.assertEqual(parse_ports("22,80,8000-8001"), [22, 80, 8000, 8001])

    def test_parse_ports_rejects_invalid(self):
        with self.assertRaises(ValueError):
            parse_ports("0")
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_port_scan_on_localhost(self):
        """Spin up a real TCP listener on localhost and confirm the scan finds it."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)

        def accept_once():
            try:
                conn, _ = server.accept()
                conn.sendall(b"SSH-2.0-OpenSSH_7.2p2 test\r\n")
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        try:
            results = scan("127.0.0.1", [port], timeout=2.0)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["port"], port)
            self.assertEqual(results[0]["state"], "open")
        finally:
            server.close()
            thread.join(timeout=2)

    def test_closed_port_not_reported(self):
        # Port 1 on localhost is (essentially) never open; scan must return [].
        self.assertEqual(scan("127.0.0.1", [1], timeout=1.0), [])


class TestReport(unittest.TestCase):
    def test_demo_sample_file_is_valid(self):
        sample = json.loads((ROOT / "samples" / "scan_localhost.json").read_text())
        self.assertEqual(sample["target"], "127.0.0.1")
        self.assertGreaterEqual(len(sample["findings"]), 3)


if __name__ == "__main__":
    unittest.main()
