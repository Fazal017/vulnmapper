"""Tests for VulnMapper v2 — attack-path graph.
Run with:  python -m unittest discover -s tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.attack_graph import (  # noqa: E402
    choke_points, enumerate_paths, exploitable_map, hosts_on_paths,
    load_scan, shortest_paths,
)
from src.combo import detect_toxic_combinations  # noqa: E402
from src.exposure import (  # noqa: E402
    exposure_score, load_exploitability, rank_findings,
)
from src.topology import load_topology, topology_from_dict  # noqa: E402
from src.whatif import parse_patch_list, resolve_patch, simulate  # noqa: E402
import vulnmapper_v2  # noqa: E402


def _enterprise():
    topo = load_topology(ROOT / "samples" / "topology_enterprise.yaml")
    scan = load_scan(ROOT / "samples" / "scan_enterprise.json")
    exploitable = exploitable_map(topo, scan)
    paths = enumerate_paths(topo, exploitable)
    ranked = rank_findings(exploitable, topo, paths, load_exploitability())
    return topo, scan, exploitable, paths, ranked


def _small_topology():
    """internet -> web (1 CVE) -> db (1 CVE). One path, one choke point."""
    return topology_from_dict({
        "name": "small",
        "crown_jewels": ["db"],
        "hosts": [
            {"name": "web", "ip": "10.0.1.10", "zone": "dmz",
             "internet_facing": True, "criticality": 2, "services": [
                 {"port": 80, "service": "http", "version": "2.4.49",
                  "banner": "Server: Apache/2.4.49 (Unix)"}]},
            {"name": "db", "ip": "10.0.3.30", "zone": "crown-jewel",
             "internet_facing": False, "criticality": 5, "services": [
                 {"port": 3306, "service": "mysql", "version": "5.5.52",
                  "banner": "MySQL 5.5.52"}]},
        ],
        "trust": [{"from": "internet", "to": "web"},
                  {"from": "web", "to": "db"}],
        "firewall_rules": [],
    })


class TestTopology(unittest.TestCase):
    def test_enterprise_parses_8_hosts_3_zones(self):
        topo = load_topology(ROOT / "samples" / "topology_enterprise.yaml")
        self.assertEqual(len(topo.hosts), 8)
        self.assertEqual(topo.zones, {"dmz", "internal", "crown-jewel"})
        self.assertEqual(sorted(topo.crown_jewels), ["db-crown", "dc-crown"])
        self.assertEqual(sorted(topo.entry_points), ["mail-dmz", "web-dmz"])

    def test_firewall_denies_internet_to_crown_jewel(self):
        topo = load_topology(ROOT / "samples" / "topology_enterprise.yaml")
        self.assertTrue(topo.is_firewall_denied("internet", "db-crown"))
        self.assertTrue(topo.is_firewall_denied("web-dmz", "db-crown"))
        self.assertFalse(topo.is_firewall_denied("web-dmz", "app-internal"))

    def test_scan_enterprise_loads_8_hosts(self):
        scan = load_scan(ROOT / "samples" / "scan_enterprise.json")
        self.assertEqual(len(scan), 8)
        self.assertEqual(len(scan["web-dmz"]), 2)


class TestAttackGraph(unittest.TestCase):
    def test_shortest_path_to_db_is_3_hosts(self):
        topo, _, _, paths, _ = _enterprise()
        shortest = shortest_paths(paths, topo.crown_jewels)
        self.assertEqual(shortest["db-crown"],
                         ["mail-dmz", "app-internal", "db-crown"])

    def test_all_paths_max_length_4_and_end_at_crown(self):
        topo, _, _, paths, _ = _enterprise()
        self.assertEqual(len(paths), 7)
        for p in paths:
            self.assertLessEqual(len(p), 4)
            self.assertIn(p[-1], topo.crown_jewels)
            self.assertEqual(len(set(p)), len(p))  # no cycles

    def test_choke_point_app_internal(self):
        _, _, _, paths, _ = _enterprise()
        chokes = {c["host"]: c for c in choke_points(paths)}
        self.assertIn("app-internal", chokes)
        self.assertGreater(chokes["app-internal"]["share"], 0.5)
        self.assertEqual(chokes["app-internal"]["paths"], 6)

    def test_isolated_host_not_on_any_path(self):
        _, _, _, paths, _ = _enterprise()
        self.assertNotIn("backup-isolated", hosts_on_paths(paths))

    def test_small_topology_single_path(self):
        topo = _small_topology()
        exploitable = exploitable_map(topo)
        paths = enumerate_paths(topo, exploitable)
        self.assertEqual(paths, [["web", "db"]])


class TestExposure(unittest.TestCase):
    def test_exposure_formula(self):
        # 7.5 x 0.91 x 1.0 x 2 = 13.65
        self.assertEqual(exposure_score(7.5, 0.91, 1.0, 2), 13.65)
        # 9.8 x 0.97 x 0.3 x 1 = 2.85
        self.assertEqual(exposure_score(9.8, 0.97, 0.3, 1), 2.85)

    def test_exposure_ranking_inversion(self):
        """CVSS 9.8 isolated ranks BELOW CVSS 7.5 on the path to the DB."""
        topo, _, _, paths, ranked = _enterprise()
        by_cve = {r["cve"]: r for r in ranked}
        isolated = by_cve["CVE-2011-2523"]  # vsFTPd, backup-isolated
        on_path = by_cve["CVE-2021-41773"]  # Apache, web-dmz -> app -> db
        self.assertEqual(isolated["cvss"], 9.8)
        self.assertEqual(on_path["cvss"], 7.5)
        self.assertFalse(isolated["on_attack_path"])
        self.assertTrue(on_path["on_attack_path"])
        self.assertLess(isolated["exposure"], on_path["exposure"])
        order = [r["cve"] for r in ranked]
        self.assertLess(order.index("CVE-2021-41773"),
                        order.index("CVE-2011-2523"))

    def test_exploitability_db_covers_all_25_cves(self):
        from src.cve import load_db
        exp = load_exploitability()
        for entry in load_db():
            self.assertIn(entry["cve"], exp, entry["cve"])
            self.assertTrue(0 < exp[entry["cve"]]["epss"] <= 1)


class TestWhatIf(unittest.TestCase):
    def test_patch_app_internal_closes_paths(self):
        topo, _, exploitable, paths, ranked = _enterprise()
        result = simulate(topo, exploitable, paths, ranked,
                          ["patch_app_internal"])
        self.assertEqual(result["paths_before"], 7)
        self.assertEqual(result["paths_closed"], 6)
        self.assertEqual(result["paths_after"], 1)
        self.assertLess(result["residual_exposure"], result["exposure_before"])

    def test_patch_single_cve_closes_small_topology_path(self):
        topo = _small_topology()
        exploitable = exploitable_map(topo)
        paths = enumerate_paths(topo, exploitable)
        ranked = rank_findings(exploitable, topo, paths, load_exploitability())
        result = simulate(topo, exploitable, paths, ranked, ["CVE-2021-41773"])
        self.assertEqual(result["paths_closed"], 1)
        self.assertEqual(result["paths_after"], 0)

    def test_next_best_patch_after_smbv1_is_app_internal(self):
        topo, _, exploitable, paths, ranked = _enterprise()
        result = simulate(topo, exploitable, paths, ranked, ["patch_smbv1"])
        self.assertEqual(result["paths_closed"], 0)  # file still has SSH
        self.assertEqual(result["next_best_patch"], "patch_app_internal")
        self.assertEqual(result["next_best_paths_closed"], 6)

    def test_unknown_patch_raises(self):
        topo, _, exploitable, _, _ = _enterprise()
        with self.assertRaises(ValueError):
            resolve_patch("patch_nonexistent", exploitable)

    def test_parse_patch_list(self):
        self.assertEqual(parse_patch_list("patch_smbv1,CVE-2019-0708"),
                         ["patch_smbv1", "CVE-2019-0708"])


class TestToxicCombos(unittest.TestCase):
    def test_lateral_movement_chain_detected(self):
        _, _, exploitable, _, _ = _enterprise()
        combos = {c["id"]: c for c in detect_toxic_combinations(exploitable)}
        self.assertIn("lateral-movement-chain", combos)
        self.assertEqual(combos["lateral-movement-chain"]["severity"], "Critical")
        self.assertIn("workstation",
                      combos["lateral-movement-chain"]["hosts"])

    def test_no_combo_when_conditions_missing(self):
        exploitable = {"web": [{"cve": "CVE-2017-0144", "cvss": 8.8,
                                 "service": "smb"}]}
        self.assertEqual(detect_toxic_combinations(exploitable), [])


class TestV2Cli(unittest.TestCase):
    def test_cli_end_to_end_writes_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "exposure.json"
            rc = vulnmapper_v2.main([
                "--topology", str(ROOT / "samples" / "topology_enterprise.yaml"),
                "--scan", str(ROOT / "samples" / "scan_enterprise.json"),
                "--output", str(out), "--whatif", "patch_smbv1"])
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["attack_paths"], 7)
            self.assertEqual(report["whatif"]["next_best_patch"],
                             "patch_app_internal")
            self.assertTrue(report["exposure_ranking"])


if __name__ == "__main__":
    unittest.main()
