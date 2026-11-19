import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER_DIR = ROOT / "checkers" / "sentinel_aml"
sys.path.insert(0, str(CHECKER_DIR))

import checker_lib  # noqa: E402


class CheckerScenarioInventoryTest(unittest.TestCase):
    def test_inventory_names_every_required_checker_scenario(self):
        inventory = checker_lib.checker_scenario_inventory()
        names = {scenario["name"] for scenario in inventory}

        required = {
            "place1_put",
            "place1_get",
            "place2_put",
            "place2_get",
            "health",
            "check_basic",
            "check_case_notes",
            "check_edd",
            "check_dedup",
            "check_audit",
            "check_graph",
            "check_export",
            "check_network_room",
            "check_retention",
            "putnoise",
            "getnoise",
        }
        self.assertEqual(required - names, set())

    def test_default_check_and_havoc_matrix_includes_all_required_subchecks(self):
        expected = (
            "health",
            "check_basic",
            "check_case_notes",
            "check_edd",
            "check_dedup",
            "check_audit",
            "check_graph",
            "check_export",
            "check_network_room",
            "check_retention",
        )
        inventory = {scenario["name"]: scenario for scenario in checker_lib.checker_scenario_inventory()}

        self.assertEqual(checker_lib.DEFAULT_CHECK_SUBCHECKS, expected)
        for name in expected:
            with self.subTest(subcheck=name):
                self.assertEqual(inventory[name]["action"], "check/havoc")
                self.assertGreater(len(inventory[name]["normal_api_paths"]), 0)
                self.assertEqual(inventory[name]["bounded_timeout_seconds"], checker_lib.DEFAULT_HTTP_TIMEOUT_SECONDS)

    def test_inventory_pins_owner_flows_and_owner_get_paths(self):
        inventory = {scenario["name"]: scenario for scenario in checker_lib.checker_scenario_inventory()}

        self.assertEqual(inventory["place1_put"]["owner_flow"], "case review note")
        self.assertEqual(inventory["place1_get"]["owner_flow"], "case review note")
        self.assertEqual(inventory["place2_put"]["owner_flow"], "enhanced review record")
        self.assertEqual(inventory["place2_get"]["owner_flow"], "enhanced review record")
        self.assertEqual(inventory["place1_get"]["normal_api_paths"], ("GET /api/cases/{case_id}/notes", "POST /api/auth/login"))
        self.assertEqual(inventory["place2_get"]["normal_api_paths"], ("GET /api/customers/{customer_id}/edd", "POST /api/auth/login"))

    def test_inventory_public_attack_data_is_locator_only(self):
        inventory = {scenario["name"]: scenario for scenario in checker_lib.checker_scenario_inventory()}

        self.assertEqual(
            inventory["place1_put"]["public_attack_data_keys"],
            (
                "service",
                "case_ref",
                "case_id",
                "customer_ref",
                "customer_id",
                "entity_ref",
                "party_ref",
                "matching_reference",
            ),
        )
        self.assertEqual(
            inventory["place2_put"]["public_attack_data_keys"],
            ("service", "customer_ref", "customer_id", "entity_ref", "party_ref"),
        )
        for name in ("place1_put", "place2_put", "putnoise"):
            with self.subTest(name=name):
                forbidden = set(inventory[name]["forbidden_public_markers"])
                for marker in (
                    "username",
                    "password",
                    "token",
                    "session",
                    "flag",
                    "checker_secret",
                    "private_state",
                    "store",
                    "dedup_hint",
                    "typology_hint",
                    "entity_hint",
                ):
                    self.assertIn(marker, forbidden)

    def test_owner_get_inventory_forbids_side_view_recovery_paths(self):
        inventory = {scenario["name"]: scenario for scenario in checker_lib.checker_scenario_inventory()}

        forbidden = set(checker_lib.forbidden_checker_get_side_view_paths())
        for name in ("place1_get", "place2_get"):
            with self.subTest(name=name):
                self.assertTrue(inventory[name]["owner_view_only"])
                self.assertEqual(set(inventory[name]["forbidden_get_paths"]), forbidden)
                self.assertIn("GET /api/cases/{case_id}/timeline", forbidden)
                self.assertIn("GET /api/graph/entities/{entity_hint}/edd-summaries", forbidden)
                self.assertIn("GET /api/network/rooms/{room_id}/dossier", forbidden)

    def test_docs_report_matches_inventory(self):
        report = (ROOT / "docs" / "wave_reports" / "wave_32_checker_validation.md").read_text(encoding="utf-8")

        for scenario in checker_lib.checker_scenario_inventory():
            self.assertIn(f"`{scenario['name']}`", report)
        self.assertIn("No checker-private state in public attack data", report)
        self.assertIn("GET remains owner-view only", report)


if __name__ == "__main__":
    unittest.main()
