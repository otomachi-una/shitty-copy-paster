import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_docs_tree.py"

spec = importlib.util.spec_from_file_location("check_docs_tree", SCRIPT_PATH)
docs_tree = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(docs_tree)


class DocsTreeTest(unittest.TestCase):
    def test_docs_tree_reports_pass(self):
        result = docs_tree.validate_docs_tree(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_required_directories_exist(self):
        result = docs_tree.validate_docs_tree(ROOT)
        directory_checks = [check for check in result["checks"] if check["name"] == "required-dir"]

        self.assertEqual({check["status"] for check in directory_checks}, {"pass"})
        self.assertEqual(
            {check["path"] for check in directory_checks},
            {"docs/decisions/", "docs/agent_packets/", "docs/wave_reports/"},
        )

    def test_required_canonical_docs_exist_exactly(self):
        result = docs_tree.validate_docs_tree(ROOT)
        doc_checks = [check for check in result["checks"] if check["name"] == "required-doc"]

        self.assertEqual({check["status"] for check in doc_checks}, {"pass"})
        self.assertIn(
            "docs/00_project_overview.md",
            {check["path"] for check in doc_checks},
        )
        self.assertIn("docs/source_of_truth_map.md", {check["path"] for check in doc_checks})
        self.assertIn("docs/definition_of_done.md", {check["path"] for check in doc_checks})

    def test_no_active_legacy_docs_remain(self):
        result = docs_tree.validate_docs_tree(ROOT)
        legacy_checks = [
            check
            for check in result["checks"]
            if check["name"] in {"no-active-legacy-filenames", "no-active-legacy-content"}
        ]

        self.assertEqual({check["status"] for check in legacy_checks}, {"pass"})

    def test_agent_prompt_pools_are_canonical(self):
        result = docs_tree.validate_docs_tree(ROOT)
        packet_checks = [
            check
            for check in result["checks"]
            if check["name"] in {"required-agent-packet", "no-root-prompt-pools"}
        ]

        self.assertTrue(packet_checks)
        self.assertEqual({check["status"] for check in packet_checks}, {"pass"})

    def test_roadmap_and_waves_are_not_collapsed(self):
        result = docs_tree.validate_docs_tree(ROOT)
        roadmap_checks = [check for check in result["checks"] if check["name"] == "roadmap-wave-detail"]

        self.assertEqual({check["status"] for check in roadmap_checks}, {"pass"})
        self.assertEqual({check["path"] for check in roadmap_checks}, {"docs/13_roadmap.md", "docs/waves.md"})

    def test_status_ledger_and_wave10_scope_are_current(self):
        roadmap = (ROOT / "docs" / "13_roadmap.md").read_text(encoding="utf-8")
        waves = (ROOT / "docs" / "waves.md").read_text(encoding="utf-8")
        source_map = (ROOT / "docs" / "source_of_truth_map.md").read_text(encoding="utf-8")

        self.assertIn("| Wave 02 | complete |", roadmap)
        self.assertIn("| Wave 03 | complete |", roadmap)
        self.assertIn("| Wave 04 | complete |", roadmap)
        self.assertIn("| Wave 05 | complete |", roadmap)
        self.assertIn("| Wave 06 | complete |", roadmap)
        self.assertIn("| Wave 07 | complete |", roadmap)
        self.assertIn("| Wave 08 | complete |", roadmap)
        self.assertIn("| Wave 09 | complete |", roadmap)
        self.assertIn("| Wave 10 | needs fixes |", roadmap)
        self.assertIn("| W02 | PostgreSQL auth/session foundation | complete |", waves)
        self.assertIn("| W03 | Customer/account/transaction domain slice | complete |", waves)
        self.assertIn("| W04 | Risk scoring, alerts, and owner case workflow | complete |", waves)
        self.assertIn("| W05 | EDD workflow | complete |", waves)
        self.assertIn("| W06 | Visibility and projection hardening | complete |", waves)
        self.assertIn("| W07 | Dedup preview secure baseline | complete |", waves)
        self.assertIn("| W08 | Audit timeline secure baseline | complete |", waves)
        self.assertIn("| W09 | Related graph secure baseline | complete |", waves)
        self.assertIn("| W10 | Export redaction and network-room secure baselines | needs fixes |", waves)
        self.assertIn("Wave 10 remains `needs fixes` until W10-T01, W10-T02, W10-T03, W10-T04, and W10-T05 pass", waves)
        self.assertIn("Wave 10 needs fixes until W10-T01/W10-T02/W10-T03/W10-T04/W10-T05 pass orchestrator review", source_map)
        self.assertIn("scripts/check_wave07_gate.py", source_map)
        self.assertIn("scripts/check_wave08_gate.py", source_map)
        self.assertIn("scripts/check_wave09_gate.py", source_map)
        self.assertIn("scripts/check_wave10_gate.py", source_map)

    def test_wave05_edd_visibility_docs_are_complete(self):
        api = (ROOT / "docs" / "03_api_contract.md").read_text(encoding="utf-8")
        visibility = (ROOT / "docs" / "06_visibility_and_projections.md").read_text(encoding="utf-8")
        database = (ROOT / "docs" / "04_database_model.md").read_text(encoding="utf-8")
        flags = (ROOT / "docs" / "07_flag_stores.md").read_text(encoding="utf-8")
        workers = (ROOT / "docs" / "10_workers_and_async_flows.md").read_text(encoding="utf-8")
        testing = (ROOT / "docs" / "12_testing_strategy.md").read_text(encoding="utf-8")

        for route in (
            "POST /api/customers/{customer_id}/edd",
            "GET /api/customers/{customer_id}/edd",
            "PATCH /api/customers/{customer_id}/edd",
        ):
            self.assertIn(route, api)
            self.assertIn(route, visibility)

        self.assertIn("Visibility matrix for `confidential_comment`", visibility)
        self.assertIn("Owner EDD create/get/patch response | visible", visibility)
        self.assertIn("Public attack-data or checker-only path | absent", visibility)
        self.assertIn("Worker, export, graph, audit, network-room, or side-view projection | absent", visibility)
        self.assertIn("restrict delete behavior to avoid deleting future flag-bearing EDD records", database)
        self.assertIn("Checker place 2 remains deferred", flags)
        self.assertIn("Workers do not inspect, copy, export, redact, score, delete, or publish `EDDRecord.confidential_comment`", workers)
        self.assertIn("TestLivePostgresWave05EDDAPIIntegration", testing)

    def test_root_prompt_pool_fails_docs_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_minimal_docs_tree(Path(tmp))
            (root / "docs" / "wave_01_prompt_pool.md").write_text("misplaced\n", encoding="utf-8")

            result = docs_tree.validate_docs_tree(root)

        root_check = next(check for check in result["checks"] if check["name"] == "no-root-prompt-pools")
        self.assertEqual(root_check["status"], "fail")

    def test_collapsed_roadmap_fails_docs_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_minimal_docs_tree(Path(tmp))
            (root / "docs" / "13_roadmap.md").write_text(
                "# Roadmap\n\n## Wave 01\n\n## Later Waves\n\nTBD.\n",
                encoding="utf-8",
            )

            result = docs_tree.validate_docs_tree(root)

        roadmap_check = next(
            check
            for check in result["checks"]
            if check["name"] == "roadmap-wave-detail" and check["path"] == "docs/13_roadmap.md"
        )
        self.assertEqual(roadmap_check["status"], "fail")
        self.assertIn("collapsed=True", roadmap_check["message"])


def make_minimal_docs_tree(root: Path) -> Path:
    source_docs = ROOT / "docs"
    target_docs = root / "docs"
    target_docs.mkdir()

    for doc_name in docs_tree.REQUIRED_DOCS:
        shutil.copyfile(source_docs / doc_name, target_docs / doc_name)
    for dir_name in docs_tree.REQUIRED_DIRS:
        (target_docs / dir_name).mkdir()
    for packet_name in docs_tree.REQUIRED_AGENT_PACKETS:
        shutil.copyfile(source_docs / "agent_packets" / packet_name, target_docs / "agent_packets" / packet_name)
    return root


if __name__ == "__main__":
    unittest.main()
