import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave29_gate.py"

spec = importlib.util.spec_from_file_location("check_wave29_gate", SCRIPT_PATH)
wave29_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave29_gate)


class Wave29GateTest(unittest.TestCase):
    def test_wave29_gate_current_branch_has_no_failures(self):
        result = wave29_gate.validate_wave29_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_checker_contract_rejects_missing_place2_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            checker = root / "checkers" / "sentinel_aml" / "checker_lib.py"
            checker.write_text(
                checker.read_text(encoding="utf-8").replace('PLACE_2_STORE = "EDDRecord.confidential_comment"', ""),
                encoding="utf-8",
            )

            check = wave29_gate.check_checker_contract(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("EDDRecord.confidential_comment", check["message"])

    def test_checker_contract_rejects_direct_db_shortcut(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            checker = root / "checkers" / "sentinel_aml" / "checker_lib.py"
            checker.write_text(checker.read_text(encoding="utf-8") + "\nimport sqlite3\n", encoding="utf-8")

            check = wave29_gate.check_checker_contract(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("sqlite3", check["message"])

    def test_exploit_inventory_rejects_extra_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_extra.py").write_text("print('extra')\n", encoding="utf-8")

            check = wave29_gate.check_exploit_inventory_and_side_views(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_extra.py", check["message"])

    def test_exploit_side_view_rejects_owner_private_api_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            sploit = root / "sploits" / "sentinel_aml" / "aml_network_room.py"
            sploit.write_text(sploit.read_text(encoding="utf-8") + '\nOWNER = "/api/customers/{customer_id}/edd"\n', encoding="utf-8")

            check = wave29_gate.check_exploit_inventory_and_side_views(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("/api/customers/{customer_id}/edd", check["message"])

    def test_all_patches_apply_rejects_missing_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_network_room.patch").unlink()

            check = wave29_gate.check_all_patches_apply(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.patch", check["message"])

    def test_reference_fix_evidence_rejects_restricted_field_rename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_network_room.patch"
            patch.write_text(
                patch.read_text(encoding="utf-8") + '\n+\tForeignNoteBody string `json:"foreign_note_body"`\n',
                encoding="utf-8",
            )

            check = wave29_gate.check_reference_fix_evidence(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("foreign_note_body", check["message"])

    def test_vulnerable_profile_coverage_requires_all_tagged_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            runner = root / "scripts" / "run_vulnerable_profile_tests.py"
            runner.write_text(runner.read_text(encoding="utf-8").replace('"aml5_vulnerable"', '"aml5_removed"'), encoding="utf-8")

            check = wave29_gate.check_vulnerable_profile_coverage(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml5_vulnerable", check["message"])

    def test_makefile_target_requires_full_gate_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            (root / "Makefile").write_text("wave29-gate:\n\tpython -B scripts/check_wave29_gate.py\n", encoding="utf-8")

            check = wave29_gate.check_makefile_wave29_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("test_checker_*.py", check["message"])
        self.assertIn("test_wave29_regression.py", check["message"])
        self.assertIn("aml_network_room.patch", check["message"])
        self.assertIn("run_go_release_tests.py", check["message"])
        self.assertIn("run_vulnerable_profile_tests.py", check["message"])

    def test_makefile_target_rejects_unbounded_go_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8")
                + "\nwave29-extra:\n\t$(GO_RELEASE_ENV) $(GO) test ./...\n",
                encoding="utf-8",
            )

            check = wave29_gate.check_makefile_wave29_gate(root)

            self.assertEqual(check["status"], "pass")

            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace(
                    "$(PYTHON) -B scripts/run_go_release_tests.py --go $(GO) --package-timeout 120",
                    "$(GO_RELEASE_ENV) $(GO) test ./...",
                ),
                encoding="utf-8",
            )
            check = wave29_gate.check_makefile_wave29_gate(root)
            self.assertEqual(check["status"], "fail")
            self.assertIn("forbidden", check["message"])

    def test_makefile_target_rejects_duplicate_full_tagged_sweep(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave29_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace(
                    "$(PYTHON) -B scripts/run_vulnerable_profile_tests.py --go $(GO) --package-timeout 120",
                    "$(PYTHON) -B scripts/run_vulnerable_profile_tests.py --go $(GO) --package-timeout 120\n"
                    "\t$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml5_vulnerable ./...",
                ),
                encoding="utf-8",
            )

            check = wave29_gate.check_makefile_wave29_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml5_vulnerable ./...", check["message"])


def copy_wave29_tree(destination: Path) -> Path:
    for name in ("scripts", "tests", "docs", "sploits", "fixes", "internal", "checkers", "cmd"):
        source = ROOT / name
        target = destination / name
        if source.is_dir():
            shutil.copytree(
                source,
                target,
                ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc"),
            )
    for name in ("Makefile", "config.yml", "docker-compose.yml"):
        shutil.copyfile(ROOT / name, destination / name)
    return destination


if __name__ == "__main__":
    unittest.main()
