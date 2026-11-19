import importlib.util
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave12_gate.py"

spec = importlib.util.spec_from_file_location("check_wave12_gate", SCRIPT_PATH)
wave12_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave12_gate)


class Wave12GateTest(unittest.TestCase):
    def test_wave12_gate_current_branch_has_no_failures(self):
        result = wave12_gate.validate_wave12_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual({check["name"] for check in failures}, {"wave12-no-exploit-or-fix-scripts"})
        self.assertEqual(result["status"], "fail")

    def test_wave12_checker_rejects_db_dependency_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave12_tree(Path(tmp))
            checker_dir = root / "checkers" / "sentinel_aml"
            (checker_dir / "checker.py").write_text("import psycopg\n", encoding="utf-8")
            (checker_dir / "checker_lib.py").write_text("DB = 'postgresql://example'\n", encoding="utf-8")

            checks = wave12_gate.check_checker_imports_and_endpoints(root)

        failures = [check for check in checks if check["name"] == "wave12-checker-no-db-or-internal-dependencies"]
        self.assertTrue(failures)
        self.assertTrue(all(check["status"] == "fail" for check in failures))
        self.assertIn("psycopg", failures[0]["message"])

    def test_wave12_get_rejects_side_view_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave12_tree(Path(tmp))
            checker_dir = root / "checkers" / "sentinel_aml"
            (checker_dir / "checker.py").write_text("print('ok')\n", encoding="utf-8")
            (checker_dir / "checker_lib.py").write_text(
                textwrap.dedent(
                    '''
                    def list_case_notes(case_id):
                        return f"/api/cases/{case_id}/notes"

                    def get_edd_record(customer_id):
                        return f"/api/customers/{customer_id}/edd"

                    def place1_get():
                        return "/api/cases/1/notes"

                    def place2_put():
                        pass

                    def place2_get():
                        return "/api/graph/entities/hint"

                    def _register_or_login():
                        pass
                    '''
                ),
                encoding="utf-8",
            )

            checks = wave12_gate.check_checker_imports_and_endpoints(root)

        owner_only = next(check for check in checks if check["name"] == "wave12-get-owner-views-only")
        self.assertEqual(owner_only["status"], "fail")
        self.assertIn("/api/graph", owner_only["message"])

    def test_wave12_runtime_rejects_place2_deactivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave12_tree(Path(tmp))
            checker_lib = root / "checkers" / "sentinel_aml" / "checker_lib.py"
            text = checker_lib.read_text(encoding="utf-8").replace(
                "if place not in (PLACE_1, PLACE_2):",
                "if place != PLACE_1:",
            )
            checker_lib.write_text(text, encoding="utf-8")

            checks = wave12_gate.check_checker_contract_runtime(root)

        parsing = next(check for check in checks if check["name"] == "wave12-cli-action-place-parsing")
        self.assertEqual(parsing["status"], "fail")
        self.assertIn("put2", parsing["message"])

    def test_wave12_runtime_rejects_public_secret_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave12_tree(Path(tmp))
            checker_lib = root / "checkers" / "sentinel_aml" / "checker_lib.py"
            text = checker_lib.read_text(encoding="utf-8").replace(
                '"typology_hint": state.typology_hint,',
                '"typology_hint": state.typology_hint, "token": "owner-token",',
                1,
            )
            checker_lib.write_text(text, encoding="utf-8")

            checks = wave12_gate.check_checker_contract_runtime(root)

        separation = next(check for check in checks if check["name"] == "wave12-pfr-public-private-separation")
        self.assertEqual(separation["status"], "fail")
        self.assertIn("token", separation["message"])

    def test_wave12_exploit_or_fix_scripts_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave12_tree(Path(tmp))
            sploit_dir = root / "sploits" / "sentinel_aml"
            sploit_dir.mkdir(parents=True, exist_ok=True)
            (sploit_dir / "aml_export_redaction.py").write_text("# forbidden in Wave 12\n", encoding="utf-8")

            checks = wave12_gate.check_no_exploit_or_fix_scripts(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("aml_export_redaction.py", checks[0]["message"])

    def test_wave12_missing_handoff_or_docs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave12_tree(Path(tmp))
            (root / "docs" / "wave_reports" / "wave_12_W12-T04_handoff.md").unlink()
            (root / "docs" / "12_testing_strategy.md").write_text("Wave 11 only\n", encoding="utf-8")

            checks = wave12_gate.check_docs_and_handoffs(root)

        missing_report = [check for check in checks if check["name"] == "wave12-report-present" and check["status"] == "fail"]
        self.assertEqual(len(missing_report), 1)
        docs = next(check for check in checks if check["name"] == "wave12-docs-current-checker-contract")
        self.assertEqual(docs["status"], "fail")
        self.assertIn("Wave 12 Multi-Place Checker Security Matrix", docs["message"])

    def test_wave12_missing_make_target_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave12_tree(Path(tmp))
            (root / "Makefile").write_text("wave11-gate:\n\tpython -B scripts/check_wave11_gate.py\n", encoding="utf-8")

            checks = wave12_gate.check_makefile(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("wave12-gate", checks[0]["message"])


def minimal_wave12_tree(root: Path) -> Path:
    checker_dir = root / "checkers" / "sentinel_aml"
    checker_dir.mkdir(parents=True)
    shutil.copyfile(ROOT / "checkers" / "sentinel_aml" / "checker.py", checker_dir / "checker.py")
    shutil.copyfile(ROOT / "checkers" / "sentinel_aml" / "checker_lib.py", checker_dir / "checker_lib.py")

    tests_dir = root / "tests"
    tests_dir.mkdir()
    for name in ("test_checker_foundation.py", "test_checker_put_workflow.py", "test_checker_get_workflow.py"):
        shutil.copyfile(ROOT / "tests" / name, tests_dir / name)

    docs = root / "docs"
    reports = docs / "wave_reports"
    reports.mkdir(parents=True)
    shutil.copyfile(ROOT / "docs" / "12_testing_strategy.md", docs / "12_testing_strategy.md")
    for report in wave12_gate.EXPECTED_WAVE_REPORTS:
        report_path = root / report
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text("present\n", encoding="utf-8")

    sploit_dir = root / "sploits" / "sentinel_aml"
    sploit_dir.mkdir(parents=True)
    shutil.copyfile(ROOT / "Makefile", root / "Makefile")
    shutil.copyfile(ROOT / "config.yml", root / "config.yml")
    scripts = root / "scripts"
    scripts.mkdir()
    shutil.copyfile(ROOT / "scripts" / "validate_forcad_config.py", scripts / "validate_forcad_config.py")
    return root


if __name__ == "__main__":
    unittest.main()
