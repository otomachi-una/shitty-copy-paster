import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave11_gate.py"

spec = importlib.util.spec_from_file_location("check_wave11_gate", SCRIPT_PATH)
wave11_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave11_gate)


class Wave11GateTest(unittest.TestCase):
    def test_wave11_gate_is_historical_after_wave12_expansion(self):
        result = wave11_gate.validate_wave11_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(
            {check["name"] for check in failures},
            {
                "wave11-cli-action-place-parsing",
                "wave11-doc-status-and-authority",
                "wave11-no-exploit-or-fix-scripts",
            },
        )
        self.assertEqual(result["status"], "fail")

    def test_wave11_checker_rejects_db_dependency_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker_dir = root / "checkers" / "sentinel_aml"
            checker_dir.mkdir(parents=True)
            (checker_dir / "checker.py").write_text("import psycopg\n", encoding="utf-8")
            (checker_dir / "checker_lib.py").write_text("DB = 'postgresql://example'\n", encoding="utf-8")

            checks = wave11_gate.check_checker_imports_and_endpoints(root)

        failures = [check for check in checks if check["name"] == "wave11-checker-no-db-or-internal-dependencies"]
        self.assertTrue(failures)
        self.assertTrue(all(check["status"] == "fail" for check in failures))
        self.assertIn("psycopg", failures[0]["message"])

    def test_wave11_get_rejects_side_view_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker_dir = root / "checkers" / "sentinel_aml"
            checker_dir.mkdir(parents=True)
            (checker_dir / "checker.py").write_text("print('ok')\n", encoding="utf-8")
            (checker_dir / "checker_lib.py").write_text(
                textwrap.dedent(
                    '''
                    def list_case_notes(case_id):
                        return f"/api/cases/{case_id}/notes"

                    def place1_get():
                        return "/api/graph/entities/hint"

                    def _register_or_login():
                        pass
                    '''
                ),
                encoding="utf-8",
            )

            checks = wave11_gate.check_checker_imports_and_endpoints(root)

        owner_only = next(check for check in checks if check["name"] == "wave11-get-owner-note-only")
        self.assertEqual(owner_only["status"], "fail")
        self.assertIn("/api/graph", owner_only["message"])

    def test_wave11_exploit_or_fix_scripts_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sploit_dir = root / "sploits" / "sentinel_aml"
            sploit_dir.mkdir(parents=True)
            (sploit_dir / "aml_dedup_preview.py").write_text("# forbidden in Wave 11\n", encoding="utf-8")

            checks = wave11_gate.check_no_exploit_or_fix_scripts(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("aml_dedup_preview.py", checks[0]["message"])

    def test_wave11_missing_status_docs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            reports = docs / "wave_reports"
            reports.mkdir(parents=True)
            for relative in (
                "13_roadmap.md",
                "waves.md",
                "source_of_truth_map.md",
                "12_testing_strategy.md",
                "15_risk_register.md",
            ):
                (docs / relative).write_text("Wave 10 | needs fixes\n", encoding="utf-8")
            (reports / "wave_11_validation_summary.md").write_text("Wave 10 | needs fixes\n", encoding="utf-8")

            checks = wave11_gate.check_docs_status(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("| Wave 11 | needs fixes |", checks[0]["message"])
        self.assertIn("R-047", checks[0]["message"])

    def test_wave11_missing_make_target_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Makefile").write_text("wave10-gate:\n\tpython -B scripts/check_wave10_gate.py\n", encoding="utf-8")

            checks = wave11_gate.check_makefile(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("wave11-gate", checks[0]["message"])

    def test_wave11_missing_handoff_or_summary_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            reports = docs / "wave_reports"
            reports.mkdir(parents=True)
            (docs / "08_checker_design.md").write_text("Wave 11\n", encoding="utf-8")
            (docs / "07_flag_stores.md").write_text("place 2\n", encoding="utf-8")
            (docs / "12_testing_strategy.md").write_text(
                "GET /api/cases/{case_id}/notes POST /api/cases/{case_id}/notes Public attack data scripts/check_wave11_gate.py No checker bypass\n",
                encoding="utf-8",
            )
            for relative in wave11_gate.EXPECTED_WAVE_REPORTS[:-1]:
                (root / relative).write_text("present\n", encoding="utf-8")

            checks = wave11_gate.check_docs_and_handoffs(root)

        missing = [check for check in checks if check["name"] == "wave11-report-present" and check["status"] == "fail"]
        self.assertEqual(len(missing), 1)
        self.assertIn("wave_11_validation_summary.md", missing[0]["path"])


if __name__ == "__main__":
    unittest.main()
