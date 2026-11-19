import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave16_gate.py"

spec = importlib.util.spec_from_file_location("check_wave16_gate", SCRIPT_PATH)
wave16_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave16_gate)


class Wave16GateTest(unittest.TestCase):
    def test_wave16_gate_current_branch_has_no_failures(self):
        result = wave16_gate.validate_wave16_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_wave16_rejects_missing_vulnerable_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave16_tree(Path(tmp))
            (root / "internal" / "httpapi" / "graph_profile_aml3_vulnerable.go").unlink()

            check = wave16_gate.check_profile_split(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml3_vulnerable", check["message"])

    def test_wave16_rejects_unrelated_graph_profile_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave16_tree(Path(tmp))
            profile = root / "internal" / "httpapi" / "graph_profile_aml3_vulnerable.go"
            profile.write_text(profile.read_text(encoding="utf-8") + "\nconst bad = \"source_of_funds\"\n", encoding="utf-8")

            check = wave16_gate.check_profile_split(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("source_of_funds", check["message"])

    def test_wave16_rejects_reference_exploit_or_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave16_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_related_graph.py").write_text("print('future exploit')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "aml_related_graph.patch").write_text("future fix\n", encoding="utf-8")

            check = wave16_gate.check_no_reference_exploit_or_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_related_graph.py", check["message"])
        self.assertIn("aml_related_graph.patch", check["message"])

    def test_wave16_rejects_debug_admin_profile_toggle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave16_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "bad_toggle.go"
            target.write_text("package httpapi\nconst EnableDebugAdminGraphVariant = true\n", encoding="utf-8")

            check = wave16_gate.check_no_debug_admin_toggles(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("bad_toggle.go", check["message"])

    def test_wave16_rejects_direct_db_checker_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave16_tree(Path(tmp))
            checker = root / "checkers" / "sentinel_aml" / "checker.py"
            checker.parent.mkdir(parents=True, exist_ok=True)
            checker.write_text("import psycopg\n", encoding="utf-8")

            check = wave16_gate.check_no_direct_db_checker_path(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("psycopg", check["message"])

    def test_wave16_rejects_future_aml_activation_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave16_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "aml4_profile.go"
            target.write_text("package httpapi\nconst aml4_vulnerable = true\n", encoding="utf-8")

            check = wave16_gate.check_no_future_aml_activation(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml4_vulnerable", check["message"])

    def test_wave16_requires_makefile_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave16_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(makefile.read_text(encoding="utf-8").replace("wave16-gate:", "wave16-disabled:"), encoding="utf-8")

            check = wave16_gate.check_makefile_wave16_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave16-gate", check["message"])

    def test_wave16_requires_status_ledger_reconciliation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave16_tree(Path(tmp))
            roadmap = root / "docs" / "13_roadmap.md"
            roadmap.write_text(
                roadmap.read_text(encoding="utf-8").replace(
                    "| Wave 17 | ready |",
                    "| Waves 17-30 | blocked |",
                ),
                encoding="utf-8",
            )

            check = wave16_gate.check_status_ledger_reconciled(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("Waves 17-30", check["message"])


def minimal_wave16_tree(root: Path) -> Path:
    for relative in (
        "internal/httpapi/graph_profile_secure.go",
        "internal/httpapi/graph_profile_aml3_vulnerable.go",
        "internal/graph/repository_aml3_vulnerable.go",
        "internal/httpapi/server.go",
        "internal/httpapi/graph_profile_secure_test.go",
        "internal/httpapi/graph_server_test.go",
        "internal/httpapi/aml3_vulnerable_graph_test.go",
        "docs/wave_reports/wave_16_W16-T01_handoff.md",
        "docs/decisions/ADR-0003-historical-vs-current-branch-gates.md",
        "docs/13_roadmap.md",
        "docs/waves.md",
        "docs/source_of_truth_map.md",
        "config.yml",
        "docker-compose.yml",
        "Makefile",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for dirname in ("cmd", "checkers"):
        (root / dirname).mkdir(exist_ok=True)
    sploits = root / "sploits" / "sentinel_aml"
    sploits.mkdir(parents=True)
    shutil.copyfile(ROOT / "sploits" / "sentinel_aml" / "README.md", sploits / "README.md")
    fixes = root / "fixes" / "sentinel_aml"
    fixes.mkdir(parents=True)
    shutil.copyfile(ROOT / "fixes" / "sentinel_aml" / "README.md", fixes / "README.md")
    return root


if __name__ == "__main__":
    unittest.main()
