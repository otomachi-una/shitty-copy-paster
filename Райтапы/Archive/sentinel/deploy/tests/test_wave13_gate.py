import importlib.util
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave13_gate.py"

spec = importlib.util.spec_from_file_location("check_wave13_gate", SCRIPT_PATH)
wave13_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave13_gate)


class Wave13GateTest(unittest.TestCase):
    def test_wave13_gate_is_historical_after_wave14_vulnerable_profile(self):
        result = wave13_gate.validate_wave13_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(
            {check["name"] for check in failures},
            {"wave13-no-early-exploit-or-fix-scripts", "wave13-no-vulnerable-behavior-yet"},
        )
        self.assertEqual(result["status"], "fail")

    def test_wave13_rejects_hidden_checker_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave13_tree(Path(tmp))
            checker_lib = root / "checkers" / "sentinel_aml" / "checker_lib.py"
            checker_lib.write_text(checker_lib.read_text(encoding="utf-8") + "\nHIDDEN = '/api/checker'\n", encoding="utf-8")

            checks = wave13_gate.check_checker_imports_and_endpoints(root)

        hidden = [check for check in checks if check["name"] == "wave13-checker-no-hidden-endpoints"]
        self.assertTrue(any(check["status"] == "fail" and "/api/checker" in check["message"] for check in hidden))

    def test_wave13_rejects_check_framework_deactivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave13_tree(Path(tmp))
            checker_lib = root / "checkers" / "sentinel_aml" / "checker_lib.py"
            text = checker_lib.read_text(encoding="utf-8").replace(
                'DEFAULT_CHECK_SUBCHECKS = (\n    "health",\n    "check_basic",\n    "check_case_notes",\n    "check_edd",\n    "check_dedup",\n    "check_audit",\n    "check_graph",\n    "check_export",\n    "check_network_room",\n    "check_retention",\n)',
                'DEFAULT_CHECK_SUBCHECKS = ("health", "check_basic")',
            )
            checker_lib.write_text(text, encoding="utf-8")

            checks = wave13_gate.check_check_framework_runtime(root)

        dispatch = next(check for check in checks if check["name"] == "wave13-check-havoc-dispatch-runtime")
        self.assertEqual(dispatch["status"], "fail")
        self.assertIn("check_case_notes", dispatch["message"])

    def test_wave13_rejects_entrypoint_bypassing_framework(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave13_tree(Path(tmp))
            checker_py = root / "checkers" / "sentinel_aml" / "checker.py"
            checker_py.write_text(
                checker_py.read_text(encoding="utf-8").replace("run_check(parsed.host)", "SentinelAMLClient(parsed.host).health()"),
                encoding="utf-8",
            )

            checks = wave13_gate.check_check_framework_runtime(root)

        entrypoint = next(check for check in checks if check["name"] == "wave13-checker-entrypoint-uses-framework")
        self.assertEqual(entrypoint["status"], "fail")
        self.assertIn("run_check(parsed.host)", entrypoint["message"])

    def test_wave13_rejects_redaction_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave13_tree(Path(tmp))
            checker_lib = root / "checkers" / "sentinel_aml" / "checker_lib.py"
            checker_lib.write_text(
                checker_lib.read_text(encoding="utf-8").replace(
                    "return redact_sensitive(message, extra_values)[:max_length]",
                    "return message[:max_length]",
                ),
                encoding="utf-8",
            )

            checks = wave13_gate.check_check_framework_runtime(root)

        redaction = next(check for check in checks if check["name"] == "wave13-check-failure-redaction-and-classification")
        self.assertEqual(redaction["status"], "fail")
        self.assertIn("owner-token", redaction["message"])

    def test_wave13_missing_tests_or_docs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave13_tree(Path(tmp))
            (root / "tests" / "test_checker_check_workflow.py").unlink()
            (root / "docs" / "08_checker_design.md").write_text("Wave 12 only\n", encoding="utf-8")

            test_checks = wave13_gate.check_checker_tests(root)
            doc_checks = wave13_gate.check_docs(root)

        self.assertEqual(test_checks[0]["status"], "fail")
        self.assertIn("test_checker_check_workflow.py", test_checks[0]["message"])
        design = next(check for check in doc_checks if check["path"] == "docs/08_checker_design.md")
        self.assertEqual(design["status"], "fail")
        self.assertIn("Wave 13 CHECK/HAVOC Framework", design["message"])

    def test_wave13_rejects_early_exploit_or_fix_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave13_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_dedup_preview.py").write_text("print('future exploit')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch").write_text("future fix\n", encoding="utf-8")

            checks = wave13_gate.check_no_early_exploit_or_fix_scripts(root)

        self.assertTrue(all(check["status"] == "fail" for check in checks))
        self.assertTrue(any("aml_dedup_preview.py" in check["message"] for check in checks))
        self.assertTrue(any("aml_dedup_preview.patch" in check["message"] for check in checks))

    def test_wave13_rejects_vulnerable_behavior_marker_in_production_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave13_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "routes.go"
            target.write_text(target.read_text(encoding="utf-8") + "\nconst exploit_mode = true\n", encoding="utf-8")

            checks = wave13_gate.check_no_vulnerable_behavior_markers(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("exploit_mode", checks[0]["message"])

    def test_wave13_rejects_make_target_without_component_gate_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave13_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text("wave13-gate:\n\tpython -B scripts/check_wave13_gate.py\n", encoding="utf-8")

            checks = wave13_gate.check_makefile_wave13_gate(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("test_checker_*.py", checks[0]["message"])


def minimal_wave13_tree(root: Path) -> Path:
    checker_dir = root / "checkers" / "sentinel_aml"
    checker_dir.mkdir(parents=True)
    shutil.copyfile(ROOT / "checkers" / "sentinel_aml" / "checker.py", checker_dir / "checker.py")
    shutil.copyfile(ROOT / "checkers" / "sentinel_aml" / "checker_lib.py", checker_dir / "checker_lib.py")

    tests_dir = root / "tests"
    tests_dir.mkdir()
    for name in ("test_checker_foundation.py", "test_checker_check_workflow.py", "test_checker_put_workflow.py", "test_checker_get_workflow.py"):
        shutil.copyfile(ROOT / "tests" / name, tests_dir / name)

    docs = root / "docs"
    docs.mkdir()
    shutil.copyfile(ROOT / "docs" / "08_checker_design.md", docs / "08_checker_design.md")
    shutil.copyfile(ROOT / "docs" / "12_testing_strategy.md", docs / "12_testing_strategy.md")

    scripts = root / "scripts"
    scripts.mkdir()
    shutil.copyfile(ROOT / "scripts" / "validate_forcad_config.py", scripts / "validate_forcad_config.py")
    shutil.copyfile(ROOT / "config.yml", root / "config.yml")

    sploits = root / "sploits" / "sentinel_aml"
    sploits.mkdir(parents=True)
    shutil.copyfile(ROOT / "sploits" / "sentinel_aml" / "README.md", sploits / "README.md")

    fixes = root / "fixes" / "sentinel_aml"
    fixes.mkdir(parents=True)
    if (ROOT / "fixes" / "sentinel_aml" / "README.md").is_file():
        shutil.copyfile(ROOT / "fixes" / "sentinel_aml" / "README.md", fixes / "README.md")
    else:
        (fixes / "README.md").write_text("# Sentinel AML Reference Fixes\n", encoding="utf-8")

    internal = root / "internal" / "httpapi"
    internal.mkdir(parents=True, exist_ok=True)
    (internal / "routes.go").write_text("package httpapi\n", encoding="utf-8")
    return root


if __name__ == "__main__":
    unittest.main()
