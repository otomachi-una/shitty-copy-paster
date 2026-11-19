import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave15_gate.py"

spec = importlib.util.spec_from_file_location("check_wave15_gate", SCRIPT_PATH)
wave15_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave15_gate)


class Wave15GateTest(unittest.TestCase):
    def test_wave15_gate_current_branch_has_no_failures(self):
        result = wave15_gate.validate_wave15_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_wave15_rejects_missing_vulnerable_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave15_tree(Path(tmp))
            (root / "internal" / "httpapi" / "audit_profile_aml2_vulnerable.go").unlink()

            check = wave15_gate.check_profile_split(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml2_vulnerable", check["message"])

    def test_wave15_rejects_edd_leak_in_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave15_tree(Path(tmp))
            profile = root / "internal" / "httpapi" / "audit_profile_aml2_vulnerable.go"
            profile.write_text(profile.read_text(encoding="utf-8") + "\nconst bad = \"confidential_comment\"\n", encoding="utf-8")

            check = wave15_gate.check_profile_split(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("confidential_comment", check["message"])

    def test_wave15_rejects_reference_exploit_or_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave15_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_audit_timeline.py").write_text("print('future exploit')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch").write_text("future fix\n", encoding="utf-8")

            check = wave15_gate.check_no_reference_exploit_or_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_audit_timeline.py", check["message"])
        self.assertIn("aml_audit_timeline.patch", check["message"])

    def test_wave15_rejects_debug_admin_profile_toggle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave15_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "bad_toggle.go"
            target.write_text("package httpapi\nconst EnableDebugAdminAuditVariant = true\n", encoding="utf-8")

            check = wave15_gate.check_no_debug_admin_toggles(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("bad_toggle.go", check["message"])
        self.assertIn("EnableDebugAdmin", check["message"])

    def test_wave15_rejects_future_aml_activation_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave15_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "aml3_profile.go"
            target.write_text("package httpapi\nconst aml3_vulnerable = true\n", encoding="utf-8")

            check = wave15_gate.check_no_future_aml_activation(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml3_vulnerable", check["message"])

    def test_wave15_requires_makefile_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave15_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(makefile.read_text(encoding="utf-8").replace("wave15-gate:", "wave15-disabled:"), encoding="utf-8")

            check = wave15_gate.check_makefile_wave15_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave15-gate", check["message"])

    def test_checker_unittest_discovery_returns_after_ok(self):
        command = [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_checker_*.py",
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            output = ((exc.stdout or "") + "\n" + (exc.stderr or "")).strip()
            self.fail(f"checker unittest discovery did not return within timeout after output:\n{output[-4000:]}")

        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, output[-4000:])
        self.assertIn("OK", output)
        self.assertIn("Ran ", output)


def minimal_wave15_tree(root: Path) -> Path:
    for relative in (
        "internal/httpapi/audit_profile_secure.go",
        "internal/httpapi/audit_profile_aml2_vulnerable.go",
        "internal/httpapi/server.go",
        "internal/httpapi/audit_timeline_test.go",
        "internal/httpapi/visibility_leak_test.go",
        "internal/httpapi/aml2_vulnerable_audit_test.go",
        "docs/09_vulnerability_matrix.md",
        "docs/06_visibility_and_projections.md",
        "docs/audit_export_graph_invariants.md",
        "docs/12_testing_strategy.md",
        "docs/15_risk_register.md",
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
