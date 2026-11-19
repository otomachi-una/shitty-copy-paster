import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave14_gate.py"

spec = importlib.util.spec_from_file_location("check_wave14_gate", SCRIPT_PATH)
wave14_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave14_gate)


class Wave14GateTest(unittest.TestCase):
    def test_wave14_gate_current_branch_has_no_failures(self):
        result = wave14_gate.validate_wave14_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_wave14_rejects_missing_vulnerable_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave14_tree(Path(tmp))
            (root / "internal" / "httpapi" / "dedup_profile_aml1_vulnerable.go").unlink()

            check = wave14_gate.check_profile_split(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("private_notes", check["message"])

    def test_wave14_rejects_edd_leak_in_targeted_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave14_tree(Path(tmp))
            repository = root / "internal" / "casework" / "repository.go"
            repository.write_text(
                repository.read_text(encoding="utf-8").replace(
                    "SELECT cn.id, cn.case_id, cn.author_user_id, cn.visibility, cn.body, cn.created_at, cn.updated_at",
                    "SELECT cn.id, cn.case_id, cn.author_user_id, cn.visibility, cn.body, edd_records.confidential_comment, cn.created_at, cn.updated_at",
                    1,
                ),
                encoding="utf-8",
            )

            check = wave14_gate.check_targeted_repository_lookup(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("edd_records", check["message"])

    def test_wave14_rejects_reference_exploit_or_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave14_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_dedup_preview.py").write_text("print('future exploit')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch").write_text("future fix\n", encoding="utf-8")

            check = wave14_gate.check_no_reference_exploit_or_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_dedup_preview.py", check["message"])
        self.assertIn("aml_dedup_preview.patch", check["message"])

    def test_wave14_rejects_debug_admin_profile_toggle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave14_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "bad_toggle.go"
            target.write_text("package httpapi\nconst debugVariantToggle = true\n", encoding="utf-8")

            check = wave14_gate.check_no_debug_admin_toggles(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("debugVariantToggle", check["message"])

    def test_wave14_rejects_future_aml_activation_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave14_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "aml2_profile.go"
            target.write_text("package httpapi\nconst aml2_vulnerable = true\n", encoding="utf-8")

            check = wave14_gate.check_no_future_aml_activation(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml2_vulnerable", check["message"])

    def test_wave14_requires_makefile_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave14_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(makefile.read_text(encoding="utf-8").replace("wave14-gate:", "wave14-disabled:"), encoding="utf-8")

            check = wave14_gate.check_makefile_wave14_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave14-gate", check["message"])

    def test_wave14_requires_task_handoff_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave14_tree(Path(tmp))
            (root / "docs" / "wave_reports" / "wave_14_W14-T03_handoff.md").unlink()

            check = wave14_gate.check_handoff_reports(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave_14_W14-T03_handoff.md", check["message"])

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


def minimal_wave14_tree(root: Path) -> Path:
    for relative in (
        "internal/httpapi/dedup_profile_secure.go",
        "internal/httpapi/dedup_profile_aml1_vulnerable.go",
        "internal/httpapi/server.go",
        "internal/httpapi/domain_server_test.go",
        "internal/httpapi/aml1_vulnerable_dedup_test.go",
        "internal/casework/repository.go",
        "docs/09_vulnerability_matrix.md",
        "docs/06_visibility_and_projections.md",
        "docs/12_testing_strategy.md",
        "docs/15_risk_register.md",
        "docs/wave_reports/wave_14_W14-T01_handoff.md",
        "docs/wave_reports/wave_14_W14-T02_handoff.md",
        "docs/wave_reports/wave_14_W14-T03_handoff.md",
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
