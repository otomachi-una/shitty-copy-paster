import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave30_gate.py"

spec = importlib.util.spec_from_file_location("check_wave30_gate", SCRIPT_PATH)
wave30_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave30_gate)


class Wave30GateTest(unittest.TestCase):
    def test_wave30_gate_current_branch_has_no_failures(self):
        result = wave30_gate.validate_wave30_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_makefile_rejects_missing_wave30_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave30_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(makefile.read_text(encoding="utf-8").replace("wave30-gate", "wave30-removed"), encoding="utf-8")

            check = wave30_gate.check_wave30_make_target(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("target_present=False", check["message"])

    def test_makefile_rejects_docs_only_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave30_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                ".PHONY: wave30-gate\n\nwave30-gate:\n\t$(PYTHON) -B scripts/check_docs_tree.py\n",
                encoding="utf-8",
            )

            check = wave30_gate.check_wave30_make_target(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave29-gate", check["message"])
        self.assertIn("release-archive", check["message"])

    def test_makefile_rejects_missing_release_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave30_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace("\n\t$(MAKE) release-archive", ""),
                encoding="utf-8",
            )

            check = wave30_gate.check_wave30_make_target(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("release-archive", check["message"])

    def test_docs_must_name_final_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave30_tree(Path(tmp))
            summary = root / "docs" / "wave_reports" / "wave_30_final_validation_summary.md"
            summary.write_text(summary.read_text(encoding="utf-8").replace("timeout 300 make wave30-gate", ""), encoding="utf-8")

            check = wave30_gate.check_wave30_docs(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("timeout 300 make wave30-gate", check["message"])

    def test_delegate_rejects_weakened_wave29_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave30_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(makefile.read_text(encoding="utf-8").replace("scripts/run_vulnerable_profile_tests.py", "scripts/removed.py"), encoding="utf-8")

            check = wave30_gate.check_wave29_delegate_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("failing Wave 29 checks", check["message"])

    def test_rejects_plain_subprocess_vulnerable_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave30_tree(Path(tmp))
            runner = root / "scripts" / "run_vulnerable_profile_tests.py"
            runner.write_text(
                runner.read_text(encoding="utf-8").replace("runner: Runner = run_command", "runner: Runner = subprocess.run")
                + "\n# bad fallback subprocess.run(\n",
                encoding="utf-8",
            )

            check = wave30_gate.check_bounded_vulnerable_profile_runner(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("subprocess.run(", check["message"])


def copy_wave30_tree(destination: Path) -> Path:
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
