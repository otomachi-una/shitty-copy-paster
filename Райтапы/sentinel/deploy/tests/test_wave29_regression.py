import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave29_regression.py"

spec = importlib.util.spec_from_file_location("check_wave29_regression", SCRIPT_PATH)
regression = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(regression)


class Wave29RegressionTest(unittest.TestCase):
    def test_regression_uses_external_clean_copy_for_patch_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_repo(Path(tmp) / "repo")
            copied_roots: list[Path] = []

            def fake_copy(_source: Path, destination: Path) -> Path:
                copied_roots.append(destination)
                return minimal_repo(destination)

            original_copy = regression.copy_clean_repo
            regression.copy_clean_repo = fake_copy
            try:
                result = regression.validate_wave29_regression(root, python="python", go="go", runner=success_runner)
            finally:
                regression.copy_clean_repo = original_copy

        self.assertEqual(result["status"], "pass")
        self.assertEqual(len(copied_roots), 1)
        for copied in copied_roots:
            self.assertNotEqual(copied, root)

    def test_vulnerable_build_tags_run_all_five_tags(self):
        commands: list[list[str]] = []

        def runner(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_repo(Path(tmp) / "repo")
            check = regression.check_vulnerable_build_tags(root, go="go", runner=runner)

        self.assertEqual(check["status"], "pass")
        joined = "\n".join(" ".join(command) for command in commands)
        for scenario in regression.SCENARIOS:
            self.assertIn(f"-tags {scenario['tag']}", joined)
            for package in scenario["vulnerable_packages"]:
                self.assertIn(package, joined)

    def test_patch_scenario_rejects_failed_fixed_go_test(self):
        def runner(command, **kwargs):
            if command[:2] == ["go", "test"] and "./internal/httpapi" in command:
                return subprocess.CompletedProcess(command, 1, "", "fixed proof failed")
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_repo(Path(tmp) / "repo")
            check = regression.check_patch_scenarios_in_clean_copies(root, python="python", go="go", runner=runner)

        self.assertEqual(check["status"], "fail")
        self.assertIn("fixed tagged proof", check["message"])

    def test_patch_scenario_rejects_failed_checker_after_patch(self):
        def runner(command, **kwargs):
            if "unittest" in command and "test_checker_*.py" in command:
                return subprocess.CompletedProcess(command, 1, "", "checker failed")
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_repo(Path(tmp) / "repo")
            check = regression.check_patch_scenarios_in_clean_copies(root, python="python", go="go", runner=runner)

        self.assertEqual(check["status"], "fail")
        self.assertIn("checker regression after cumulative patches", check["message"])

    def test_exploit_compile_rejects_compile_failure(self):
        def runner(command, **kwargs):
            if any("aml_network_room.py" in part for part in command):
                return subprocess.CompletedProcess(command, 1, "", "syntax error")
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_repo(Path(tmp) / "repo")
            check = regression.check_exploit_compile(root, python="python", runner=runner)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.py", check["message"])


def success_runner(command, **kwargs):
    return subprocess.CompletedProcess(command, 0, "ok\n", "")


def minimal_repo(root: Path) -> Path:
    for dirname in ("fixes/sentinel_aml", "sploits/sentinel_aml", "internal/httpapi", "internal/graph", "internal/exporting", "internal/networkroom", "tests"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in regression.EXPLOITS:
        (root / relative).write_text("print('ok')\n", encoding="utf-8")
    for scenario in regression.SCENARIOS:
        (root / scenario["patch"]).write_text("diff --git a/a b/a\n", encoding="utf-8")
    return root


if __name__ == "__main__":
    unittest.main()
