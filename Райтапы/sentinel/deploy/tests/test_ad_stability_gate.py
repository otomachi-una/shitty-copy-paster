import importlib.util
import io
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_ad_stability_gate.py"

spec = importlib.util.spec_from_file_location("check_ad_stability_gate", SCRIPT_PATH)
ad_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ad_gate)


class AdStabilityGateTest(unittest.TestCase):
    def test_current_branch_has_no_static_failures(self):
        result = ad_gate.validate_ad_stability_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_makefile_target_exists_and_excludes_release_archives(self):
        check = ad_gate.check_makefile_target(ROOT)

        self.assertEqual(check["status"], "pass")

        target = ad_gate.make_target_block((ROOT / "Makefile").read_text(encoding="utf-8"), "ad-stability-gate")
        self.assertIn("scripts/check_ad_stability_gate.py --run", target)
        self.assertNotIn("release-archive", target)
        self.assertNotIn("build_release_archive.py", target)

    def test_makefile_rejects_archive_generation_inside_stability_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_ad_gate_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace(
                    "$(PYTHON) -B scripts/check_ad_stability_gate.py --run --go $(GO) --python $(PYTHON)",
                    "$(PYTHON) -B scripts/check_ad_stability_gate.py --run --go $(GO) --python $(PYTHON)\n\t$(MAKE) release-archive",
                ),
                encoding="utf-8",
            )

            check = ad_gate.check_makefile_target(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("release-archive", check["message"])

    def test_makefile_rejects_missing_ad_stability_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_ad_gate_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(makefile.read_text(encoding="utf-8").replace("ad-stability-gate", "ad-stability-removed"), encoding="utf-8")

            check = ad_gate.check_makefile_target(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("target_present=False", check["message"])

    def test_phase_plan_includes_checker_sploit_fix_matrix_go_and_forcad_validations(self):
        check = ad_gate.check_phase_plan(ROOT)

        self.assertEqual(check["status"], "pass")
        phases = ad_gate.command_phase_specs("python", "go", cache_dir="cache-dir", appdata_dir="appdata-dir")
        joined = "\n".join(" ".join(str(part) for part in phase["command"]) for phase in phases)
        self.assertIn('unittest discover -s tests -p test_ad_stability_gate.py', joined)
        self.assertIn('unittest discover -s tests -p test_checker_*.py', joined)
        self.assertIn('unittest discover -s tests -p test_competition_matrix_gate.py', joined)
        self.assertIn("scripts/check_competition_matrix_gate.py", joined)
        self.assertIn("scripts/check_wave29_gate.py", joined)
        self.assertIn("scripts/run_vulnerable_profile_tests.py --go go --package-timeout 60", joined)
        self.assertIn("scripts/run_go_release_tests.py --go go --package-timeout 60", joined)
        self.assertIn("--cache-dir cache-dir --appdata-dir appdata-dir", joined)
        self.assertIn("go vet ./...", joined)
        self.assertIn("go build ./cmd/aml-api ./cmd/aml-worker", joined)
        self.assertIn("scripts/check_docs_tree.py", joined)
        self.assertIn("scripts/validate_forcad_config.py", joined)
        for relative in ad_gate.EXPECTED_EXPLOITS:
            self.assertIn(f"py_compile {relative}", joined)
        for relative in ad_gate.EXPECTED_PATCHES:
            self.assertIn(f"git apply --check --whitespace=error {relative}", joined)

    def test_phase_plan_rejects_missing_sploit_or_fix_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_ad_gate_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_network_room.py").unlink()
            (root / "fixes" / "sentinel_aml" / "aml_network_room.patch").unlink()

            check = ad_gate.check_phase_plan(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.py", check["message"])
        self.assertIn("aml_network_room.patch", check["message"])

    def test_runner_uses_process_tree_bounded_command_helper(self):
        check = ad_gate.check_runner_uses_bounded_process_trees(ROOT)

        self.assertEqual(check["status"], "pass")

    def test_run_gate_emits_phase_timing_and_uses_runner_timeouts(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append({"command": command, "timeout": timeout})
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_ad_gate_tree(Path(tmp))
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = ad_gate.run_gate(root, python="python", go="go", runner=fake_runner, stdout=stdout, stderr=stderr)

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertGreater(len(calls), 10)
        self.assertTrue(all(call["timeout"] > 0 for call in calls))
        self.assertIn("ad-stability-gate: phase 1/", stdout.getvalue())
        self.assertIn("gate_timeout=", stdout.getvalue())
        self.assertIn("elapsed=", stdout.getvalue())

    def test_run_gate_stops_on_bounded_phase_failure(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append(command)
            return subprocess.CompletedProcess(command, 7, "", "failed\n")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_ad_gate_tree(Path(tmp))
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = ad_gate.run_gate(root, python="python", go="go", runner=fake_runner, stdout=stdout, stderr=stderr)

        self.assertEqual(exit_code, 7)
        self.assertEqual(len(calls), 1)
        self.assertIn("failed after", stderr.getvalue())

    def test_docs_describe_stability_release_split(self):
        check = ad_gate.check_docs(ROOT)

        self.assertEqual(check["status"], "pass")


def copy_ad_gate_tree(destination: Path) -> Path:
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
