import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "run_vulnerable_profile_tests.py"
spec = importlib.util.spec_from_file_location("run_vulnerable_profile_tests", SCRIPT_PATH)
profile_runner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(profile_runner)


class VulnerableProfileRunnerTests(unittest.TestCase):
    def test_runs_all_five_profiles_with_one_external_cache_pair(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append({"command": command, "env": kwargs["env"], "timeout": kwargs["timeout"]})
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            exit_code = profile_runner.run_scenarios(Path(tmp), go="go", package_timeout=7, runner=fake_run)

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(calls), 5)
        cache_dirs = {call["env"]["GOCACHE"] for call in calls}
        appdata_dirs = {call["env"]["APPDATA"] for call in calls}
        self.assertEqual(len(cache_dirs), 1)
        self.assertEqual(len(appdata_dirs), 1)
        self.assertNotIn(str(ROOT), next(iter(cache_dirs)))
        self.assertNotIn(str(ROOT), next(iter(appdata_dirs)))
        joined = "\n".join(" ".join(call["command"]) for call in calls)
        for tag, packages in profile_runner.SCENARIOS:
            self.assertIn(f"-tags {tag}", joined)
            for package in packages:
                self.assertIn(package, joined)
        self.assertTrue(all(call["timeout"] == 37 for call in calls))

    def test_timeout_returns_bounded_failure(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append({"command": command, "timeout": kwargs["timeout"]})
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        with tempfile.TemporaryDirectory() as tmp:
            exit_code = profile_runner.run_scenarios(Path(tmp), go="go", package_timeout=1, runner=fake_run)

        self.assertEqual(exit_code, 1)
        self.assertEqual(calls[0]["timeout"], 31)

    def test_default_outer_timeout_is_capped_for_final_gate_liveness(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append({"command": command, "timeout": kwargs["timeout"]})
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            exit_code = profile_runner.run_scenarios(Path(tmp), go="go", package_timeout=120, runner=fake_run)

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(call["timeout"] == 60 for call in calls))

    def test_accepts_shared_cache_pair_from_aggregate_gate(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append({"env": kwargs["env"]})
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = str(Path(tmp) / "cache")
            appdata_dir = str(Path(tmp) / "appdata")
            exit_code = profile_runner.run_scenarios(
                Path(tmp),
                go="go",
                package_timeout=7,
                runner=fake_run,
                cache_dir=cache_dir,
                appdata_dir=appdata_dir,
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual({call["env"]["GOCACHE"] for call in calls}, {cache_dir})
        self.assertEqual({call["env"]["APPDATA"] for call in calls}, {appdata_dir})


if __name__ == "__main__":
    unittest.main()
