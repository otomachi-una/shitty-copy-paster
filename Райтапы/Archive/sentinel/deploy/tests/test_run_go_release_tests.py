import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts" / "run_go_release_tests.py"
spec = importlib.util.spec_from_file_location("run_go_release_tests_under_test", RUNNER_PATH)
go_release_runner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(go_release_runner)


class GoReleaseRunnerLivenessTests(unittest.TestCase):
    def test_run_command_times_out_and_cleans_up_process_group(self):
        sleeper = "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); time.sleep(30)"

        with tempfile.TemporaryDirectory() as tmp:
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                go_release_runner.run_command(
                    [sys.executable, "-c", sleeper],
                    cwd=Path(tmp),
                    env=os.environ.copy(),
                    timeout=0.5,
                )
            elapsed = time.monotonic() - started

        self.assertLess(elapsed, 5)

    def test_run_command_returns_when_child_keeps_pipe_open_after_parent_exit(self):
        child = "import sys, time; print('child-ready'); sys.stdout.flush(); time.sleep(30)"
        parent = (
            "import subprocess, sys, time, warnings; "
            "warnings.filterwarnings('ignore', category=ResourceWarning); "
            "time.sleep(0.2); "
            f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
            "print('parent-ok')"
        )

        with tempfile.TemporaryDirectory() as tmp:
            started = time.monotonic()
            completed = go_release_runner.run_command(
                [sys.executable, "-c", parent],
                cwd=Path(tmp),
                env=os.environ.copy(),
                timeout=5,
            )
            elapsed = time.monotonic() - started

        self.assertEqual(completed.returncode, 0)
        self.assertLess(elapsed, 5)
        self.assertIn("parent-ok", completed.stdout)

    def test_release_runner_reports_stuck_package_as_bounded_failure(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append({"command": command, "cwd": cwd, "env": env, "timeout": timeout})
            if command[1] == "list":
                return subprocess.CompletedProcess(command, 0, "example.com/sentinel/stuck\n", "")
            raise subprocess.TimeoutExpired(command, timeout, output="partial output\n", stderr="partial error\n")

        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = go_release_runner.run_release_tests(
                Path(tmp),
                go="go",
                package_timeout=1,
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )

        self.assertEqual(exit_code, 1)
        self.assertIn("go test package: example.com/sentinel/stuck", stdout.getvalue())
        self.assertIn("go test timed out after 31s: example.com/sentinel/stuck", stderr.getvalue())
        self.assertEqual(calls[-1]["timeout"], 31)

    def test_release_runner_reuses_one_external_cache_pair_for_packages(self):
        def fake_runner(command, *, cwd, env, timeout):
            if command[1] == "list":
                return subprocess.CompletedProcess(command, 0, "example.com/sentinel/a\nexample.com/sentinel/b\n", "")
            calls.append({"command": command, "env": env, "timeout": timeout})
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = go_release_runner.run_release_tests(
                Path(tmp),
                go="go",
                package_timeout=9,
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual({call["env"]["GOCACHE"] for call in calls}, {calls[0]["env"]["GOCACHE"]})
        self.assertEqual({call["env"]["APPDATA"] for call in calls}, {calls[0]["env"]["APPDATA"]})
        self.assertNotIn(str(ROOT), calls[0]["env"]["GOCACHE"])
        self.assertNotIn(str(ROOT), calls[0]["env"]["APPDATA"])

    def test_release_runner_accepts_shared_cache_pair_from_aggregate_gate(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append({"command": command, "env": env})
            if command[1] == "list":
                return subprocess.CompletedProcess(command, 0, "example.com/sentinel/a\n", "")
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = str(Path(tmp) / "cache")
            appdata_dir = str(Path(tmp) / "appdata")
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = go_release_runner.run_release_tests(
                Path(tmp),
                go="go",
                package_timeout=9,
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
                cache_dir=cache_dir,
                appdata_dir=appdata_dir,
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual({call["env"]["GOCACHE"] for call in calls}, {cache_dir})
        self.assertEqual({call["env"]["APPDATA"] for call in calls}, {appdata_dir})
        self.assertIn(f"go release shared GOCACHE: {cache_dir}", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
