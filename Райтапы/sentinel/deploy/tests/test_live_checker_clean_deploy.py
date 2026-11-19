import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_live_checker_clean_deploy.py"

spec = importlib.util.spec_from_file_location("check_live_checker_clean_deploy", SCRIPT_PATH)
live_checker = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = live_checker
spec.loader.exec_module(live_checker)


class LiveCheckerCleanDeployStaticTest(unittest.TestCase):
    def test_static_checks_pass_on_repository(self):
        result = live_checker.static_checks(ROOT)

        self.assertEqual(result["status"], "pass", result)

    def test_phase_plan_is_clean_check_havoc_only(self):
        self.assertEqual(
            live_checker.phase_plan(),
            [
                "static-preflight",
                "clean:start-postgres-api-worker",
                "clean:checker-check",
                "clean:checker-havoc",
            ],
        )

    def test_required_subchecks_cover_coarse_fix_modules(self):
        self.assertEqual(
            live_checker.REQUIRED_SUBCHECKS,
            (
                "health",
                "check_basic",
                "check_case_notes",
                "check_edd",
                "check_dedup",
                "check_audit",
                "check_graph",
                "check_export",
                "check_network_room",
                "check_retention",
            ),
        )
        self.assertTrue(set(live_checker.REQUIRED_SUBCHECKS).issubset(set(live_checker.checker_lib.DEFAULT_CHECK_SUBCHECKS)))

    def test_exit_classification_matches_hackerdom_codes(self):
        self.assertEqual(live_checker.classify_exit(live_checker.checker_lib.EXIT_OK), "OK")
        self.assertEqual(live_checker.classify_exit(live_checker.checker_lib.EXIT_MUMBLE), "MUMBLE")
        self.assertEqual(live_checker.classify_exit(live_checker.checker_lib.EXIT_DOWN), "DOWN")
        self.assertEqual(live_checker.classify_exit(77), "UNKNOWN(77)")

    def test_script_static_entrypoint_outputs_machine_readable_json(self):
        completed = subprocess.run(
            [sys.executable, "-B", str(SCRIPT_PATH)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = live_checker.json.loads(completed.stdout)
        self.assertEqual(payload["status"], "pass")
        self.assertIn("required_subchecks", payload)
        self.assertIn("check_network_room", payload["required_subchecks"])


class LiveCheckerCleanDeployOptionalLiveTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("SENTINEL_AML_RUN_LIVE_CHECKER") == "1", "live checker clean deploy is opt-in")
    def test_live_clean_deploy_check_havoc(self):
        completed = subprocess.run(
            [sys.executable, "-B", str(SCRIPT_PATH), "--run", "--python", sys.executable],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=300,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
        payload = live_checker.json.loads(completed.stdout)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual([phase["classification"] for phase in payload["phases"]], ["OK", "OK"])


if __name__ == "__main__":
    unittest.main()
