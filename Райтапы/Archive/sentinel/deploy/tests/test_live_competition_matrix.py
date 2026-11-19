import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_live_competition_matrix.py"

spec = importlib.util.spec_from_file_location("check_live_competition_matrix", SCRIPT_PATH)
live_matrix = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = live_matrix
spec.loader.exec_module(live_matrix)


class LiveCompetitionMatrixStaticTest(unittest.TestCase):
    def test_static_checks_pass_on_repository(self):
        result = live_matrix.static_checks(ROOT)
        self.assertEqual(result["status"], "pass", result)

    def test_matrix_covers_all_five_sploits_and_fixes(self):
        rows = list(live_matrix.AML_CASES)
        self.assertEqual([row.aml_id for row in rows], ["AML-1", "AML-2", "AML-3", "AML-4", "AML-5"])
        self.assertEqual(len({row.sploit for row in rows}), 5)
        self.assertEqual(len({row.fix_patch for row in rows}), 5)
        for row in rows:
            self.assertTrue((ROOT / row.sploit).is_file(), row)
            self.assertTrue((ROOT / row.fix_patch).is_file(), row)

    def test_phase_plan_contains_black_box_checker_sploit_fix_evidence(self):
        plan = live_matrix.phase_plan()
        joined = "\n".join(plan)
        self.assertIn("vulnerable:start-postgres-api-worker", joined)
        for aml_id in ("AML-1", "AML-2", "AML-3", "AML-4", "AML-5"):
            for marker in (
                "checker-put",
                "reference-sploit-extracts-flag",
                "checker-get",
                "checker-check",
                "checker-havoc",
                "apply-reference-fix-isolated-copy",
                "fixed-reference-sploit-blocked",
                "fixed-checker-get",
                "fixed-checker-check",
                "fixed-checker-havoc",
            ):
                self.assertIn(f"{aml_id}:{marker}", joined)

    def test_aml2_requires_product_neutral_entity_locator(self):
        aml2 = next(row for row in live_matrix.AML_CASES if row.aml_id == "AML-2")
        attack_data = {"service": "sentinel_aml", "entity_ref": "public-related-entity", "matching_reference": "match-ref"}

        normalized = live_matrix.normalize_attack_data_for_aml(aml2, attack_data)

        self.assertEqual(normalized["entity_ref"], "public-related-entity")
        self.assertEqual(normalized["matching_reference"], "match-ref")
        self.assertNotIn("password", normalized)
        self.assertNotIn("token", normalized)

        with self.assertRaises(live_matrix.MatrixFailure):
            live_matrix.normalize_attack_data_for_aml(aml2, {"service": "sentinel_aml", "matching_reference": "match-ref"})

    def test_checker_put_parser_uses_pfr_stdout_and_stderr_streams(self):
        class FakeRunner:
            def __init__(self):
                self.env = None

            def run(self, command, *, cwd, env=None, timeout=30, check=True):
                self.env = env
                return live_matrix.CommandResult(
                    command,
                    live_matrix.CHECKER_OK,
                    '{"service":"sentinel_aml","case_id":12,"entity_ref":"party-12"}',
                    "private-state\n",
                    0.1,
                )

        runner = FakeRunner()
        private_state, attack_data = live_matrix.checker_put(runner, sys.executable, "http://service", "FLAG{unit}", 1, "matrix-secret")

        self.assertEqual(private_state, "private-state")
        self.assertEqual(attack_data["case_id"], 12)
        self.assertEqual(runner.env["SENTINEL_AML_CHECKER_SECRET"], "matrix-secret")

    def test_script_static_entrypoint_outputs_machine_readable_json(self):
        completed = subprocess.run(
            [sys.executable, "-B", str(SCRIPT_PATH)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = live_matrix.json.loads(completed.stdout)
        self.assertEqual(payload["status"], "pass")
        self.assertIn("phase_plan", payload)


class LiveCompetitionMatrixOptionalLiveTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("SENTINEL_AML_RUN_LIVE_MATRIX") == "1", "live matrix is opt-in")
    def test_live_matrix_against_docker_postgres_runtime(self):
        completed = subprocess.run(
            [sys.executable, "-B", str(SCRIPT_PATH), "--run", "--python", sys.executable],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=900,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
        payload = live_matrix.json.loads(completed.stdout)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(len(payload["rows"]), 10)


if __name__ == "__main__":
    unittest.main()
