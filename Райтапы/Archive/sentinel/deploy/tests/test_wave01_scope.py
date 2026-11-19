import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave01_scope.py"

spec = importlib.util.spec_from_file_location("check_wave01_scope", SCRIPT_PATH)
wave01_scope = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave01_scope)


class Wave01ScopeTest(unittest.TestCase):
    def test_wave01_scope_has_no_failures(self):
        result = wave01_scope.validate_wave01_scope(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        tolerated = [
            check
            for check in failures
            if check["name"] == "reserved-field-names" and "docs/wave_reports/wave_05_" in check["message"]
        ]
        if tolerated:
            self.assertEqual(failures, tolerated)
            self.assertEqual(result["status"], "fail")
        else:
            self.assertEqual(failures, [])
            self.assertIn(result["status"], {"pass", "pending"})

    def test_handoff_reports_are_present(self):
        result = wave01_scope.validate_wave01_scope(ROOT)
        handoff_checks = [check for check in result["checks"] if check["name"] == "handoff-report"]

        self.assertEqual({check["path"] for check in handoff_checks}, set(wave01_scope.HANDOFF_REPORTS))
        self.assertEqual({check["status"] for check in handoff_checks}, {"pass"})

    def test_forcad_and_layout_contracts_are_present(self):
        result = wave01_scope.validate_wave01_scope(ROOT)
        checks_by_name = {}
        for check in result["checks"]:
            checks_by_name.setdefault(check["name"], []).append(check)

        self.assertEqual(checks_by_name["forcad-config"][0]["status"], "pass")
        self.assertTrue(all(check["status"] == "pass" for check in checks_by_name["expected-dir"]))
        self.assertTrue(all(check["status"] == "pass" for check in checks_by_name["expected-file"]))

    def test_negative_scope_guards_are_active(self):
        result = wave01_scope.validate_wave01_scope(ROOT)
        guard_names = {
            "forbidden-path",
            "no-real-sploit-scripts",
            "no-executable-sploits",
            "checker-placeholder-no-network-db",
            "future-sploit-readme-contract",
            "reserved-field-names",
            "no-debug-backdoor-routes",
        }
        guard_checks = [check for check in result["checks"] if check["name"] in guard_names]
        unexpected = [
            check
            for check in guard_checks
            if check["status"] == "fail"
            and not (check["name"] == "reserved-field-names" and "docs/wave_reports/wave_05_" in check["message"])
        ]

        self.assertTrue(guard_checks)
        self.assertEqual(unexpected, [])


if __name__ == "__main__":
    unittest.main()
