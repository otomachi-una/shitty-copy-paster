import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave18_gate.py"

spec = importlib.util.spec_from_file_location("check_wave18_gate", SCRIPT_PATH)
wave18_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave18_gate)


class Wave18GateTest(unittest.TestCase):
    def test_wave18_gate_current_branch_has_no_failures(self):
        result = wave18_gate.validate_wave18_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_wave18_rejects_missing_vulnerable_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            (root / "internal" / "httpapi" / "network_room_profile_aml5_vulnerable.go").unlink()

            check = wave18_gate.check_profile_split(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml5_vulnerable", check["message"])

    def test_wave18_rejects_unrelated_private_fields_in_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            profile = root / "internal" / "httpapi" / "network_room_profile_aml5_vulnerable.go"
            profile.write_text(profile.read_text(encoding="utf-8") + "\nconst bad = \"source_of_funds diff_json\"\n", encoding="utf-8")

            check = wave18_gate.check_profile_split(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("source_of_funds", check["message"])
        self.assertIn("diff_json", check["message"])

    def test_wave18_rejects_reference_exploit_or_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_network_room.py").write_text("print('future exploit')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "aml_network_room.patch").write_text("future fix\n", encoding="utf-8")

            check = wave18_gate.check_no_reference_exploit_or_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.py", check["message"])
        self.assertIn("aml_network_room.patch", check["message"])

    def test_wave18_rejects_debug_admin_profile_toggle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "bad_toggle.go"
            target.write_text("package httpapi\nconst EnableDebugAdminNetworkVariant = true\n", encoding="utf-8")

            check = wave18_gate.check_no_debug_admin_toggles(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("bad_toggle.go", check["message"])
        self.assertIn("EnableDebugAdmin", check["message"])

    def test_wave18_requires_makefile_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text("competition-matrix-gate:\n\tpython -B scripts/check_competition_matrix_gate.py\n", encoding="utf-8")

            check = wave18_gate.check_makefile_wave18_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave18-gate", check["message"])

    def test_wave18_requires_deterministic_tagged_runner_in_makefile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace(
                    "$(GO_RELEASE_ENV) python -B scripts/run_aml5_tagged_tests.py",
                    "$(GO_OFFLINE_ENV) go test -tags aml5_vulnerable ./...",
                ),
                encoding="utf-8",
            )

            check = wave18_gate.check_makefile_wave18_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("scripts/run_aml5_tagged_tests.py", check["message"])
        self.assertIn("go test -tags aml5_vulnerable ./...", check["message"])

    def test_wave18_requires_archive_hygiene_in_makefile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace(
                    "\n\tpython -B scripts/check_archive_hygiene.py",
                    "",
                ),
                encoding="utf-8",
            )

            check = wave18_gate.check_makefile_wave18_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("check_archive_hygiene.py", check["message"])

    def test_wave18_requires_release_env_for_go_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace("$(GO_RELEASE_ENV) go test ./...", "$(GO_OFFLINE_ENV) go test ./..."),
                encoding="utf-8",
            )

            check = wave18_gate.check_makefile_wave18_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("GO_RELEASE_ENV", check["message"])
        self.assertIn("GO_OFFLINE_ENV", check["message"])

    def test_wave18_requires_deterministic_tagged_runner_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            (root / "scripts" / "run_aml5_tagged_tests.py").unlink()

            check = wave18_gate.check_deterministic_tagged_runner(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("run_aml5_tagged_tests.py", check["path"])

    def test_wave18_runner_rejects_weakened_tagged_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            runner = root / "scripts" / "run_aml5_tagged_tests.py"
            runner.write_text("TAG = \"aml5_vulnerable\"\n# missing go list package sweep\n", encoding="utf-8")

            check = wave18_gate.check_deterministic_tagged_runner(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn('"./..."', check["message"])

    def test_wave18_requires_archive_hygiene_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave18_tree(Path(tmp))
            gitignore = root / ".gitignore"
            gitignore.write_text(gitignore.read_text(encoding="utf-8").replace(".gocache*/", ".gocache/\n"), encoding="utf-8")

            check = wave18_gate.check_archive_hygiene_policy(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn(".gocache*/", check["message"])


def minimal_wave18_tree(root: Path) -> Path:
    for relative in (
        "internal/networkroom/repository.go",
        "internal/networkroom/repository_test.go",
        "internal/networkroom/dossier_profile_aml5_vulnerable.go",
        "internal/networkroom/repository_aml5_vulnerable.go",
        "internal/networkroom/repository_aml5_vulnerable_test.go",
        "internal/httpapi/network_room_profile_secure.go",
        "internal/httpapi/network_room_profile_aml5_vulnerable.go",
        "internal/httpapi/network_room_server_test.go",
        "internal/httpapi/aml5_vulnerable_network_room_test.go",
        "docs/wave_reports/wave_18_W18-T01_handoff.md",
        "docs/wave_reports/wave_18_W18-F01_handoff.md",
        "docs/wave_reports/wave_18_W18-F02_handoff.md",
        "scripts/run_aml5_tagged_tests.py",
        "scripts/check_archive_hygiene.py",
        "tests/test_archive_hygiene.py",
        ".gitignore",
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
