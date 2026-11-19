import importlib.util
import io
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_split_package_gate.py"

spec = importlib.util.spec_from_file_location("check_split_package_gate", SCRIPT_PATH)
split_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(split_gate)


class SplitPackageGateTest(unittest.TestCase):
    def test_current_branch_has_no_static_failures(self):
        result = split_gate.validate_split_package_gate(ROOT)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_makefile_target_exists_and_excludes_release_archives(self):
        check = split_gate.check_makefile_target(ROOT)

        self.assertEqual(check["status"], "pass")
        target = split_gate.make_target_block((ROOT / "Makefile").read_text(encoding="utf-8"), "final-split-package-gate")
        self.assertIn("scripts/check_split_package_gate.py --run", target)
        self.assertNotIn("release-archive", target)
        self.assertNotIn("build_release_archive.py", target)

    def test_makefile_rejects_archive_generation_inside_final_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_split_gate_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace(
                    "$(PYTHON) -B scripts/check_split_package_gate.py --run --go $(GO) --python $(PYTHON) --docker $(DOCKER)",
                    "$(PYTHON) -B scripts/check_split_package_gate.py --run --go $(GO) --python $(PYTHON) --docker $(DOCKER)\n\t$(MAKE) release-archive",
                ),
                encoding="utf-8",
            )

            check = split_gate.check_makefile_target(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("release-archive", check["message"])

    def test_phase_plan_keeps_player_admin_and_organizer_evidence_separate(self):
        check = split_gate.check_phase_plan(ROOT)

        self.assertEqual(check["status"], "pass")
        phases = split_gate.command_phase_specs("python", "go", docker="docker")
        artifact_by_name = {phase["name"]: phase["artifact"] for phase in phases}
        self.assertEqual(artifact_by_name["player-package-runtime-proof"], "player-service")
        self.assertEqual(artifact_by_name["player-final-hygiene"], "player-service")
        self.assertEqual(artifact_by_name["admin-package-build"], "admin-checker")
        self.assertEqual(artifact_by_name["admin-inventory-gate"], "admin-checker")
        self.assertEqual(artifact_by_name["organizer-ad-stability-gate"], "organizer")
        joined = "\n".join(" ".join(str(part) for part in phase["command"]) for phase in phases)
        for marker in (
            "scripts/check_player_package_runtime.py",
            "scripts/check_player_bundle_hygiene.py",
            "--require-runtime-ready",
            "scripts/build_admin_bundle.py",
            "scripts/check_admin_bundle_hygiene.py",
            "scripts/check_ad_stability_gate.py --run",
            "scripts/check_archive_hygiene.py",
            "scripts/check_repository_submission_hygiene.py",
            "scripts/check_docs_tree.py",
            "scripts/validate_forcad_config.py",
        ):
            self.assertIn(marker, joined)
        self.assertNotIn("build_release_archive.py", joined)
        self.assertNotIn("release-archive", joined)

    def test_cleanup_only_refuses_to_remove_outside_repo_tmp(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "candidate"
            outside.mkdir()
            with self.assertRaises(RuntimeError):
                split_gate.cleanup_candidates(ROOT, str(outside))

    def test_cleanup_removes_empty_tmp_directory_after_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / split_gate.PLAYER_CANDIDATE
            candidate.mkdir(parents=True)
            allowlist = root / split_gate.PLAYER_ALLOWLIST
            allowlist.write_text("{}\n", encoding="utf-8")

            split_gate.cleanup_candidates(root, split_gate.PLAYER_CANDIDATE, split_gate.PLAYER_ALLOWLIST)

            self.assertFalse((root / "tmp").exists())

    def test_player_runtime_command_can_delegate_to_windows_host(self):
        command = split_gate.player_runtime_command(
            "python3",
            "go.exe",
            "docker.exe",
            database_url=split_gate.DEFAULT_PACKAGE_DATABASE_URL,
            base_url=split_gate.DEFAULT_PACKAGE_BASE_URL,
            host_player_runtime=True,
            repo_root=Path("/mnt/c/Users/example/Sentinel_AML"),
        )

        self.assertEqual(command[:4], ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass"])
        joined = " ".join(command)
        self.assertIn("Set-Location -LiteralPath", joined)
        self.assertIn("python -B scripts\\check_player_package_runtime.py", joined)
        self.assertIn("--go 'go'", joined)
        self.assertIn("--docker 'docker'", joined)

    def test_run_gate_emits_explicit_artifact_statuses_and_uses_timeouts(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append({"command": command, "timeout": timeout})
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_split_gate_tree(Path(tmp))
            (root / "tmp").mkdir(exist_ok=True)
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = split_gate.run_gate(
                root,
                python="python",
                go="go",
                docker="docker",
                database_url=split_gate.DEFAULT_PACKAGE_DATABASE_URL,
                base_url=split_gate.DEFAULT_PACKAGE_BASE_URL,
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertGreaterEqual(len(calls), 10)
        self.assertTrue(all(call["timeout"] > 0 for call in calls))
        output = stdout.getvalue()
        self.assertIn('"player-service"', output)
        self.assertIn('"admin-checker"', output)
        self.assertIn('"organizer-internal"', output)
        self.assertIn('"final_archives_created": false', output)
        self.assertIn("final-split-package-gate: pass elapsed=", output)

    def test_run_gate_cleans_candidates_on_failure(self):
        def fake_runner(command, *, cwd, env, timeout):
            return subprocess.CompletedProcess(command, 3, "", "failed\n")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_split_gate_tree(Path(tmp))
            candidate = root / split_gate.PLAYER_CANDIDATE
            candidate.mkdir(parents=True)
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = split_gate.run_gate(
                root,
                python="python",
                go="go",
                docker="docker",
                database_url=split_gate.DEFAULT_PACKAGE_DATABASE_URL,
                base_url=split_gate.DEFAULT_PACKAGE_BASE_URL,
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )

            self.assertEqual(exit_code, 3)
            self.assertFalse(candidate.exists())
            self.assertIn('"status": "fail"', stdout.getvalue())


def copy_split_gate_tree(destination: Path) -> Path:
    for name in ("scripts", "tests", "docs", "sploits", "fixes", "internal", "checkers", "cmd", "packaging"):
        source = ROOT / name
        target = destination / name
        if source.is_dir():
            shutil.copytree(
                source,
                target,
                ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc", "tmp"),
            )
    for name in ("Makefile", "config.yml", "docker-compose.yml", "go.mod", "go.sum"):
        shutil.copyfile(ROOT / name, destination / name)
    return destination


if __name__ == "__main__":
    unittest.main()
