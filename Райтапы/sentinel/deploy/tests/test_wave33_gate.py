import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave33_gate.py"

spec = importlib.util.spec_from_file_location("check_wave33_gate", SCRIPT_PATH)
wave33_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave33_gate)


class Wave33GateTest(unittest.TestCase):
    def test_current_branch_has_no_static_failures(self):
        result = wave33_gate.validate_wave33_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_makefile_target_exists_and_excludes_release_archives(self):
        check = wave33_gate.check_makefile_target(ROOT)

        self.assertEqual(check["status"], "pass")
        target = wave33_gate.make_target_block((ROOT / "Makefile").read_text(encoding="utf-8"), "wave33-gate")
        self.assertIn("scripts/check_wave33_gate.py --run", target)
        self.assertNotIn("release-archive", target)
        self.assertNotIn("build_release_archive.py", target)

    def test_makefile_rejects_archive_generation_inside_wave33_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave33_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace(
                    "$(PYTHON) -B scripts/check_wave33_gate.py --run --go $(GO) --python $(PYTHON)",
                    "$(PYTHON) -B scripts/check_wave33_gate.py --run --go $(GO) --python $(PYTHON)\n\t$(MAKE) release-archive",
                ),
                encoding="utf-8",
            )

            check = wave33_gate.check_makefile_target(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("release-archive", check["message"])

    def test_artifact_first_static_checks_pass(self):
        result = wave33_gate.validate_artifact_first_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_artifact_first_makefile_target_is_bounded_aggregate(self):
        check = wave33_gate.check_artifact_first_makefile_target(ROOT)

        self.assertEqual(check["status"], "pass")
        target = wave33_gate.make_target_block((ROOT / "Makefile").read_text(encoding="utf-8"), "artifact-first-gate")
        self.assertIn("scripts/check_wave33_gate.py --artifact-first", target)
        self.assertNotIn("go test ./...", target)
        self.assertNotIn("release-archive", target)

    def test_artifact_first_phase_plan_order_builds_then_scans_artifact_bytes(self):
        check = wave33_gate.check_artifact_first_phase_plan(ROOT)

        self.assertEqual(check["status"], "pass")
        phases = wave33_gate.artifact_first_phase_specs("python", "go", docker="docker")
        names = [phase["name"] for phase in phases]
        self.assertLess(names.index("clean-generated"), names.index("build-transfer-artifacts"))
        self.assertLess(names.index("clean-generated"), names.index("verify-frontend-ui-source-scan"))
        self.assertLess(names.index("verify-frontend-ui-source-scan"), names.index("verify-frontend-ui-dist-scan"))
        self.assertLess(names.index("verify-frontend-ui-dist-scan"), names.index("build-transfer-artifacts"))
        self.assertLess(names.index("build-transfer-artifacts"), names.index("verify-artifact-inventory"))
        self.assertLess(names.index("verify-artifact-inventory"), names.index("verify-player-source-manifest"))
        self.assertLess(names.index("verify-player-source-manifest"), names.index("verify-player-source-hygiene"))
        self.assertLess(names.index("verify-player-source-hygiene"), names.index("verify-side-view-lexicon"))
        self.assertLess(names.index("verify-side-view-lexicon"), names.index("verify-semantic-red-herrings"))
        self.assertLess(names.index("verify-semantic-red-herrings"), names.index("verify-player-artifact-hygiene"))
        self.assertLess(names.index("verify-player-artifact-hygiene"), names.index("verify-admin-artifact-hygiene"))
        self.assertLess(names.index("verify-admin-artifact-hygiene"), names.index("verify-player-ui-artifact"))
        self.assertLess(names.index("verify-player-runtime-profile-evidence"), names.index("verify-admin-checker-sploit-fix-matrix-evidence"))
        self.assertLess(names.index("verify-admin-checker-sploit-fix-matrix-evidence"), names.index("verify-artifact-live-acceptance-binding"))
        joined = "\n".join(" ".join(str(part) for part in phase["command"]) for phase in phases).replace("\\", "/").replace("npm.cmd", "npm")
        verify_only_commands = [
            phase["command"]
            for phase in phases
            if "scripts/build_artifacts.py" in phase["command"] and "--verify-only" in phase["command"]
        ]
        self.assertEqual(len(verify_only_commands), 1)
        self.assertIn("scripts/check_repository_submission_hygiene.py --clean-generated --preserve-frontend-ui-build .", joined)
        self.assertIn("npm --prefix frontend run security:scan:source", joined)
        self.assertIn("npm --prefix frontend run security:scan:dist", joined)
        self.assertIn("scripts/build_artifacts.py --output-root out", joined)
        self.assertNotIn("--no-frontend-ui", joined)
        self.assertIn("scripts/check_player_source_manifest.py --output-root out", joined)
        self.assertIn("scripts/check_player_source_hygiene.py out/artifacts/sentinel-aml-player-source.tar.gz", joined)
        self.assertIn("scripts/check_side_view_lexicon.py out/artifacts/sentinel-aml-player-source.tar.gz --require-artifact", joined)
        self.assertIn("scripts/check_semantic_red_herrings.py", joined)
        self.assertIn("scripts/check_player_bundle_hygiene.py out/artifacts/sentinel-aml-player-service.tar.gz", joined)
        self.assertIn("scripts/check_admin_bundle_hygiene.py out/artifacts/sentinel-aml-admin-organizer.tar.gz", joined)
        self.assertIn("scripts/check_competition_runtime_profile.py --mode binary", joined)
        self.assertIn("scripts/check_competition_matrix_gate.py", joined)
        self.assertIn("scripts/check_artifact_first_live_acceptance.py --output-root out", joined)

    def test_phase_plan_includes_hygiene_candidates_ad_evidence_and_forcad(self):
        check = wave33_gate.check_phase_plan(ROOT)

        self.assertEqual(check["status"], "pass")
        phases = wave33_gate.command_phase_specs("python", "go", cache_dir="cache-dir", appdata_dir="appdata-dir")
        joined = "\n".join(" ".join(str(part) for part in phase["command"]) for phase in phases)
        for marker in (
            "test_player_bundle*.py",
            "scripts/check_repository_submission_hygiene.py",
            "scripts/build_player_bundle.py",
            "scripts/build_admin_bundle.py",
            "--allow-wave33-local-candidates",
            "scripts/check_player_bundle_hygiene.py",
            "packaging/player",
            "test_checker_*.py",
            "test_competition_matrix_gate.py",
            "scripts/check_competition_matrix_gate.py",
            "scripts/run_vulnerable_profile_tests.py --go go --package-timeout 60",
            "scripts/run_go_release_tests.py --go go --package-timeout 60",
            "--cache-dir cache-dir --appdata-dir appdata-dir",
            "go vet ./...",
            "go build ./cmd/aml-api ./cmd/aml-worker",
            "scripts/check_docs_tree.py",
            "scripts/validate_forcad_config.py",
            "scripts/check_wave33_gate.py --cleanup-only",
        ):
            self.assertIn(marker, joined)
        names = [phase["name"] for phase in phases]
        self.assertLess(names.index("repository-submission-hygiene-strict"), names.index("player-candidate-build"))
        self.assertGreater(names.index("repository-submission-hygiene-local-staging"), names.index("admin-candidate-build"))
        self.assertLess(names.index("repository-submission-hygiene-local-staging"), names.index("player-candidate-hygiene"))
        self.assertGreater(names.index("cleanup-wave33-generated-candidates"), names.index("forcad-config"))
        for relative in wave33_gate.EXPECTED_EXPLOITS:
            self.assertIn(f"py_compile {relative}", joined)
        for relative in wave33_gate.EXPECTED_PATCHES:
            self.assertIn(f"git apply --check --whitespace=error {relative}", joined)
        self.assertNotIn("build_release_archive.py", joined)
        self.assertNotIn("release-archive", joined)

    def test_participant_docs_clean_check_fails_on_banned_terms(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave33_tree(Path(tmp))
            (root / "packaging" / "player" / "README.md").write_text(
                "Use checker_secret and AML-1 hints here.\n",
                encoding="utf-8",
            )

            check = wave33_gate.check_player_docs_clean(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("checker", check["message"])
        self.assertIn("AML-1", check["message"])

    def test_candidate_builder_policy_rejects_archive_builder_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave33_tree(Path(tmp))
            builder = root / "scripts" / "build_player_bundle.py"
            builder.write_text(builder.read_text(encoding="utf-8") + "\nimport tarfile\n", encoding="utf-8")

            check = wave33_gate.check_candidate_builder_policy(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("tarfile", check["message"])

    def test_cleanup_only_removes_known_wave33_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            player = root / wave33_gate.PLAYER_CANDIDATE
            admin = root / wave33_gate.ADMIN_CANDIDATE
            player.mkdir(parents=True)
            admin.mkdir(parents=True)
            allowlist = root / wave33_gate.PLAYER_ALLOWLIST
            allowlist.write_text("{}\n", encoding="utf-8")

            wave33_gate.cleanup_generated_candidates(root)

            self.assertFalse(player.exists())
            self.assertFalse(admin.exists())
            self.assertFalse(allowlist.exists())
            self.assertFalse((root / "tmp").exists())

    def test_run_gate_emits_timing_and_uses_bounded_runner(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append({"command": command, "timeout": timeout})
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave33_tree(Path(tmp))
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = wave33_gate.run_gate(root, python="python", go="go", runner=fake_runner, stdout=stdout, stderr=stderr)

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertGreaterEqual(len(calls), 20)
        self.assertTrue(all(call["timeout"] > 0 for call in calls))
        joined = "\n".join(" ".join(call["command"]) for call in calls)
        self.assertIn("scripts/check_repository_submission_hygiene.py", joined)
        self.assertIn("--allow-wave33-local-candidates", joined)
        self.assertIn("scripts/check_wave33_gate.py --cleanup-only", joined)
        self.assertIn("wave33-gate: phase 1/", stdout.getvalue())
        self.assertIn("gate_timeout=", stdout.getvalue())
        self.assertIn("elapsed=", stdout.getvalue())

    def test_run_gate_stops_on_first_failure(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append(command)
            return subprocess.CompletedProcess(command, 9, "", "failed\n")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave33_tree(Path(tmp))
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = wave33_gate.run_gate(root, python="python", go="go", runner=fake_runner, stdout=stdout, stderr=stderr)

        self.assertEqual(exit_code, 9)
        self.assertEqual(len(calls), 1)
        self.assertIn("failed after", stderr.getvalue())

    def test_artifact_first_run_writes_summary_and_uses_bounded_runner(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append({"command": command, "timeout": timeout})
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave33_tree(Path(tmp))
            create_minimal_artifact_outputs(root / "out")
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = wave33_gate.run_artifact_first_gate(
                root,
                python="python",
                go="go",
                docker="docker",
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )
            summary = json.loads((root / wave33_gate.DEFAULT_ARTIFACT_FIRST_SUMMARY).read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertGreaterEqual(len(calls), 14)
        self.assertTrue(all(call["timeout"] > 0 for call in calls))
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["schema"], "sentinel-aml-artifact-first-gate.v1")
        self.assertTrue(summary["artifact_evidence"]["player_artifact"]["exists"])
        self.assertTrue(summary["artifact_evidence"]["player_source_artifact"]["exists"])
        self.assertRegex(summary["player_artifact_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(summary["player_source_artifact_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(summary["admin_artifact_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(summary["runtime_validation"]["player_artifact_sha256"], summary["player_artifact_sha256"])
        self.assertEqual(summary["runtime_validation"]["admin_artifact_sha256"], summary["admin_artifact_sha256"])
        self.assertEqual(summary["runtime_validation"]["runtime_smoke"]["status"], "external-required")
        self.assertEqual(summary["runtime_validation"]["checker_check_havoc"]["status"], "external-required")
        self.assertEqual(summary["runtime_validation"]["sploit_matrix"]["status"], "external-required")
        self.assertEqual(summary["runtime_validation"]["sploit_matrix"]["expected_count"], 5)
        self.assertEqual(summary["runtime_validation"]["fix_workflow"]["status"], "external-required")
        self.assertEqual(summary["runtime_validation"]["fix_workflow"]["expected_count"], 5)
        self.assertEqual(summary["runtime_validation"]["matrix_status"]["status"], "external-required")
        self.assertEqual(summary["external_gates"][0]["status"], "external-required")
        self.assertIn("checker-check-havoc-from-admin-artifact", {gate["name"] for gate in summary["external_gates"]})
        self.assertIn("five-sploits-from-admin-artifact", {gate["name"] for gate in summary["external_gates"]})
        self.assertIn("five-fixes-accepted-workflow", {gate["name"] for gate in summary["external_gates"]})
        self.assertIn("artifact-first-gate: phase 1/", stdout.getvalue())
        self.assertIn("validation summary", stdout.getvalue())

    def test_artifact_first_gate_fails_on_stale_artifact_verification(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append(command)
            if "scripts/build_artifacts.py" in command and "--verify-only" in command:
                return subprocess.CompletedProcess(command, 17, '{"status":"fail"}\n', "")
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave33_tree(Path(tmp))
            create_minimal_artifact_outputs(root / "out")
            (root / "out" / "artifacts" / "stale.tar.gz").write_text("old\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = wave33_gate.run_artifact_first_gate(
                root,
                python="python",
                go="go",
                docker="docker",
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )
            summary = json.loads((root / wave33_gate.DEFAULT_ARTIFACT_FIRST_SUMMARY).read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 17)
        self.assertEqual(len(calls), 5)
        self.assertEqual(summary["status"], "fail")
        self.assertIn("verify-artifact-inventory exit=17", summary["message"])
        self.assertIn("failed after", stderr.getvalue())

    def test_artifact_first_gate_writes_summary_on_phase_timeout(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append(command)
            if "scripts/build_artifacts.py" in command and "--verify-only" in command:
                raise subprocess.TimeoutExpired(command, timeout, output="partial\n", stderr="hung\n")
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave33_tree(Path(tmp))
            create_minimal_artifact_outputs(root / "out")
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = wave33_gate.run_artifact_first_gate(
                root,
                python="python",
                go="go",
                docker="docker",
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )
            summary = json.loads((root / wave33_gate.DEFAULT_ARTIFACT_FIRST_SUMMARY).read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 1)
        self.assertEqual(len(calls), 5)
        self.assertEqual(summary["status"], "fail")
        self.assertEqual(summary["phases"][-1]["name"], "verify-artifact-inventory")
        self.assertIn("timeout after", summary["message"])
        self.assertRegex(summary["player_artifact_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(summary["admin_artifact_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("hung", stderr.getvalue())

    def test_artifact_first_gate_writes_summary_on_phase_launch_error(self):
        def fake_runner(command, *, cwd, env, timeout):
            if "scripts/build_artifacts.py" in command:
                raise OSError("tool missing")
            return subprocess.CompletedProcess(command, 0, "ok\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = copy_wave33_tree(Path(tmp))
            create_minimal_artifact_outputs(root / "out")
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = wave33_gate.run_artifact_first_gate(
                root,
                python="python",
                go="go",
                docker="docker",
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )
            summary = json.loads((root / wave33_gate.DEFAULT_ARTIFACT_FIRST_SUMMARY).read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 1)
        self.assertEqual(summary["status"], "fail")
        self.assertEqual(summary["phases"][-1]["name"], "build-transfer-artifacts")
        self.assertIn("launch failed", summary["message"])
        self.assertIn("tool missing", stderr.getvalue())


def copy_wave33_tree(destination: Path) -> Path:
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


def create_minimal_artifact_outputs(output_root: Path) -> None:
    for relative in (
        wave33_gate.PLAYER_ARTIFACT,
        wave33_gate.PLAYER_SOURCE_ARTIFACT,
        wave33_gate.ADMIN_ARTIFACT,
        wave33_gate.PLAYER_MANIFEST,
        wave33_gate.PLAYER_SOURCE_MANIFEST,
        wave33_gate.ADMIN_MANIFEST,
        wave33_gate.CHECKSUMS_FILE,
    ):
        path = output_root.parent / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative.as_posix() + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
