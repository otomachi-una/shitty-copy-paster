import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PLAYER_SCRIPT_PATH = ROOT / "scripts" / "build_player_bundle.py"
player_spec = importlib.util.spec_from_file_location("build_player_bundle", PLAYER_SCRIPT_PATH)
build_player_bundle = importlib.util.module_from_spec(player_spec)
assert player_spec.loader is not None
player_spec.loader.exec_module(build_player_bundle)

ADMIN_SCRIPT_PATH = ROOT / "scripts" / "build_admin_bundle.py"
admin_spec = importlib.util.spec_from_file_location("build_admin_bundle", ADMIN_SCRIPT_PATH)
build_admin_bundle = importlib.util.module_from_spec(admin_spec)
assert admin_spec.loader is not None
admin_spec.loader.exec_module(build_admin_bundle)

HYGIENE_SCRIPT_PATH = ROOT / "scripts" / "check_player_bundle_hygiene.py"
hygiene_spec = importlib.util.spec_from_file_location("check_player_bundle_hygiene", HYGIENE_SCRIPT_PATH)
player_hygiene = importlib.util.module_from_spec(hygiene_spec)
assert hygiene_spec.loader is not None
hygiene_spec.loader.exec_module(player_hygiene)


class PlayerBundleBuildTest(unittest.TestCase):
    def test_player_candidate_contains_required_service_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "player"
            allowlist = Path(tmp) / "player.hygiene-allowlist.json"

            result = build_player_candidate_for_test(candidate, allowlist)

            files = set(result["files"])
            self.assertEqual(result["status"], "pass")
            self.assertIn("README.md", files)
            self.assertIn("TROUBLESHOOTING.md", files)
            self.assertIn("PACKAGING_STATUS.json", files)
            self.assertIn("Dockerfile", files)
            self.assertIn("bin/aml-api", files)
            self.assertIn("bin/aml-worker", files)
            self.assertIn("bin/aml-migrate", files)
            self.assertIn("migrations/000009_create_network_rooms.sql", files)
            self.assertIn("config/player.env.example", files)
            self.assertIn("deploy/compose.yaml", files)
            self.assertNotIn("go.mod", files)
            self.assertNotIn("go.sum", files)
            self.assertFalse(any(path.startswith(("cmd/", "internal/", "vendor/")) for path in files))
            self.assertTrue(allowlist.exists())
            self.assertEqual(json.loads(allowlist.read_text(encoding="utf-8")), {"allow": []})

    def test_player_compose_exposes_only_http_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "player"
            build_player_candidate_for_test(candidate, Path(tmp) / "allow.json")

            compose = (candidate / "deploy" / "compose.yaml").read_text(encoding="utf-8")
            env_template = (candidate / "config" / "player.env.example").read_text(encoding="utf-8")

        self.assertIn("gateway:", compose)
        self.assertIn('${SENTINEL_AML_HTTP_PORT:-80}:80', compose)
        self.assertIn("sentinel_aml_pgdata:/var/lib/postgresql/data", compose)
        self.assertNotIn("SENTINEL_AML_POSTGRES_PORT", compose)
        self.assertNotIn("SENTINEL_AML_API_PORT", compose)
        self.assertNotIn("5432\"", compose)
        self.assertNotIn("8080:8080", compose)
        self.assertEqual(
            env_template,
            "DATABASE_URL=postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable\n"
            "SENTINEL_AML_HTTP_PORT=80\n",
        )

    def test_player_package_metadata_is_operational_and_neutral(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "player"
            build_player_candidate_for_test(candidate, Path(tmp) / "allow.json")

            status = json.loads((candidate / "PACKAGING_STATUS.json").read_text(encoding="utf-8"))

        self.assertEqual(status["artifact_class"], "player-service")
        self.assertEqual(status["package_role"], "team-runtime")
        self.assertEqual(status["delivery_mode"], "binary-image")
        self.assertEqual(status["artifact_contract"], "player-service-with-ui.v1")
        for removed_key in ("candidate_state", "final_package", "binary_runtime_ready", "promotion_blocker"):
            self.assertNotIn(removed_key, status)
        self.assertEqual(status["runtime_validation"]["status"], "external-required")
        self.assertIn("PostgreSQL", status["runtime_requirements"]["database"])
        self.assertIs(status["participant_ui"]["included"], True)
        self.assertIs(status["participant_ui"]["required"], True)
        self.assertEqual(
            {component["key"]: component["included"] for component in status["delivered_components"]},
            {"backend-runtime": True, "participant-ui": True},
        )
        self.assertEqual(status["binaries"]["targets"], ["bin/aml-api", "bin/aml-worker", "bin/aml-migrate"])

    def test_player_candidate_excludes_organizer_only_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = build_player_candidate_for_test(Path(tmp) / "player", Path(tmp) / "allow.json")

            files = set(result["files"])

        forbidden_prefixes = ("checkers/", "sploits/", "fixes/", "tests/", "scripts/", "docs/")
        for path in files:
            self.assertFalse(path.endswith("_test.go"), path)
            for prefix in forbidden_prefixes:
                self.assertFalse(path.startswith(prefix), path)

    def test_player_candidate_excludes_build_profile_vocabulary_from_readable_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "player"
            result = build_player_candidate_for_test(candidate, Path(tmp) / "allow.json")

            text_files = [candidate / path for path in result["files"] if not path.startswith("bin/")]
            combined = "\n".join(path.read_text(encoding="utf-8") for path in text_files)

        for token in (
            "aml1_vulnerable",
            "aml2_vulnerable",
            "aml3_vulnerable",
            "aml4_vulnerable",
            "aml5_vulnerable",
            "case_match_preview",
            "audit_detail_view",
            "entity_review_summary",
            "linked_case_export_detail",
            "network_room_detail",
            "COMPETITION_TAGS",
            "//go:build",
            "staged",
            "promotion_blocker",
            "frontend/dist",
            "--no-frontend-ui",
        ):
            self.assertNotIn(token, combined)

    def test_player_candidate_does_not_ship_source_variant_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "player"
            result = build_player_candidate_for_test(candidate, Path(tmp) / "allow.json")

            for path in result["files"]:
                self.assertFalse(path.endswith(".go"), path)
                self.assertNotIn("_profile_", path)
                self.assertFalse(path.endswith("_profile.go"), path)
                self.assertFalse(path.startswith(("cmd/", "internal/", "vendor/")), path)
                self.assertFalse(path.endswith("_default.go"), path)
                self.assertFalse(path.endswith("_detail.go"), path)
                self.assertNotIn("case_match", path)
                self.assertNotIn("linked_case_export", path)

            text_files = [candidate / path for path in result["files"] if not path.startswith("bin/")]
            combined = "\n".join(path.read_text(encoding="utf-8") for path in text_files)
            for token in (
                "ProfileEnabled",
                "ForProfile",
                "ExportProfileData",
                "ExportProfileMaps",
                "LinkedCaseProfileData",
            ):
                self.assertNotIn(token, combined)

    def test_player_candidate_passes_hygiene_with_generated_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "player"
            allowlist = Path(tmp) / "player.hygiene-allowlist.json"
            build_player_candidate_for_test(candidate, allowlist)

            result = player_hygiene.validate_player_bundle(candidate, allowlist)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_player_candidate_fails_final_runtime_readiness_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "player"
            allowlist = Path(tmp) / "player.hygiene-allowlist.json"
            build_player_candidate_for_test(candidate, allowlist)

            result = player_hygiene.validate_player_bundle(candidate, allowlist, require_runtime_ready=True)

        self.assertEqual(result["status"], "fail")
        self.assertIn("runtime readiness has not been proven", result["checks"][-1]["message"])

    def test_player_candidate_hygiene_fails_on_planted_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "player"
            allowlist = Path(tmp) / "player.hygiene-allowlist.json"
            build_player_candidate_for_test(candidate, allowlist)
            leak = candidate / "checkers" / "sentinel_aml" / "checker.py"
            leak.parent.mkdir(parents=True)
            leak.write_text("checker_secret and public_attack_data\n", encoding="utf-8")

            result = player_hygiene.validate_player_bundle(candidate, allowlist)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("forbidden player bundle path prefix checkers/", message)
        self.assertIn("checker_secret", message)
        self.assertIn("public_attack_data", message)

    def test_admin_candidate_contains_only_checker_package_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = build_admin_bundle.build_admin_candidate(Path(tmp) / "admin")

            files = set(result["files"])

        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            files,
            {
                "README.md",
                "PACKAGING_STATUS.json",
                "config.yml",
                "config/operator.env.example",
                "sentinel_aml/checker.py",
                "sentinel_aml/checker_lib.py",
                "sentinel_aml/requirements.txt",
            },
        )

    def test_candidate_builders_reject_repo_root_and_nonignored_repo_dirs(self):
        with self.assertRaises(ValueError):
            build_player_bundle.build_player_candidate(ROOT, ROOT / "tmp" / "unused.allowlist.json")
        with self.assertRaises(ValueError):
            build_admin_bundle.build_admin_candidate(ROOT)
        with self.assertRaises(ValueError):
            build_player_bundle.build_player_candidate(ROOT / "player-candidate", ROOT / "tmp" / "unused.allowlist.json")
        with self.assertRaises(ValueError):
            build_admin_bundle.build_admin_candidate(ROOT / "admin-candidate")

    def test_repo_local_tmp_outputs_are_allowed_and_replace_existing_tree(self):
        output = ROOT / "tmp" / "test-player-candidate-build"
        allowlist = ROOT / "tmp" / "test-player-candidate-build.allowlist.json"
        try:
            output.mkdir(parents=True, exist_ok=True)
            (output / "stale.txt").write_text("stale\n", encoding="utf-8")

            result = build_player_candidate_for_test(output, allowlist)

            self.assertEqual(result["status"], "pass")
            self.assertFalse((output / "stale.txt").exists())
            self.assertTrue((output / "bin" / "aml-api").exists())
            self.assertTrue((output / "ui" / "index.html").exists())
            self.assertTrue(allowlist.exists())
        finally:
            if output.exists():
                shutil.rmtree(output)
            if allowlist.exists():
                allowlist.unlink()

    def test_makefile_candidate_targets_exist_and_do_not_build_release_archives(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        for target in ("player-candidate", "admin-candidate", "bundle-candidates", "player-hygiene-gate", "admin-hygiene-gate"):
            self.assertRegex(makefile, rf"(?m)^{target}:")

        relevant = makefile.split("player-candidate:", 1)[1]
        relevant = relevant.split("wave30-gate:", 1)[0]
        self.assertIn("scripts/build_player_bundle.py", relevant)
        self.assertIn("scripts/build_admin_bundle.py", relevant)
        self.assertIn("scripts/check_player_bundle_hygiene.py", relevant)
        self.assertNotIn("release-archive", relevant)
        self.assertNotIn("build_release_archive.py", relevant)


def build_player_candidate_for_test(candidate: Path, allowlist: Path):
    frontend_dist = candidate.parent / "frontend-dist"
    write_frontend_dist_fixture(frontend_dist)
    return build_player_bundle.build_player_candidate(candidate, allowlist, frontend_dist)


def write_frontend_dist_fixture(frontend_dist: Path) -> None:
    frontend_dist.mkdir(parents=True, exist_ok=True)
    (frontend_dist / "assets").mkdir(exist_ok=True)
    (frontend_dist / "index.html").write_text("<!doctype html><div id=\"root\"></div><script src=\"/assets/app.js\"></script>\n", encoding="utf-8")
    (frontend_dist / "runtime-config.js").write_text("window.__SENTINEL_AML_CONFIG__ = { apiBaseUrl: '' };\n", encoding="utf-8")
    (frontend_dist / "assets" / "app.js").write_text("console.log('sentinel aml player ui');\n", encoding="utf-8")
    (frontend_dist / "assets" / "app.css").write_text("body{font-family:sans-serif}\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
