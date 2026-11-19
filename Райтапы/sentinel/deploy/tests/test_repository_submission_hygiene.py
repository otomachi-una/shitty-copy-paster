import importlib.util
import io
import json
import hashlib
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_repository_submission_hygiene.py"
BUILD_SCRIPT_PATH = ROOT / "scripts" / "build_repository_submission_archive.py"

spec = importlib.util.spec_from_file_location("check_repository_submission_hygiene", SCRIPT_PATH)
submission_hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(submission_hygiene)

build_spec = importlib.util.spec_from_file_location("build_repository_submission_archive", BUILD_SCRIPT_PATH)
submission_builder = importlib.util.module_from_spec(build_spec)
assert build_spec.loader is not None
build_spec.loader.exec_module(submission_builder)


class RepositorySubmissionHygieneTest(unittest.TestCase):
    def test_submission_archive_fails_on_pycache_and_pyc(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "repo.tar.gz"
            write_tar(
                archive_path,
                {
                    "README.md": "ok\n",
                    "checkers/sentinel_aml/__pycache__/checker.cpython-312.pyc": "cache",
                    "scripts/checker_gate.pyc": "cache",
                },
            )

            result = submission_hygiene.validate_repository_submission(archive_path)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn("__pycache__", message)
        self.assertIn("checker_gate.pyc", message)

    def test_submission_archive_fails_on_go_and_app_cache_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "repo.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(".gocache-build/cache.bin", "cache")
                archive.writestr(".appdata-review/state.json", "{}")

            result = submission_hygiene.validate_repository_submission(archive_path)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn(".gocache-build", message)
        self.assertIn(".appdata-review", message)

    def test_submission_archive_fails_on_generated_tmp_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "repo.tar.gz"
            write_tar(
                archive_path,
                {
                    "tmp/wave33-player-service-candidate/README.md": "candidate\n",
                    "tmp/wave33-admin-checker-candidate/README.md": "candidate\n",
                },
            )

            result = submission_hygiene.validate_repository_submission(archive_path)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn("tmp/wave33-player-service-candidate/README.md", message)
        self.assertIn("tmp/wave33-admin-checker-candidate/README.md", message)

    def test_submission_archive_fails_on_frontend_install_and_dist_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "repo.tar.gz"
            write_tar(
                archive_path,
                {
                    "sentinel-aml/README.md": "ok\n",
                    "sentinel-aml/frontend/node_modules/pkg/index.js": "generated\n",
                    "sentinel-aml/frontend/dist/index.html": "generated\n",
                },
            )

            result = submission_hygiene.validate_repository_submission(archive_path)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn("frontend/node_modules/pkg/index.js", message)
        self.assertIn("frontend/dist/index.html", message)

    def test_submission_archive_fails_on_tsbuildinfo_browser_and_test_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "repo.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("Sentinel_AML/frontend/tsconfig.app.tsbuildinfo", "generated")
                archive.writestr("Sentinel_AML/frontend/.vite/deps.json", "{}")
                archive.writestr("Sentinel_AML/frontend/test-results/results.json", "{}")
                archive.writestr("Sentinel_AML/tmp/visual-qa/edge-profile/Default/Preferences", "{}")
                archive.writestr("Sentinel_AML/frontend/playwright-report/index.html", "generated")
                archive.writestr("Sentinel_AML/screenshots/home.png", "generated")
                archive.writestr("Sentinel_AML/chrome-profile/Default/Preferences", "{}")

            result = submission_hygiene.validate_repository_submission(archive_path)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn(".tsbuildinfo", message)
        self.assertIn(".vite", message)
        self.assertIn("test-results", message)
        self.assertIn("edge-profile", message)
        self.assertIn("playwright-report", message)
        self.assertIn("screenshots", message)
        self.assertIn("chrome-profile", message)

    def test_submission_archive_fails_on_validation_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "repo.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("Sentinel_AML/README.md", "ok\n")
                archive.writestr("Sentinel_AML/validation/review.json", "{}\n")
                archive.writestr("Sentinel_AML/.env", "DATABASE_URL=postgres://local\n")
                archive.writestr("Sentinel_AML/.env.local", "LOCAL_ONLY=1\n")

            result = submission_hygiene.validate_repository_submission(archive_path)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn("validation", message)
        self.assertIn(".env", message)
        self.assertIn(".env.local", message)

    def test_submission_archive_fails_on_nested_transfer_archives_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "repo.tar.gz"
            write_tar(
                archive_path,
                {
                    "README.md": "ok\n",
                    "release/sentinel-aml-player-service.tar.gz": "nested archive\n",
                    "docs/evidence.zip": "nested archive\n",
                },
            )

            result = submission_hygiene.validate_repository_submission(archive_path)
            allowed = submission_hygiene.validate_repository_submission(
                archive_path,
                allow_nested_archives=True,
            )

        self.assertEqual(result["status"], "fail")
        self.assertIn("nested generated transfer archive", result["checks"][0]["message"])
        self.assertEqual(allowed["status"], "pass", allowed["checks"][0]["message"])

    def test_local_wave33_candidates_are_allowed_only_with_explicit_staging_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in (
                "tmp/wave33-player-service-candidate/README.md",
                "tmp/wave33-admin-checker-candidate/README.md",
                "tmp/wave33-player-service-candidate.hygiene-allowlist.json",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("staged candidate\n", encoding="utf-8")

            strict = submission_hygiene.validate_repository_submission(root)
            staged = submission_hygiene.validate_repository_submission(
                root,
                allow_wave33_local_candidates=True,
            )

        self.assertEqual(strict["status"], "fail")
        self.assertEqual(staged["status"], "pass", staged["checks"][0]["message"])

    def test_local_staging_flag_does_not_allow_candidate_paths_in_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "repo.tar.gz"
            write_tar(archive_path, {"tmp/wave33-player-service-candidate/README.md": "candidate\n"})

            result = submission_hygiene.validate_repository_submission(
                archive_path,
                allow_wave33_local_candidates=True,
            )

        self.assertEqual(result["status"], "fail")
        self.assertIn("generated candidate", result["checks"][0]["message"])

    def test_clean_submission_tree_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("ok\n", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs" / "source_of_truth_map.md").write_text("ok\n", encoding="utf-8")

            result = submission_hygiene.validate_repository_submission(root)

        self.assertEqual(result["status"], "pass", result["checks"][0]["message"])

    def test_clean_generated_removes_known_outputs_only_under_repo_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generated_paths = (
                "tmp/stale.txt",
                "out/artifacts/stale.tar.gz",
                "frontend/dist/index.html",
                "frontend/tsconfig.app.tsbuildinfo",
                ".gocache-test/cache.bin",
            )
            for relative in generated_paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("generated\n", encoding="utf-8")
            source = root / "checkers" / "sentinel_aml" / "checker.py"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("keep\n", encoding="utf-8")

            result = submission_hygiene.clean_generated(root)

            self.assertEqual(result["status"], "pass")
            for relative in generated_paths:
                self.assertFalse((root / relative).exists(), relative)
            self.assertTrue(source.exists())

    def test_clean_generated_can_preserve_frontend_ui_build_for_artifact_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generated_paths = (
                "tmp/stale.txt",
                "out/artifacts/stale.tar.gz",
                "frontend/dist/index.html",
                "frontend/node_modules/pkg/index.js",
                "frontend/tsconfig.app.tsbuildinfo",
            )
            for relative in generated_paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("generated\n", encoding="utf-8")

            result = submission_hygiene.clean_generated_paths(root, preserve_frontend_ui_build=True)

            self.assertEqual(result["status"], "pass")
            self.assertFalse((root / "tmp" / "stale.txt").exists())
            self.assertFalse((root / "out" / "artifacts" / "stale.tar.gz").exists())
            self.assertTrue((root / "frontend" / "dist" / "index.html").exists())
            self.assertTrue((root / "frontend" / "node_modules" / "pkg" / "index.js").exists())
            self.assertTrue((root / "frontend" / "tsconfig.app.tsbuildinfo").exists())

    def test_create_repository_submission_archive_excludes_generated_outputs_and_references_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            for relative, content in {
                "README.md": "ok\n",
                "docs/source_of_truth_map.md": "ok\n",
                "frontend/package.json": "{}\n",
                "frontend/src/app.tsx": "export {}\n",
                ".dockerignore": "out/\n",
                "out/artifacts/sentinel-aml-player-source.tar.gz": "transfer artifact\n",
                "out/artifacts/sentinel-aml-admin-organizer.tar.gz": "transfer artifact\n",
                "out/artifacts/SHA256SUMS": (
                    "a" * 64 + "  artifacts/sentinel-aml-admin-organizer.tar.gz\n"
                    + "b" * 64 + "  sentinel-aml-player-source.tar.gz\n"
                ),
                "frontend/dist/index.html": "generated\n",
                "frontend/.vite/deps.json": "{}\n",
                "frontend/node_modules/pkg/index.js": "generated\n",
                "frontend/tsconfig.app.tsbuildinfo": "generated\n",
                "tmp/stale.txt": "generated\n",
                "screenshots/home.png": "generated\n",
                "__pycache__/stale.pyc": "generated\n",
                "validation/review.json": "{}\n",
                "local-notes.txt": "local scratch\n",
                ".agents/skills/private.md": "local agent config\n",
            }.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            output = root / "out" / "repository-submission" / "sentinel-aml-repository-submission.zip"
            fixture_artifact_sha = hashlib.sha256((root / "out" / "artifacts" / "sentinel-aml-player-source.tar.gz").read_bytes()).hexdigest()

            result = submission_hygiene.create_repository_submission_archive(root, output)
            validation = submission_hygiene.validate_repository_submission(output)

            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
                reference = json.loads(
                    archive.read(
                        "sentinel-aml-repository-submission/REPOSITORY_SUBMISSION_ARTIFACTS.json"
                    ).decode("utf-8")
                )

        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(validation["status"], "pass", validation["checks"][0]["message"])
        self.assertIn("sentinel-aml-repository-submission/README.md", names)
        self.assertIn("sentinel-aml-repository-submission/.dockerignore", names)
        self.assertIn("sentinel-aml-repository-submission/frontend/src/app.tsx", names)
        self.assertIn("sentinel-aml-repository-submission/README_REPOSITORY_SUBMISSION.md", names)
        self.assertNotIn("sentinel-aml-repository-submission/frontend/dist/index.html", names)
        self.assertNotIn("sentinel-aml-repository-submission/frontend/.vite/deps.json", names)
        self.assertNotIn("sentinel-aml-repository-submission/frontend/node_modules/pkg/index.js", names)
        self.assertNotIn("sentinel-aml-repository-submission/out/artifacts/sentinel-aml-player-source.tar.gz", names)
        self.assertNotIn("sentinel-aml-repository-submission/screenshots/home.png", names)
        self.assertNotIn("sentinel-aml-repository-submission/validation/review.json", names)
        self.assertNotIn("sentinel-aml-repository-submission/local-notes.txt", names)
        self.assertNotIn("sentinel-aml-repository-submission/.agents/skills/private.md", names)
        self.assertFalse(any(name.endswith(".tsbuildinfo") for name in names))
        self.assertFalse(any("/tmp/" in name for name in names))
        self.assertFalse(any("__pycache__" in name for name in names))
        self.assertFalse(any(name.endswith(".tar.gz") for name in names))
        self.assertEqual(reference["transfer_artifacts_nested"], False)
        self.assertEqual(reference["archive_role"], "internal-repository-submission")
        self.assertEqual(reference["player_facing"], False)
        self.assertEqual(reference["repository_submission_not_player_artifact"], True)
        self.assertEqual(reference["player_source_artifact"], "out/artifacts/sentinel-aml-player-source.tar.gz")
        self.assertEqual(reference["admin_organizer_artifact"], "out/artifacts/sentinel-aml-admin-organizer.tar.gz")
        self.assertEqual(
            reference["artifacts"],
            [
                {"path": "out/artifacts/sentinel-aml-admin-organizer.tar.gz", "sha256": fixture_artifact_sha},
                {"path": "out/artifacts/sentinel-aml-player-source.tar.gz", "sha256": fixture_artifact_sha},
            ],
        )

    def test_makefile_clean_generated_target_exists(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertRegex(makefile, r"(?m)^clean-generated:")
        target = makefile.split("clean-generated:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("scripts/check_repository_submission_hygiene.py --clean-generated .", target)
        self.assertRegex(makefile, r"(?m)^repository-submission-hygiene:")
        submission_target = makefile.split("repository-submission-hygiene:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("test_repository_submission_hygiene.py", submission_target)
        self.assertIn("REPOSITORY_SUBMISSION", submission_target)
        self.assertIn("scripts/check_repository_submission_hygiene.py", submission_target)
        self.assertRegex(makefile, r"(?m)^repository-submission-archive:")
        archive_target = makefile.split("repository-submission-archive:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("scripts/build_repository_submission_archive.py", archive_target)
        self.assertIn("scripts/check_repository_submission_hygiene.py \"$", archive_target)

    def test_requested_archive_builder_entrypoint_exists(self):
        self.assertTrue(hasattr(submission_builder, "main"))
        self.assertTrue(BUILD_SCRIPT_PATH.is_file())


def write_tar(path: Path, members: dict[str, str]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in sorted(members.items()):
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, fileobj=io.BytesIO(data))


if __name__ == "__main__":
    unittest.main()
