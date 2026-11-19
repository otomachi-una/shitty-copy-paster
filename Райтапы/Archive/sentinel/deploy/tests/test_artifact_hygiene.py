import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SCRIPT_PATH = ROOT / "scripts" / "check_artifact_hygiene.py"
spec = importlib.util.spec_from_file_location("check_artifact_hygiene", SCRIPT_PATH)
artifact_hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(artifact_hygiene)

PLAYER_SCRIPT_PATH = ROOT / "scripts" / "check_player_bundle_hygiene.py"
player_spec = importlib.util.spec_from_file_location("check_player_bundle_hygiene", PLAYER_SCRIPT_PATH)
player_hygiene = importlib.util.module_from_spec(player_spec)
assert player_spec.loader is not None
player_spec.loader.exec_module(player_hygiene)

ADMIN_SCRIPT_PATH = ROOT / "scripts" / "check_admin_bundle_hygiene.py"
admin_spec = importlib.util.spec_from_file_location("check_admin_bundle_hygiene", ADMIN_SCRIPT_PATH)
admin_hygiene = importlib.util.module_from_spec(admin_spec)
assert admin_spec.loader is not None
admin_spec.loader.exec_module(admin_hygiene)


class ArtifactHygieneTest(unittest.TestCase):
    def test_clean_player_artifact_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = make_player_archive(Path(tmp) / "player.tar.gz")

            result = player_hygiene.validate_player_bundle(archive)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_player_artifact_with_checker_sploit_or_fix_fails(self):
        for relative in (
            "checkers/sentinel_aml/checker.py",
            "sploits/sentinel_aml/tool.py",
            "fixes/sentinel_aml/fix.patch",
        ):
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as tmp:
                    archive = make_player_archive(Path(tmp) / "player.tar.gz", {relative: "placeholder\n"})

                    result = player_hygiene.validate_player_bundle(archive)

                self.assertEqual(result["status"], "fail")
                self.assertIn(relative.split("/", 1)[0], result["checks"][1]["message"])

    def test_player_artifact_with_source_map_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = make_player_archive(Path(tmp) / "player.tar.gz", {"ui/assets/app.js.map": "{}\n"})

            result = player_hygiene.validate_player_bundle(archive)

        self.assertEqual(result["status"], "fail")
        self.assertIn(".map", result["checks"][1]["message"])

    def test_player_artifact_with_forbidden_token_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = make_player_archive(Path(tmp) / "player.tar.gz", {"README.md": "AML-1 vulnerable profile\n"})

            result = player_hygiene.validate_player_bundle(archive)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("AML-1", message)
        self.assertIn("vulnerable", message)

    def test_admin_artifact_missing_checker_fixes_or_sploits_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = make_tar(
                Path(tmp) / "admin.tar.gz",
                "sentinel-aml-admin-organizer",
                {
                    "Makefile": "artifact-gate:\n",
                    "config.yml": "service_name: sentinel_aml\n",
                    "checkers/sentinel_aml/checker.py": "print('checker')\n",
                    "checkers/sentinel_aml/checker_lib.py": "\n",
                    "checkers/sentinel_aml/requirements.txt": "\n",
                },
            )

            result = admin_hygiene.validate_admin_bundle(archive)

        self.assertEqual(result["status"], "fail")
        self.assertIn("missing=", result["checks"][1]["message"])
        self.assertIn("fixes/sentinel_aml", result["checks"][1]["message"])
        self.assertIn("sploits/sentinel_aml", result["checks"][1]["message"])

    def test_local_generated_cache_artifacts_fail_for_player_and_admin(self):
        bad_paths = (
            "node_modules/pkg/index.js",
            "__pycache__/tool.cpython-311.pyc",
            "frontend/tsconfig.tsbuildinfo",
            "tmp/stale.txt",
            "validation/exact-artifact-live/summary.json",
            ".gocache/ab/cache-entry",
        )
        for relative in bad_paths:
            with self.subTest(relative=relative, artifact="player"):
                with tempfile.TemporaryDirectory() as tmp:
                    archive = make_player_archive(Path(tmp) / "player.tar.gz", {relative: "generated\n"})

                    result = player_hygiene.validate_player_bundle(archive)

                self.assertEqual(result["status"], "fail")
                self.assertIn("local/generated/cache artifact", result["checks"][1]["message"])

            with self.subTest(relative=relative, artifact="admin"):
                with tempfile.TemporaryDirectory() as tmp:
                    archive = make_admin_archive(Path(tmp) / "admin.tar.gz", {relative: "generated\n"})

                    result = admin_hygiene.validate_admin_bundle(archive)

                self.assertEqual(result["status"], "fail")
                self.assertIn("forbidden", result["checks"][2]["message"])

    def test_combined_artifact_hygiene_runner_scans_explicit_archive_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            player = make_player_archive(root / "player.tar.gz")
            admin = make_admin_archive(root / "admin.tar.gz")

            result = artifact_hygiene.validate_artifact_hygiene(player, admin)

        self.assertEqual(result["status"], "pass", result["checks"])


def make_player_archive(path: Path, extra_files: dict[str, str] | None = None) -> Path:
    files = {
        "README.md": "Sentinel service runtime package\n",
        "PACKAGING_STATUS.json": json.dumps(
            {
                "artifact_class": "player-service",
                "artifact_contract": "player-service-with-ui.v1",
                "delivery_mode": "binary-image",
                "participant_ui": {"included": True, "required": True, "delivery_path": "ui/"},
                "delivered_components": [
                    {"key": "backend-runtime", "included": True, "required": True, "delivery_path": "bin/"},
                    {"key": "participant-ui", "included": True, "required": True, "delivery_path": "ui/"},
                ],
            }
        ),
        "Dockerfile": "FROM alpine:3.20\n",
        "deploy/compose.yaml": "services:\n  api:\n    build:\n      context: ..\n",
        "bin/aml-api": "binary\n",
        "bin/aml-worker": "binary\n",
        "bin/aml-migrate": "binary\n",
        "ui/index.html": "<!doctype html><div id=\"root\"></div>\n",
        "ui/runtime-config.js": "window.__SENTINEL_AML_CONFIG__ = { apiBaseUrl: '' };\n",
        "ui/assets/app.js": "console.log('sentinel aml');\n",
        "migrations/000001_create_users_sessions.sql": "select 1;\n",
    }
    files.update(extra_files or {})
    return make_tar(path, "sentinel-aml-player-service", files)


def make_admin_archive(path: Path, extra_files: dict[str, str] | None = None) -> Path:
    files = {
        "Makefile": "artifact-gate:\n",
        "config.yml": "service_name: sentinel_aml\n",
        "checkers/sentinel_aml/checker.py": "print('checker')\n",
        "checkers/sentinel_aml/checker_lib.py": "\n",
        "checkers/sentinel_aml/requirements.txt": "\n",
        "sploits/sentinel_aml/aml_dedup_preview.py": "\n",
        "sploits/sentinel_aml/aml_audit_timeline.py": "\n",
        "sploits/sentinel_aml/aml_related_graph.py": "\n",
        "sploits/sentinel_aml/aml_export_redaction.py": "\n",
        "sploits/sentinel_aml/aml_network_room.py": "\n",
        "fixes/sentinel_aml/aml_dedup_preview.patch": "\n",
        "fixes/sentinel_aml/aml_audit_timeline.patch": "\n",
        "fixes/sentinel_aml/aml_related_graph.patch": "\n",
        "fixes/sentinel_aml/aml_export_redaction.patch": "\n",
        "fixes/sentinel_aml/aml_network_room.patch": "\n",
        "tests/test_checker_check_workflow.py": "\n",
        "tests/test_checker_put_workflow.py": "\n",
        "docs/wave_reports/wave_32_sploit_fix_matrix.md": "\n",
    }
    files.update(extra_files or {})
    return make_tar(path, "sentinel-aml-admin-organizer", files)


def make_tar(path: Path, archive_root: str, files: dict[str, str]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for relative, content in sorted(files.items()):
            data = content.encode("utf-8")
            info = tarfile.TarInfo(f"{archive_root}/{relative}")
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return path


if __name__ == "__main__":
    unittest.main()
