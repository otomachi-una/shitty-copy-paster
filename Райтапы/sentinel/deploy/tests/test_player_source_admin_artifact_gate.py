from __future__ import annotations

import gzip
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


player_builder = load_script("build_player_source_artifact", ROOT / "scripts" / "build_player_source_artifact.py")
admin_builder = load_script("build_admin_organizer_artifact", ROOT / "scripts" / "build_admin_organizer_artifact.py")
acceptance = load_script("check_artifact_first_live_acceptance", ROOT / "scripts" / "check_artifact_first_live_acceptance.py")
matrix = load_script("check_exact_artifact_checker_sploit_fix_matrix", ROOT / "scripts" / "check_exact_artifact_checker_sploit_fix_matrix.py")
source_admin_gate = load_script("check_player_source_admin_artifact_gate", ROOT / "scripts" / "check_player_source_admin_artifact_gate.py")


class PlayerSourceAdminArtifactGateTest(unittest.TestCase):
    def build_pair(self, root: Path) -> tuple[Path, Path]:
        artifact_dir = root / "artifacts"
        player = artifact_dir / "sentinel-aml-player-source.tar.gz"
        admin = artifact_dir / "sentinel-aml-admin-organizer.tar.gz"
        player_result = player_builder.build_player_source_artifact(player)
        admin_result = admin_builder.build_admin_organizer_artifact(admin)
        self.assertEqual(player_result["status"], "pass", player_result)
        self.assertEqual(admin_result["status"], "pass", admin_result)
        return player, admin

    def test_refuses_repo_path_as_player_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary.json"
            result = acceptance.check_artifact_first_live_acceptance(
                player_artifact=ROOT,
                admin_artifact=ROOT,
                summary_output=summary,
                validation_root=Path(tmp) / "work",
                run_live=False,
            )

        self.assertEqual(result["status"], "fail")
        self.assertIn("not a directory", result["error"])

    def test_fails_if_artifact_sha_changes_after_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            player, admin = self.build_pair(root)
            with player.open("ab") as handle:
                handle.write(b"\nchanged-after-manifest\n")
            summary = root / "summary.json"

            result = acceptance.check_artifact_first_live_acceptance(
                player_artifact=player,
                admin_artifact=admin,
                summary_output=summary,
                validation_root=root / "work",
                run_live=False,
            )

            written = json.loads(summary.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(written["status"], "fail")
        self.assertIn("SHA changed after manifest", written["error"])

    def test_fails_if_any_sploit_or_fix_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            player_root = root / "sentinel-aml-player-source"
            admin_root = root / "sentinel-aml-admin-organizer"
            for relative in ("Dockerfile", "docker-compose.yml", "Makefile", "cmd/aml-api/main.go", "internal/httpapi/server.go"):
                path = player_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("placeholder\n", encoding="utf-8")
            for relative in ("checkers/sentinel_aml/checker.py", "checkers/sentinel_aml/checker_lib.py", "README_ADMIN.md"):
                path = admin_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("placeholder\n", encoding="utf-8")

            result = matrix.static_preflight(player_root, admin_root)

        self.assertEqual(result["status"], "fail")
        self.assertTrue(any("sploits/sentinel_aml/" in missing for missing in result["missing"]))
        self.assertTrue(any("fixes/sentinel_aml/" in missing for missing in result["missing"]))

    def test_fails_docker_unavailable_without_marking_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            player, admin = self.build_pair(root)
            summary = root / "summary.json"

            result = acceptance.check_artifact_first_live_acceptance(
                player_artifact=player,
                admin_artifact=admin,
                summary_output=summary,
                validation_root=root / "work",
                docker="definitely-not-docker",
                run_live=True,
            )

            written = json.loads(summary.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "external-required", result)
        self.assertNotEqual(result["status"], "pass")
        self.assertIn("external_required", written)
        self.assertFalse(written["runtime"]["docker_available"])

    def test_records_external_required_and_cleans_up_static_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            player, admin = self.build_pair(root)
            work = root / "matrix-work"

            result = matrix.check_exact_artifact_checker_sploit_fix_matrix(
                player,
                admin,
                validation_root=work,
                run_live=False,
            )

        self.assertEqual(result["status"], "external-required", result)
        self.assertIn("external_required", result)
        self.assertEqual(result["cleanup"]["status"], "pass")
        self.assertFalse(work.exists())

    def test_final_promotion_uses_exact_validated_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_dir = root / "out" / "artifacts"
            final_dir = root / "out" / "final" / "artifacts"
            artifact_dir.mkdir(parents=True)
            player = artifact_dir / "sentinel-aml-player-source.tar.gz"
            admin = artifact_dir / "sentinel-aml-admin-organizer.tar.gz"
            player.write_bytes(b"player-bytes\n")
            admin.write_bytes(b"admin-bytes\n")
            player_manifest = artifact_dir / "PLAYER_SOURCE_MANIFEST.json"
            admin_manifest = artifact_dir / "ADMIN_MANIFEST.json"
            player_manifest.write_text(json.dumps({"artifact": {"path": "old-player", "sha256": "old"}}), encoding="utf-8")
            admin_manifest.write_text(json.dumps({"artifact": {"path": "old-admin", "sha256": "old"}}), encoding="utf-8")

            old_values = {
                "FINAL_ROOT": source_admin_gate.FINAL_ROOT,
                "FINAL_ARTIFACT_DIR": source_admin_gate.FINAL_ARTIFACT_DIR,
                "PLAYER_ARTIFACT": source_admin_gate.PLAYER_ARTIFACT,
                "ADMIN_ARTIFACT": source_admin_gate.ADMIN_ARTIFACT,
                "PLAYER_MANIFEST": source_admin_gate.PLAYER_MANIFEST,
                "ADMIN_MANIFEST": source_admin_gate.ADMIN_MANIFEST,
                "FINAL_PLAYER_ARTIFACT": source_admin_gate.FINAL_PLAYER_ARTIFACT,
                "FINAL_ADMIN_ARTIFACT": source_admin_gate.FINAL_ADMIN_ARTIFACT,
                "FINAL_PLAYER_MANIFEST": source_admin_gate.FINAL_PLAYER_MANIFEST,
                "FINAL_ADMIN_MANIFEST": source_admin_gate.FINAL_ADMIN_MANIFEST,
                "FINAL_SHA256SUMS": source_admin_gate.FINAL_SHA256SUMS,
                "FINAL_OUTPUT_FILES": source_admin_gate.FINAL_OUTPUT_FILES,
            }
            try:
                source_admin_gate.FINAL_ROOT = root / "out" / "final"
                source_admin_gate.FINAL_ARTIFACT_DIR = final_dir
                source_admin_gate.PLAYER_ARTIFACT = player
                source_admin_gate.ADMIN_ARTIFACT = admin
                source_admin_gate.PLAYER_MANIFEST = player_manifest
                source_admin_gate.ADMIN_MANIFEST = admin_manifest
                source_admin_gate.FINAL_PLAYER_ARTIFACT = final_dir / player.name
                source_admin_gate.FINAL_ADMIN_ARTIFACT = final_dir / admin.name
                source_admin_gate.FINAL_PLAYER_MANIFEST = final_dir / player_manifest.name
                source_admin_gate.FINAL_ADMIN_MANIFEST = final_dir / admin_manifest.name
                source_admin_gate.FINAL_SHA256SUMS = final_dir / "SHA256SUMS"
                source_admin_gate.FINAL_OUTPUT_FILES = (
                    source_admin_gate.FINAL_PLAYER_ARTIFACT,
                    source_admin_gate.FINAL_ADMIN_ARTIFACT,
                    source_admin_gate.FINAL_PLAYER_MANIFEST,
                    source_admin_gate.FINAL_ADMIN_MANIFEST,
                    source_admin_gate.FINAL_SHA256SUMS,
                )

                promotion = source_admin_gate.promote_final_outputs()
                verification = source_admin_gate.verify_final_outputs()
            finally:
                for name, value in old_values.items():
                    setattr(source_admin_gate, name, value)

            self.assertEqual(promotion["status"], "pass")
            self.assertEqual(verification["status"], "pass", verification)
            self.assertEqual((final_dir / player.name).read_bytes(), b"player-bytes\n")
            self.assertEqual((final_dir / admin.name).read_bytes(), b"admin-bytes\n")
            final_player_manifest = json.loads((final_dir / "PLAYER_SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
            self.assertEqual(final_player_manifest["artifact"]["sha256"], source_admin_gate.sha256_file(final_dir / player.name))
            self.assertIn("PLAYER_SOURCE_MANIFEST.json", (final_dir / "SHA256SUMS").read_text(encoding="utf-8"))

    def test_phase_recorder_honors_timeout(self):
        recorder = matrix.PhaseRecorder()
        with self.assertRaises(matrix.MatrixFailure):
            recorder.run(
                "slow-command",
                [sys.executable, "-c", "import time; time.sleep(2)"],
                cwd=ROOT,
                timeout=0.1,
            )

        self.assertEqual(recorder.phases[-1]["status"], "timeout")


def make_archive(path: Path, root_name: str, files: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for relative, text in sorted(files.items()):
            data = text.encode("utf-8")
            info = tarfile.TarInfo(f"{root_name}/{relative}")
            info.size = len(data)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(payload.getvalue())


if __name__ == "__main__":
    unittest.main()
