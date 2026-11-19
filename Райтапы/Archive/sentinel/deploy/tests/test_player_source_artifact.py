from __future__ import annotations

import gzip
import importlib.util
import io
import os
import subprocess
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


builder = load_script("build_player_source_artifact", ROOT / "scripts" / "build_player_source_artifact.py")
manifest_checker = load_script("check_artifact_manifests", ROOT / "scripts" / "check_artifact_manifests.py")


class PlayerSourceArtifactTest(unittest.TestCase):
    def build_artifact(self, directory: Path) -> Path:
        artifact = directory / "sentinel-aml-player-source.tar.gz"
        result = builder.build_player_source_artifact(artifact)
        self.assertEqual(result["status"], "pass", result)
        return artifact

    def archive_members(self, artifact: Path) -> list[str]:
        with gzip.open(artifact, "rb") as raw:
            payload = io.BytesIO(raw.read())
        with tarfile.open(fileobj=payload, mode="r:") as archive:
            return sorted(member.name for member in archive.getmembers() if member.isfile())

    def test_builder_is_deterministic_and_writes_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = self.build_artifact(root / "a")
            second = self.build_artifact(root / "b")

            self.assertEqual(builder.sha256_file(first), builder.sha256_file(second))
            self.assertTrue((first.parent / builder.MANIFEST_NAME).is_file())
            self.assertTrue((first.parent / builder.CHECKSUM_NAME).is_file())
            self.assertEqual(manifest_checker.check_manifest(first)["status"], "pass")

    def test_required_source_tree_is_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self.build_artifact(Path(tmp))
            names = set(self.archive_members(artifact))

        required = {
            "sentinel-aml-player-source/README.md",
            "sentinel-aml-player-source/TROUBLESHOOTING.md",
            "sentinel-aml-player-source/Makefile",
            "sentinel-aml-player-source/Dockerfile",
            "sentinel-aml-player-source/docker-compose.yml",
            "sentinel-aml-player-source/deploy/player.env.example",
            "sentinel-aml-player-source/go.mod",
            "sentinel-aml-player-source/go.sum",
            "sentinel-aml-player-source/cmd/aml-api/main.go",
            "sentinel-aml-player-source/cmd/aml-worker/main.go",
            "sentinel-aml-player-source/cmd/aml-migrate/main.go",
            "sentinel-aml-player-source/internal/httpapi/server.go",
            "sentinel-aml-player-source/migrations/000001_create_users_sessions.sql",
            "sentinel-aml-player-source/web/dist/index.html",
            "sentinel-aml-player-source/web/dist/runtime-config.js",
        }
        self.assertTrue(required <= names, sorted(required - names))
        for dirname in ("vendor/", "cmd/", "internal/", "migrations/", "web/dist/"):
            self.assertTrue(any(name.startswith(f"sentinel-aml-player-source/{dirname}") for name in names), dirname)
        forbidden = {
            "sentinel-aml-player-source/frontend/package.json",
            "sentinel-aml-player-source/frontend/package-lock.json",
            "sentinel-aml-player-source/frontend/src/main.tsx",
        }
        self.assertFalse(forbidden & names, sorted(forbidden & names))

    def test_extracted_source_builds_with_vendored_go_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self.build_artifact(root)
            with gzip.open(artifact, "rb") as raw:
                payload = io.BytesIO(raw.read())
            with tarfile.open(fileobj=payload, mode="r:") as archive:
                archive.extractall(root / "extract")
            source_root = root / "extract" / "sentinel-aml-player-source"
            env = os.environ.copy()
            env.update(
                {
                    "GOTOOLCHAIN": "local",
                    "GOFLAGS": "-mod=vendor",
                    "GOTELEMETRY": "off",
                    "GOCACHE": str(root / "gocache"),
                    "APPDATA": str(root / "appdata"),
                }
            )

            completed = subprocess.run(
                ["go", "test", "./..."],
                cwd=source_root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
