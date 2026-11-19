from __future__ import annotations

import gzip
import importlib.util
import io
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
runtime = load_script("check_player_source_runtime", ROOT / "scripts" / "check_player_source_runtime.py")


class PlayerSourceRuntimeTest(unittest.TestCase):
    def build_artifact(self, directory: Path) -> Path:
        artifact = directory / "sentinel-aml-player-source.tar.gz"
        result = builder.build_player_source_artifact(artifact)
        self.assertEqual(result["status"], "pass", result)
        return artifact

    def test_generated_artifact_contains_source_based_compose_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self.build_artifact(Path(tmp))
            files = read_artifact_files(artifact)

        compose = files["sentinel-aml-player-source/docker-compose.yml"]
        dockerfile = files["sentinel-aml-player-source/Dockerfile"]
        for service in ("postgres", "aml-migrate", "aml-api", "aml-worker", "aml-ui"):
            self.assertRegex(compose, rf"(?m)^  {service}:\s*$")
        self.assertIn("target: runtime", compose)
        self.assertIn("target: ui", compose)
        self.assertNotIn("frontend/", compose)
        self.assertNotIn("5432:", compose)
        self.assertNotIn("FROM node:20-alpine AS frontend-build", dockerfile)
        self.assertNotIn("RUN npm run build", dockerfile)
        self.assertIn("COPY web/dist /usr/share/nginx/html", dockerfile)
        self.assertIn("FROM golang:1.22-alpine AS go-build", dockerfile)
        self.assertIn("FROM alpine:3.20 AS runtime", dockerfile)
        self.assertIn("FROM nginx:1.27-alpine AS ui", dockerfile)
        self.assertIn("go build -o /out/aml-api ./cmd/aml-api", dockerfile)
        self.assertNotIn("COPY bin/", dockerfile)

    def test_generated_artifact_makefile_and_docs_are_participant_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self.build_artifact(Path(tmp))
            files = read_artifact_files(artifact)

        makefile = files["sentinel-aml-player-source/Makefile"]
        docs = files["sentinel-aml-player-source/README.md"] + files["sentinel-aml-player-source/TROUBLESHOOTING.md"]
        for target in ("up", "down", "logs", "rebuild", "smoke"):
            self.assertRegex(makefile, rf"(?m)^{target}:\s*$")
        self.assertIn("docker compose up --build", docs)
        self.assertIn("make rebuild", docs)
        self.assertIn("make smoke", docs)
        lowered = (makefile + docs).lower()
        for forbidden in ("checker", "sploit", "exploit", "aml1_vulnerable", "aml2_vulnerable", "aml3_vulnerable", "aml4_vulnerable", "aml5_vulnerable"):
            self.assertNotIn(forbidden, lowered)

    def test_runtime_checker_reports_external_required_when_docker_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self.build_artifact(Path(tmp))
            result = runtime.check_player_source_runtime(artifact, docker="definitely-not-docker", run_live=True)

        self.assertEqual(result["status"], "external-required", result)
        self.assertFalse(result["docker_available"])
        self.assertEqual(result["cleanup"]["status"], "not-run")
        self.assertTrue(any(check["name"] == "docker-live-runtime" and check["status"] == "external-required" for check in result["checks"]))

    def test_runtime_checker_fails_missing_required_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "fixture.tar.gz"
            files = runtime_fixture_files()
            files["sentinel-aml-player-source/docker-compose.yml"] = files["sentinel-aml-player-source/docker-compose.yml"].replace("  aml-worker:\n", "  worker:\n")
            write_tar(artifact, files)
            result = runtime.check_player_source_runtime(artifact, docker="definitely-not-docker", run_live=True)

        self.assertEqual(result["status"], "fail", result)
        self.assertTrue(any(check["name"] == "compose-required-services" and check["status"] == "fail" for check in result["checks"]))


def read_artifact_files(artifact: Path) -> dict[str, str]:
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        result: dict[str, str] = {}
        for member in archive.getmembers():
            if not member.isfile():
                continue
            handle = archive.extractfile(member)
            assert handle is not None
            result[member.name] = handle.read().decode("utf-8", errors="ignore")
        return result


def runtime_fixture_files() -> dict[str, str]:
    return {
        "sentinel-aml-player-source/README.md": "docker compose up --build\nmake rebuild\nmake smoke\n",
        "sentinel-aml-player-source/TROUBLESHOOTING.md": "Use make rebuild before make up.\n",
        "sentinel-aml-player-source/Makefile": "up:\n\ndown:\n\nlogs:\n\nrebuild:\n\nsmoke:\n",
        "sentinel-aml-player-source/deploy/player.env.example": "SENTINEL_AML_API_PORT=8080\nSENTINEL_AML_HTTP_PORT=8081\n",
        "sentinel-aml-player-source/Dockerfile": "\n".join(
            [
                "FROM golang:1.22-alpine AS go-build",
                "RUN go build -o /out/aml-api ./cmd/aml-api",
                "RUN go build -o /out/aml-worker ./cmd/aml-worker",
                "RUN go build -o /out/aml-migrate ./cmd/aml-migrate",
                "FROM alpine:3.20 AS runtime",
                "FROM nginx:1.27-alpine AS ui",
                "COPY web/dist /usr/share/nginx/html",
            ]
        ),
        "sentinel-aml-player-source/docker-compose.yml": "\n".join(
            [
                "services:",
                "  postgres:",
                "  aml-migrate:",
                "    build:",
                "      context: .",
                "      target: runtime",
                "  aml-api:",
                "    build:",
                "      context: .",
                "      target: runtime",
                "  aml-worker:",
                "    build:",
                "      context: .",
                "      target: runtime",
                "  aml-ui:",
                "    build:",
                "      context: .",
                "      target: ui",
            ]
        ),
        "sentinel-aml-player-source/web/dist/index.html": "<title>Sentinel AML</title>\n",
        "sentinel-aml-player-source/web/dist/runtime-config.js": "window.__SENTINEL_CONFIG__ = { apiBaseUrl: \"\" };\n",
    }


def write_tar(path: Path, files: dict[str, str]) -> None:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, text in sorted(files.items()):
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
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
