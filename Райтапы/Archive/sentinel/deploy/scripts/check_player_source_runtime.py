#!/usr/bin/env python3
"""Validate Docker Compose runtime readiness for the player source artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from run_go_release_tests import run_command


ARCHIVE_ROOT = "sentinel-aml-player-source"
REQUIRED_SERVICES = ("postgres", "aml-migrate", "aml-api", "aml-worker", "aml-ui")
REQUIRED_MAKE_TARGETS = ("up", "down", "logs", "rebuild", "smoke")
REVEALING_TOKENS = (
    "aml1_vulnerable",
    "aml2_vulnerable",
    "aml3_vulnerable",
    "aml4_vulnerable",
    "aml5_vulnerable",
    "checkers/",
    "sploits/",
    "fixes/",
)


@dataclass(frozen=True)
class RuntimeCheck:
    name: str
    status: str
    message: str
    elapsed_seconds: float | None = None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = check_player_source_runtime(args.artifact, docker=args.docker, run_live=not args.static_only)
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] == "fail":
        return 1
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--json-report", type=Path)
    parser.add_argument("--static-only", action="store_true", help="skip live Docker phases after static artifact validation")
    return parser.parse_args(argv)


def check_player_source_runtime(artifact: Path, *, docker: str = "docker", run_live: bool = True) -> dict[str, Any]:
    started = time.monotonic()
    checks: list[RuntimeCheck] = []
    endpoints: list[dict[str, str]] = []
    cleanup = {"attempted": False, "status": "not-run", "message": ""}
    project = f"sentinel-aml-player-{os.getpid()}-{int(time.time())}"

    if not artifact.is_file():
        checks.append(RuntimeCheck("artifact-present", "fail", "artifact is missing"))
        return report("fail", artifact, checks, endpoints, cleanup, started)

    with tempfile.TemporaryDirectory(prefix="sentinel-aml-player-source-runtime-") as tmp:
        temp_root = Path(tmp)
        extract_root = temp_root / "extract"
        source_root = extract_artifact(artifact, extract_root)
        checks.append(RuntimeCheck("artifact-unpack", "pass", source_root.as_posix()))

        checks.extend(static_runtime_checks(source_root))
        if any(check.status == "fail" for check in checks):
            return report("fail", artifact, checks, endpoints, cleanup, started)
        if not run_live:
            checks.append(RuntimeCheck("docker-live-runtime", "external-required", "static-only mode requested"))
            return report("external-required", artifact, checks, endpoints, cleanup, started)

        available, message = docker_available(docker, source_root)
        if not available:
            checks.append(RuntimeCheck("docker-live-runtime", "external-required", message))
            return report("external-required", artifact, checks, endpoints, cleanup, started)
        checks.append(RuntimeCheck("docker-live-runtime", "pass", message))

        api_port = free_port()
        ui_port = free_port()
        env = os.environ.copy()
        env["SENTINEL_AML_API_PORT"] = str(api_port)
        env["SENTINEL_AML_HTTP_PORT"] = str(ui_port)
        compose = [docker, "compose", "-p", project]
        status = "pass"
        try:
            run_phase(checks, "docker-compose-config", [*compose, "config"], source_root, env, timeout=45)
            for service in ("aml-migrate", "aml-api", "aml-worker", "aml-ui"):
                run_phase(checks, f"docker-compose-build-{service}", [*compose, "build", "--no-cache", service], source_root, env, timeout=420)
            run_phase(checks, "docker-compose-up", [*compose, "up", "--no-build", "-d"], source_root, env, timeout=180)
            endpoints.extend(smoke_endpoints(api_port, ui_port))
            checks.append(RuntimeCheck("http-smoke", "pass", f"endpoints={len(endpoints)}"))
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            status = "fail"
            checks.append(RuntimeCheck("runtime-failure", "fail", str(exc)))
            append_logs(checks, compose, source_root, env)
        finally:
            cleanup = cleanup_compose(compose, source_root, env)
        if cleanup["status"] == "fail":
            checks.append(RuntimeCheck("docker-compose-cleanup", "fail", str(cleanup["message"])))
            status = "fail"
        return report(status, artifact, checks, endpoints, cleanup, started)


def report(
    status: str,
    artifact: Path,
    checks: list[RuntimeCheck],
    endpoints: list[dict[str, str]],
    cleanup: dict[str, object],
    started: float,
) -> dict[str, Any]:
    return {
        "schema": "sentinel-aml-player-source-runtime.v1",
        "status": status,
        "artifact": artifact.as_posix(),
        "artifact_sha256": sha256_file(artifact) if artifact.is_file() else None,
        "docker_available": any(check.name == "docker-live-runtime" and check.status == "pass" for check in checks),
        "checks": [asdict(check) for check in checks],
        "endpoints_tested": endpoints,
        "cleanup": cleanup,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def extract_artifact(artifact: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            validate_member(member)
        archive.extractall(destination)
    source_root = destination / ARCHIVE_ROOT
    if not source_root.is_dir():
        raise RuntimeError(f"artifact must contain {ARCHIVE_ROOT}/")
    return source_root


def validate_member(member: tarfile.TarInfo) -> None:
    path = Path(member.name)
    if path.is_absolute() or ".." in path.parts:
        raise RuntimeError(f"unsafe archive member: {member.name}")
    if not member.name.startswith(f"{ARCHIVE_ROOT}/"):
        raise RuntimeError(f"unexpected archive root: {member.name}")


def static_runtime_checks(source_root: Path) -> list[RuntimeCheck]:
    checks: list[RuntimeCheck] = []
    compose = read_required(source_root / "docker-compose.yml", checks)
    dockerfile = read_required(source_root / "Dockerfile", checks)
    makefile = read_required(source_root / "Makefile", checks)
    readme = read_required(source_root / "README.md", checks)
    troubleshooting = read_required(source_root / "TROUBLESHOOTING.md", checks)
    env_example = read_required(source_root / "deploy" / "player.env.example", checks)
    if any(check.status == "fail" for check in checks):
        return checks

    services = set(re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", compose))
    missing_services = sorted(set(REQUIRED_SERVICES) - services)
    checks.append(
        RuntimeCheck(
            "compose-required-services",
            "fail" if missing_services else "pass",
            "missing " + ", ".join(missing_services) if missing_services else ", ".join(sorted(services)),
        )
    )
    checks.append(RuntimeCheck("compose-builds-from-source", "pass" if compose.count("context: .") >= 4 else "fail", "expected source build contexts"))
    checks.append(RuntimeCheck("compose-no-frontend-source", "pass" if "frontend/" not in compose else "fail", "player compose must not depend on frontend source"))
    checks.append(RuntimeCheck("compose-no-db-host-port", "pass" if "5432:" not in compose else "fail", "PostgreSQL must stay compose-local"))
    checks.append(RuntimeCheck("dockerfile-source-build", "pass" if dockerfile_source_build_ok(dockerfile) else "fail", "Go builds must run inside Dockerfile and UI must use static bundle"))
    checks.append(RuntimeCheck("static-frontend-present", "pass" if (source_root / "web" / "dist" / "index.html").is_file() else "fail", "web/dist/index.html must be present"))

    make_targets = {match.group(1) for match in re.finditer(r"(?m)^([A-Za-z0-9_-]+):\s*$", makefile)}
    missing_targets = sorted(set(REQUIRED_MAKE_TARGETS) - make_targets)
    checks.append(
        RuntimeCheck(
            "makefile-participant-commands",
            "fail" if missing_targets else "pass",
            "missing " + ", ".join(missing_targets) if missing_targets else ", ".join(REQUIRED_MAKE_TARGETS),
        )
    )
    docs = "\n".join([readme, troubleshooting])
    docs_ok = "docker compose up --build" in docs and "make rebuild" in docs and "make smoke" in docs
    checks.append(RuntimeCheck("player-docs-runtime-workflow", "pass" if docs_ok else "fail", "README/TROUBLESHOOTING must describe run and rebuild"))
    combined = "\n".join([compose, dockerfile, makefile, readme, troubleshooting, env_example]).lower()
    leaks = [token for token in REVEALING_TOKENS if token.lower() in combined]
    checks.append(RuntimeCheck("runtime-no-organizer-references", "fail" if leaks else "pass", ", ".join(leaks) if leaks else "no organizer-only references"))
    return checks


def read_required(path: Path, checks: list[RuntimeCheck]) -> str:
    if not path.is_file():
        checks.append(RuntimeCheck(f"required-file-{path.name}", "fail", path.as_posix()))
        return ""
    return path.read_text(encoding="utf-8")


def dockerfile_source_build_ok(dockerfile: str) -> bool:
    required = (
        "FROM golang:1.22-alpine AS go-build",
        "go build -o /out/aml-api ./cmd/aml-api",
        "go build -o /out/aml-worker ./cmd/aml-worker",
        "go build -o /out/aml-migrate ./cmd/aml-migrate",
        "FROM alpine:3.20 AS runtime",
        "FROM nginx:1.27-alpine AS ui",
        "COPY web/dist /usr/share/nginx/html",
    )
    forbidden = ("COPY bin/", "../", "npm ci", "npm install", "npm run build", "node:20")
    return all(item in dockerfile for item in required) and not any(item in dockerfile for item in forbidden)


def docker_available(docker: str, cwd: Path) -> tuple[bool, str]:
    if shutil.which(docker) is None:
        return False, f"{docker!r} executable was not found"
    env = os.environ.copy()
    for command in ([docker, "--version"], [docker, "compose", "version"], [docker, "info"]):
        try:
            completed = run_command(command, cwd=cwd, env=env, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"{' '.join(command)} unavailable: {exc}"
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            return False, f"{' '.join(command)} exited {completed.returncode}: {detail}"
    return True, "docker, compose plugin, and daemon are available"


def run_phase(checks: list[RuntimeCheck], name: str, command: list[str], cwd: Path, env: dict[str, str], *, timeout: float) -> None:
    started = time.monotonic()
    try:
        completed = run_command(command, cwd=cwd, env=env, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        checks.append(RuntimeCheck(name, "fail", f"timeout after {timeout:.0f}s", round(time.monotonic() - started, 3)))
        raise
    elapsed = round(time.monotonic() - started, 3)
    message = f"exit={completed.returncode}"
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        if detail:
            message = f"{message}: {detail[-1200:]}"
    checks.append(RuntimeCheck(name, "pass" if completed.returncode == 0 else "fail", message, elapsed))
    if completed.returncode != 0:
        raise RuntimeError(f"{name} exited {completed.returncode}")


def smoke_endpoints(api_port: int, ui_port: int) -> list[dict[str, str]]:
    endpoints = [
        ("api-health", f"http://127.0.0.1:{api_port}/healthz", "application/json"),
        ("api-ready", f"http://127.0.0.1:{api_port}/readyz", "application/json"),
        ("ui-index", f"http://127.0.0.1:{ui_port}/", "text/html"),
        ("ui-proxied-health", f"http://127.0.0.1:{ui_port}/healthz", "application/json"),
    ]
    tested: list[dict[str, str]] = []
    for name, url, expected_content_type in endpoints:
        body, content_type = wait_for_http(url)
        if expected_content_type not in content_type.lower():
            raise RuntimeError(f"{name} returned unexpected content-type {content_type!r}")
        if name.startswith("api") or name == "ui-proxied-health":
            if '"status":"ok"' not in body.replace(" ", ""):
                raise RuntimeError(f"{name} did not return healthy JSON")
        if name == "ui-index" and "Sentinel AML" not in body:
            raise RuntimeError("UI index did not contain Sentinel AML title")
        tested.append({"name": name, "url": url, "status": "pass"})
    return tested


def wait_for_http(url: str) -> tuple[str, str]:
    deadline = time.monotonic() + 120
    last_error = ""
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(request, timeout=3) as response:
                body = response.read().decode("utf-8", errors="ignore")
                return body, response.headers.get("Content-Type", "")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
            time.sleep(1)
    raise RuntimeError(f"HTTP endpoint did not become ready: {url}: {last_error}")


def append_logs(checks: list[RuntimeCheck], compose: list[str], cwd: Path, env: dict[str, str]) -> None:
    try:
        completed = run_command([*compose, "logs", "--no-color", "--tail", "120"], cwd=cwd, env=env, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        checks.append(RuntimeCheck("docker-compose-logs", "fail", str(exc)))
        return
    logs = (completed.stdout or completed.stderr).strip()
    checks.append(RuntimeCheck("docker-compose-logs", "pass" if completed.returncode == 0 else "fail", logs[-4000:]))


def cleanup_compose(compose: list[str], cwd: Path, env: dict[str, str]) -> dict[str, object]:
    started = time.monotonic()
    try:
        completed = run_command([*compose, "down", "--remove-orphans", "-v"], cwd=cwd, env=env, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"attempted": True, "status": "fail", "message": str(exc), "elapsed_seconds": round(time.monotonic() - started, 3)}
    message = (completed.stderr or completed.stdout).strip()
    return {
        "attempted": True,
        "status": "pass" if completed.returncode == 0 else "fail",
        "message": message[-1200:],
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as handle:
        handle.bind(("127.0.0.1", 0))
        return int(handle.getsockname()[1])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
