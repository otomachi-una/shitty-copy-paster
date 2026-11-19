#!/usr/bin/env python3
"""Prove the generated player-service source candidate is runnable."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_player_bundle
import check_player_bundle_hygiene
import runtime_smoke
from run_go_release_tests import run_command


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "tmp" / "w34-player-source-candidate"
DEFAULT_PACKAGE_DATABASE_URL = "postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable"


def package_env(base_env: dict[str, str], cache_dir: str, appdata_dir: str, base_url: str | None = None) -> dict[str, str]:
    env = dict(base_env)
    env["GOTOOLCHAIN"] = "local"
    env["GOFLAGS"] = "-mod=vendor"
    env["GOTELEMETRY"] = "off"
    env["GOCACHE"] = cache_dir
    env["APPDATA"] = appdata_dir
    if base_url is not None:
        env["SENTINEL_AML_HTTP_PORT"] = runtime_smoke.http_port_from_base_url(base_url)
        env["WSLENV"] = runtime_smoke.merge_wslenv(env.get("WSLENV", ""), ("DATABASE_URL", "SENTINEL_AML_HTTP_PORT"))
    return env


def run_player_package_runtime(
    output_dir: Path,
    *,
    allowlist_path: Path | None,
    go: str,
    docker: str,
    database_url: str,
    base_url: str,
    skip_if_docker_unavailable: bool,
    stdout=sys.stdout,
    stderr=sys.stderr,
) -> int:
    started = time.monotonic()
    checks: list[dict[str, Any]] = []
    if allowlist_path is None:
        allowlist_path = output_dir.parent / f"{output_dir.name}.hygiene-allowlist.json"

    try:
        build_result = build_player_bundle.build_player_candidate(output_dir, allowlist_path)
        checks.append({"name": "player-source-candidate-build", "status": "pass", "message": f"{build_result['file_count']} files"})
        record_check(checks, "player-source-hygiene", check_player_bundle_hygiene.validate_player_bundle(output_dir, allowlist_path))

        with tempfile.TemporaryDirectory(prefix="sentinel-aml-player-package-gocache.") as cache_dir:
            with tempfile.TemporaryDirectory(prefix="sentinel-aml-player-package-appdata.") as appdata_dir:
                env = package_env(os.environ, cache_dir, appdata_dir, base_url)
                compose_env = write_compose_env_file(output_dir, base_url)
                try:
                    run_phase(checks, "player-source-go-test", [go, "test", "./..."], output_dir, env, 120, stdout, stderr)
                    run_phase(
                        checks,
                        "player-source-go-build",
                        [go, "build", "./cmd/aml-api", "./cmd/aml-worker", "./cmd/aml-migrate"],
                        output_dir,
                        env,
                        120,
                        stdout,
                        stderr,
                    )
                    run_phase(
                        checks,
                        "player-source-compose-config",
                        [docker, "compose", "--env-file", ".env", "-f", "deploy/compose.yaml", "config"],
                        output_dir,
                        env,
                        30,
                        stdout,
                        stderr,
                    )
                    smoke_code = runtime_smoke.run_runtime_smoke(
                        output_dir,
                        go=go,
                        docker=docker,
                        database_url=database_url,
                        base_url=base_url,
                        skip_if_docker_unavailable=skip_if_docker_unavailable,
                        migrate_package="./cmd/aml-migrate",
                        compose_file=Path("deploy/compose.yaml"),
                        compose_env_file=Path(".env"),
                        stdout=stdout,
                        stderr=stderr,
                    )
                    checks.append({"name": "player-source-runtime-smoke", "status": "pass" if smoke_code == 0 else "fail", "message": f"exit={smoke_code}"})
                    cleanup_compose(output_dir, docker, env, stdout, stderr)
                    if smoke_code != 0:
                        return emit_result(checks, started, stdout, 77 if smoke_code == 77 else 1)
                finally:
                    remove_compose_env_file(compose_env)

        write_runtime_proof(output_dir, elapsed=time.monotonic() - started)
        record_check(
            checks,
            "player-source-runtime-readiness",
            check_player_bundle_hygiene.validate_player_bundle(output_dir, allowlist_path, require_runtime_ready=True),
        )
        return emit_result(checks, started, stdout, 0)
    except Exception as exc:
        checks.append({"name": "player-source-runtime-proof", "status": "fail", "message": str(exc)})
        return emit_result(checks, started, stdout, 1)


def run_phase(
    checks: list[dict[str, Any]],
    name: str,
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    stdout,
    stderr,
) -> None:
    started = time.monotonic()
    print(f"player-package-runtime: phase {name} start timeout={timeout:.0f}s", file=stdout, flush=True)
    print(f"player-package-runtime: command {' '.join(command)}", file=stdout, flush=True)
    completed = run_command(command, cwd=cwd, env=env, timeout=timeout)
    if completed.stdout:
        print(completed.stdout, end="", file=stdout, flush=True)
    if completed.stderr:
        print(completed.stderr, end="", file=stderr, flush=True)
    elapsed = time.monotonic() - started
    status = "pass" if completed.returncode == 0 else "fail"
    checks.append({"name": name, "status": status, "message": f"exit={completed.returncode} elapsed={elapsed:.3f}s"})
    print(f"player-package-runtime: phase {name} exit={completed.returncode} elapsed={elapsed:.3f}s", file=stdout, flush=True)
    if completed.returncode != 0:
        raise RuntimeError(f"{name} exited {completed.returncode}")


def record_check(checks: list[dict[str, Any]], name: str, result: dict[str, object]) -> None:
    status = str(result.get("status", "fail"))
    checks.append({"name": name, "status": status, "message": json.dumps(result, sort_keys=True)})
    if status != "pass":
        raise RuntimeError(f"{name} failed")


def cleanup_compose(candidate: Path, docker: str, env: dict[str, str], stdout, stderr) -> None:
    command = [docker, "compose", "--env-file", ".env", "-f", "deploy/compose.yaml", "down", "--remove-orphans", "-v"]
    print("player-package-runtime: phase player-source-compose-cleanup start timeout=30s", file=stdout, flush=True)
    completed = run_command(command, cwd=candidate, env=env, timeout=30)
    if completed.stdout:
        print(completed.stdout, end="", file=stdout, flush=True)
    if completed.stderr:
        print(completed.stderr, end="", file=stderr, flush=True)
    print(f"player-package-runtime: phase player-source-compose-cleanup exit={completed.returncode}", file=stdout, flush=True)


def write_compose_env_file(candidate: Path, base_url: str) -> Path:
    env_path = candidate / ".env"
    env_path.write_text(
        f"SENTINEL_AML_HTTP_PORT={runtime_smoke.http_port_from_base_url(base_url)}\n",
        encoding="utf-8",
    )
    return env_path


def remove_compose_env_file(env_path: Path) -> None:
    try:
        env_path.unlink()
    except FileNotFoundError:
        pass


def write_runtime_proof(candidate: Path, *, elapsed: float) -> None:
    status = dict(build_player_bundle.STAGED_SOURCE_STATUS)
    status.update(
        {
            "candidate_state": "runtime-proven",
            "delivery_mode": "source",
            "final_package": True,
            "source_runtime_ready": True,
            "runtime_proof": {
                "command": "python -B scripts/check_player_package_runtime.py",
                "exit_code": 0,
                "elapsed_seconds": round(elapsed, 3),
                "mode": "source",
                "evidence": [
                    "offline go test ./...",
                    "offline go build ./cmd/aml-api ./cmd/aml-worker ./cmd/aml-migrate",
                    "docker compose -f deploy/compose.yaml config",
                    "runtime smoke with PostgreSQL, migrations, worker, API health, and representative AML workflow",
                ],
            },
            "promotion_blocker": None,
        }
    )
    (candidate / build_player_bundle.PACKAGING_STATUS_FILE).write_text(
        json.dumps(status, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def emit_result(checks: list[dict[str, Any]], started: float, stdout, exit_code: int) -> int:
    result = {
        "checks": checks,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "status": "pass" if exit_code == 0 else ("skip" if exit_code == 77 else "fail"),
    }
    print(json.dumps(result, indent=2, sort_keys=True), file=stdout, flush=True)
    return exit_code


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--allowlist-out", type=Path)
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_PACKAGE_DATABASE_URL))
    parser.add_argument("--base-url", default=os.environ.get("SENTINEL_AML_RUNTIME_SMOKE_URL", runtime_smoke.DEFAULT_BASE_URL))
    parser.add_argument("--skip-if-docker-unavailable", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return run_player_package_runtime(
        args.output_dir,
        allowlist_path=args.allowlist_out,
        go=args.go,
        docker=args.docker,
        database_url=args.database_url,
        base_url=args.base_url,
        skip_if_docker_unavailable=args.skip_if_docker_unavailable,
    )


if __name__ == "__main__":
    raise SystemExit(main())
