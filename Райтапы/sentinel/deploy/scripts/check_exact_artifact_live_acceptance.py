#!/usr/bin/env python3
"""Run live acceptance against exact Sentinel AML transfer artifact bytes."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_artifacts
import build_player_bundle
import check_live_competition_matrix


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAYER_ARTIFACT = ROOT / "out" / "artifacts" / build_artifacts.PLAYER_ARTIFACT_NAME
DEFAULT_ADMIN_ARTIFACT = ROOT / "out" / "artifacts" / build_artifacts.ADMIN_ARTIFACT_NAME
DEFAULT_SUMMARY_OUTPUT = ROOT / "out" / "exact-artifact-live-acceptance-summary.json"
DEFAULT_VALIDATION_ROOT = ROOT / "validation" / "exact-artifact-live"
PLAYER_ROOT_NAME = build_artifacts.PLAYER_SPEC.archive_root
ADMIN_ROOT_NAME = build_artifacts.ADMIN_SPEC.archive_root
CHECKER_OK = 101
AML_CASES = check_live_competition_matrix.AML_CASES


class AcceptanceFailure(RuntimeError):
    pass


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float


class PhaseRecorder:
    def __init__(self) -> None:
        self.phases: list[dict[str, Any]] = []

    def run(
        self,
        name: str,
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str] | None = None,
        timeout: float,
        check: bool = True,
        expected_exit_codes: tuple[int, ...] = (0,),
    ) -> CommandResult:
        started = time.monotonic()
        try:
            completed = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - started
            self.phases.append({"name": name, "status": "timeout", "elapsed_seconds": round(elapsed, 3), "timeout_seconds": timeout})
            raise AcceptanceFailure(f"{name} timed out after {timeout:.0f}s: {command_label(command)}") from exc
        except OSError as exc:
            elapsed = time.monotonic() - started
            self.phases.append({"name": name, "status": "fail", "elapsed_seconds": round(elapsed, 3), "message": str(exc)})
            raise AcceptanceFailure(f"{name} failed to start: {command_label(command)}: {exc}") from exc

        elapsed = time.monotonic() - started
        result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr, elapsed)
        expected = result.returncode in expected_exit_codes
        self.phases.append(
            {
                "name": name,
                "status": "pass" if expected else "fail",
                "exit_code": result.returncode,
                "elapsed_seconds": round(elapsed, 3),
                "timeout_seconds": timeout,
            }
        )
        if check and not expected:
            raise AcceptanceFailure(command_failure_message(result))
        return result


class PlayerComposeInstance:
    def __init__(self, player_root: Path, *, docker: str, recorder: PhaseRecorder, label: str) -> None:
        self.player_root = player_root
        self.docker = docker
        self.recorder = recorder
        self.port = free_port()
        self.project = safe_project_name(label, self.port)
        self.env = os.environ.copy()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "PlayerComposeInstance":
        (self.player_root / ".env").write_text(f"SENTINEL_AML_HTTP_PORT={self.port}\n", encoding="utf-8")
        self.recorder.run("player-artifact-docker-version", [self.docker, "--version"], cwd=self.player_root, env=self.env, timeout=20)
        self.compose("config", timeout=30)
        self.compose("up", "--build", "-d", timeout=180)
        wait_ready(self.base_url)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.compose("down", "--remove-orphans", "-v", timeout=90, check=False)

    def compose(self, *args: str, timeout: float, check: bool = True) -> CommandResult:
        return self.recorder.run(
            f"player-artifact-compose-{'-'.join(args[:2])}",
            [self.docker, "compose", "-p", self.project, "--env-file", ".env", "-f", "deploy/compose.yaml", *args],
            cwd=self.player_root,
            env=self.env,
            timeout=timeout,
            check=check,
        )


class SourceServiceInstance:
    def __init__(self, repo_root: Path, *, docker: str, go: str, recorder: PhaseRecorder, label: str, tags: str | None = None) -> None:
        self.repo_root = repo_root
        self.docker = docker
        self.go = go
        self.recorder = recorder
        self.tags = tags
        self.api_port = free_port()
        self.pg_port = free_port()
        self.project = safe_project_name(label, self.api_port)
        self.database_url = f"postgres://sentinel:sentinel@127.0.0.1:{self.pg_port}/sentinel_aml_test?sslmode=disable"
        self.env = source_service_env(self.database_url)
        self.api_process: subprocess.Popen[str] | None = None
        self.worker_process: subprocess.Popen[str] | None = None
        self.base_compose_file = self.repo_root / "docker-compose.yml"
        self.base_compose_created = False
        self.override_file = self.repo_root / "compose.fh05-live-acceptance.override.yml"

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    def __enter__(self) -> "SourceServiceInstance":
        if not self.base_compose_file.exists():
            self.base_compose_file.write_text(
                "services:\n"
                "  postgres:\n"
                "    image: postgres:16-alpine\n"
                "    environment:\n"
                "      POSTGRES_DB: sentinel_aml_test\n"
                "      POSTGRES_USER: sentinel\n"
                "      POSTGRES_PASSWORD: sentinel\n"
                "    healthcheck:\n"
                "      test: [\"CMD-SHELL\", \"pg_isready -U sentinel -d sentinel_aml_test\"]\n"
                "      interval: 2s\n"
                "      timeout: 5s\n"
                "      retries: 20\n",
                encoding="utf-8",
            )
            self.base_compose_created = True
        self.override_file.write_text(
            "services:\n"
            "  postgres:\n"
            "    ports:\n"
            f"      - \"127.0.0.1:{self.pg_port}:5432\"\n",
            encoding="utf-8",
        )
        self.compose("up", "-d", "postgres", timeout=90)
        self.wait_for_postgres()
        self.recorder.run(
            f"{self.project}-migrations",
            self.go_run_command("./scripts/migrate"),
            cwd=self.repo_root,
            env=self.env,
            timeout=90,
        )
        self.api_process = start_process(
            [*self.go_run_command("./cmd/aml-api"), "-addr", f"127.0.0.1:{self.api_port}"],
            self.repo_root,
            self.env,
        )
        self.worker_process = start_process(
            [*self.go_run_command("./cmd/aml-worker"), "--interval", "1ms"],
            self.repo_root,
            self.env,
        )
        self.wait_for_health()
        time.sleep(3)
        if self.worker_process is not None and self.worker_process.poll() is not None:
            stdout, stderr = self.worker_process.communicate(timeout=1)
            raise AcceptanceFailure(
                f"{self.project}: worker exited during startup code={self.worker_process.returncode} stdout={stdout[-2000:]} stderr={stderr[-2000:]}"
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        for process in (self.worker_process, self.api_process):
            if process is not None:
                terminate_process_tree(process)
        self.compose("down", "--remove-orphans", "-v", timeout=90, check=False)
        if self.override_file.exists():
            self.override_file.unlink()
        if self.base_compose_created and self.base_compose_file.exists():
            self.base_compose_file.unlink()

    def go_run_command(self, package: str) -> list[str]:
        command = [self.go, "run"]
        if self.tags:
            command.extend(["-tags", self.tags])
        command.append(package)
        return command

    def compose(
        self,
        *args: str,
        timeout: float,
        check: bool = True,
        expected_exit_codes: tuple[int, ...] = (0,),
    ) -> CommandResult:
        return self.recorder.run(
            f"{self.project}-compose-{'-'.join(args[:2])}",
            [self.docker, "compose", "-p", self.project, "-f", "docker-compose.yml", "-f", self.override_file.name, *args],
            cwd=self.repo_root,
            env=self.env,
            timeout=timeout,
            check=check,
            expected_exit_codes=expected_exit_codes,
        )

    def wait_for_postgres(self) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            result = self.compose(
                "exec",
                "-T",
                "postgres",
                "pg_isready",
                "-U",
                "sentinel",
                "-d",
                "sentinel_aml_test",
                timeout=10,
                check=False,
                expected_exit_codes=(0, 1, 2),
            )
            if result.returncode == 0:
                return
            time.sleep(1)
        raise AcceptanceFailure(f"{self.project}: postgres did not become healthy")

    def wait_for_health(self) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            for name, process in (("api", self.api_process), ("worker", self.worker_process)):
                if process is not None and process.poll() is not None:
                    stdout, stderr = process.communicate(timeout=1)
                    raise AcceptanceFailure(f"{self.project}: {name} exited early code={process.returncode} stdout={stdout[-2000:]} stderr={stderr[-2000:]}")
            try:
                with urllib.request.urlopen(self.base_url + "/healthz", timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.5)
        raise AcceptanceFailure(f"{self.project}: api health did not become ready")


def run_acceptance(
    *,
    player_artifact: Path,
    admin_artifact: Path,
    validation_root: Path,
    summary_output: Path,
    python: str,
    go: str,
    docker: str,
) -> dict[str, Any]:
    started = time.monotonic()
    recorder = PhaseRecorder()
    summary: dict[str, Any] = {
        "schema": "sentinel-aml-exact-artifact-live-acceptance.v1",
        "status": "fail",
        "started_at_unix": int(time.time()),
        "artifacts": {},
        "paths": {
            "player_artifact": rel_or_abs(player_artifact),
            "admin_artifact": rel_or_abs(admin_artifact),
            "validation_root": rel_or_abs(validation_root),
            "summary_output": rel_or_abs(summary_output),
        },
        "runtime_validation": {},
        "phases": recorder.phases,
    }
    try:
        require_file(player_artifact, "player artifact")
        require_file(admin_artifact, "admin artifact")
        summary["artifacts"] = {
            "player": artifact_record(player_artifact, build_artifacts.PLAYER_SPEC.manifest_name),
            "admin": artifact_record(admin_artifact, build_artifacts.ADMIN_SPEC.manifest_name),
        }
        clean_validation_root(validation_root)
        extracted = extract_transfer_artifacts(player_artifact, admin_artifact, validation_root)
        summary["extracted"] = {name: rel_or_abs(path) for name, path in extracted.items()}
        validate_extracted_contract(extracted["player"], extracted["admin"])

        runtime = run_exact_player_runtime(extracted["player"], extracted["admin"], python=python, docker=docker, recorder=recorder)
        fixes = run_fix_workflow(extracted["admin"], validation_root / "fixed", python=python, go=go, docker=docker, recorder=recorder)
        summary["runtime_validation"] = {
            "status": aggregate([runtime["status"], fixes["status"]]),
            "player_artifact_sha256": summary["artifacts"]["player"]["sha256"],
            "admin_artifact_sha256": summary["artifacts"]["admin"]["sha256"],
            "runtime_smoke": runtime["runtime_smoke"],
            "checker_check_havoc": runtime["checker_check_havoc"],
            "flag_stores": runtime["flag_stores"],
            "sploit_matrix": runtime["sploit_matrix"],
            "fix_workflow": fixes,
            "matrix_status": {
                "status": aggregate([runtime["sploit_matrix"]["status"], fixes["status"]]),
                "source": "exact player/admin transfer artifacts",
                "historical_candidate_tree_substitute": False,
            },
        }
        if summary["runtime_validation"]["status"] != "pass":
            raise AcceptanceFailure("exact-artifact live acceptance failed")
        summary["status"] = "pass"
    except Exception as exc:
        summary["status"] = "fail"
        summary["error"] = str(exc)
    finally:
        summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
        summary["phases"] = recorder.phases
        summary_output.parent.mkdir(parents=True, exist_ok=True)
        summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def run_exact_player_runtime(admin_player_root: Path, admin_root: Path, *, python: str, docker: str, recorder: PhaseRecorder) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    flag_store_status: dict[str, dict[str, Any]] = {}
    env = checker_env()
    with PlayerComposeInstance(admin_player_root, docker=docker, recorder=recorder, label="fh05-exact-player") as service:
        checker(admin_root, python, "check", service.base_url, env=env, recorder=recorder, phase_name="checker-check")
        checker(admin_root, python, "havoc", service.base_url, env=env, recorder=recorder, phase_name="checker-havoc")
        for item in AML_CASES:
            flag = f"SENTINEL{{FH05_{item.aml_id.replace('-', '_')}_{time.time_ns()}}}"
            put_result = checker(
                admin_root,
                python,
                "put",
                service.base_url,
                flag,
                str(item.place),
                env=env,
                recorder=recorder,
                phase_name=f"{item.aml_id}-checker-put",
            )
            private_state = put_result.stderr.strip()
            attack_data = parse_attack_data(item.aml_id, put_result.stdout)
            attack_data = check_live_competition_matrix.normalize_attack_data_for_aml(item, attack_data)
            assert_public_attack_data_safe(attack_data)
            sploit = run_sploit(
                admin_root,
                python,
                item,
                "127.0.0.1",
                service.port,
                attack_data,
                recorder=recorder,
                phase_name=f"{item.aml_id}-sploit",
            )
            assert_sploit_extracts(sploit, flag, item.aml_id)
            checker(
                admin_root,
                python,
                "get",
                service.base_url,
                private_state,
                flag,
                str(item.place),
                env=env,
                recorder=recorder,
                phase_name=f"{item.aml_id}-checker-get",
            )
            rows.append(
                {
                    "aml": item.aml_id,
                    "place": item.place,
                    "flag_store": item.flag_store,
                    "status": "pass",
                    "sploit": item.sploit,
                    "flag_sha256": sha256_text(flag),
                    "public_attack_data_keys": sorted(attack_data),
                }
            )
            flag_store_status[item.flag_store] = {
                "status": "pass",
                "place": item.place,
                "validated_by": f"{item.aml_id} PUT/GET",
            }
    return {
        "status": "pass",
        "runtime_smoke": {"status": "pass", "source": "deployed exact player artifact compose stack"},
        "checker_check_havoc": {"status": "pass", "check": "pass", "havoc": "pass", "source": "checker from exact admin artifact"},
        "flag_stores": {
            "status": "pass" if {"CaseNote.body", "EDDRecord.confidential_comment"}.issubset(flag_store_status) else "fail",
            "stores": flag_store_status,
        },
        "sploit_matrix": {"status": "pass", "expected_count": len(AML_CASES), "passed_count": len(rows), "rows": rows},
    }


def run_fix_workflow(admin_root: Path, fixed_root: Path, *, python: str, go: str, docker: str, recorder: PhaseRecorder) -> dict[str, Any]:
    clean_validation_root(fixed_root)
    source_root = fixed_root / "all-fixes"
    shutil.copytree(admin_root, source_root)
    for item in AML_CASES:
        recorder.run(
            f"{item.aml_id}-fix-apply-check",
            ["git", "apply", "--check", "--whitespace=nowarn", "--exclude=*_test.go", item.fix_patch],
            cwd=source_root,
            timeout=30,
        )
        recorder.run(
            f"{item.aml_id}-fix-apply",
            ["git", "apply", "--whitespace=nowarn", "--exclude=*_test.go", item.fix_patch],
            cwd=source_root,
            timeout=30,
        )
    service_root = fixed_root / "materialized-player-source"
    materialize_player_source_from(source_root, service_root)
    rows: list[dict[str, Any]] = []
    env = checker_env(f"fh05-all-fixes-{time.time_ns()}")
    with SourceServiceInstance(service_root, docker=docker, go=go, recorder=recorder, label="fh05-all-fixes") as service:
        checker(source_root, python, "check", service.base_url, env=env, recorder=recorder, phase_name="all-fixes-checker-check")
        for item in AML_CASES:
            rows.append(run_fixed_case(source_root, service, item, python=python, env=env, recorder=recorder))
        checker(source_root, python, "check", service.base_url, env=env, recorder=recorder, phase_name="all-fixes-checker-check-after")
    return {
        "status": "pass",
        "expected_count": len(AML_CASES),
        "passed_count": len(rows),
        "patch_application": "production hunks from exact admin artifact; *_test.go hunks excluded for live runtime validation",
        "rows": rows,
    }


def run_fixed_case(
    admin_tools_root: Path,
    service: SourceServiceInstance,
    item: Any,
    *,
    python: str,
    env: dict[str, str],
    recorder: PhaseRecorder,
) -> dict[str, Any]:
    put_result = checker(
        admin_tools_root,
        python,
        "put",
        service.base_url,
        f"SENTINEL{{FH05_FIXED_{item.aml_id.replace('-', '_')}_{time.time_ns()}}}",
        str(item.place),
        env=env,
        recorder=recorder,
        phase_name=f"{item.aml_id}-fixed-checker-put",
    )
    flag = put_result.command[-2]
    private_state = put_result.stderr.strip()
    attack_data = parse_attack_data(item.aml_id, put_result.stdout)
    attack_data = check_live_competition_matrix.normalize_attack_data_for_aml(item, attack_data)
    sploit = run_sploit(
        admin_tools_root,
        python,
        item,
        "127.0.0.1",
        service.api_port,
        attack_data,
        recorder=recorder,
        phase_name=f"{item.aml_id}-fixed-sploit-blocked",
        expected_exit_codes=(1,),
    )
    assert_sploit_blocked(sploit, flag, item.aml_id)
    checker(
        admin_tools_root,
        python,
        "get",
        service.base_url,
        private_state,
        flag,
        str(item.place),
        env=env,
        recorder=recorder,
        phase_name=f"{item.aml_id}-fixed-checker-get",
    )
    checker(admin_tools_root, python, "check", service.base_url, env=env, recorder=recorder, phase_name=f"{item.aml_id}-fixed-checker-check-after")
    return {
        "aml": item.aml_id,
        "place": item.place,
        "flag_store": item.flag_store,
        "status": "pass",
        "fix_patch": item.fix_patch,
        "sploit_exit": sploit.returncode,
    }


def checker(
    admin_root: Path,
    python: str,
    action: str,
    base_url: str,
    *args: str,
    env: dict[str, str],
    recorder: PhaseRecorder,
    phase_name: str,
) -> CommandResult:
    result = recorder.run(
        phase_name,
        [python, str(admin_root / "checkers" / "sentinel_aml" / "checker.py"), action, base_url, *args],
        cwd=admin_root,
        env=env,
        timeout=60,
        check=False,
        expected_exit_codes=(CHECKER_OK,),
    )
    if result.returncode != CHECKER_OK:
        raise AcceptanceFailure(f"{phase_name} failed: exit={result.returncode} stdout={redact(result.stdout)} stderr={redact(result.stderr)}")
    return result


def run_sploit(
    admin_root: Path,
    python: str,
    item: Any,
    host: str,
    port: int,
    attack_data: dict[str, Any],
    *,
    recorder: PhaseRecorder,
    phase_name: str,
    expected_exit_codes: tuple[int, ...] = (0,),
) -> CommandResult:
    return recorder.run(
        phase_name,
        [python, str(admin_root / item.sploit), host, str(port), json.dumps(attack_data, sort_keys=True), "--timeout", "8"],
        cwd=admin_root,
        timeout=60,
        check=False,
        expected_exit_codes=expected_exit_codes,
    )


def extract_transfer_artifacts(player_artifact: Path, admin_artifact: Path, validation_root: Path) -> dict[str, Path]:
    player_extract = validation_root / "player-extracted"
    admin_extract = validation_root / "admin-extracted"
    safe_extract(player_artifact, player_extract)
    safe_extract(admin_artifact, admin_extract)
    return {"player": player_extract / PLAYER_ROOT_NAME, "admin": admin_extract / ADMIN_ROOT_NAME}


def validate_extracted_contract(player_root: Path, admin_root: Path) -> None:
    required_player = [
        "Dockerfile",
        "deploy/compose.yaml",
        "bin/aml-api",
        "bin/aml-worker",
        "bin/aml-migrate",
        "ui/index.html",
        "ui/runtime-config.js",
    ]
    required_admin = [
        "checkers/sentinel_aml/checker.py",
        "checkers/sentinel_aml/checker_lib.py",
        "cmd/aml-api/main.go",
        "cmd/aml-worker/main.go",
        "scripts/migrate/main.go",
        "docker-compose.yml",
    ]
    for item in AML_CASES:
        required_admin.extend([item.sploit, item.fix_patch])
    missing = [f"player:{path}" for path in required_player if not (player_root / path).is_file()]
    missing.extend(f"admin:{path}" for path in required_admin if not (admin_root / path).is_file())
    if missing:
        raise AcceptanceFailure("extracted artifact contract is missing required files: " + ", ".join(missing))


def safe_extract(archive_path: Path, dest: Path) -> None:
    clean_validation_root(dest)
    dest_resolved = dest.resolve()
    with gzip.open(archive_path, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        for member in archive.getmembers():
            target = (dest / member.name).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError as exc:
                raise AcceptanceFailure(f"unsafe archive member path: {member.name}") from exc
        archive.extractall(dest)


def clean_validation_root(path: Path) -> None:
    ensure_generated_path(path)
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def ensure_generated_path(path: Path) -> None:
    resolved = path.resolve()
    if resolved == ROOT:
        raise ValueError("refusing to clean repository root")
    try:
        relative = resolved.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"refusing to clean outside repository: {resolved}") from exc
    if not relative.parts or relative.parts[0] not in {"validation", "tmp", "out"}:
        raise ValueError(f"refusing to clean non-generated repository path: {resolved}")


def artifact_record(artifact: Path, manifest_name: str) -> dict[str, Any]:
    manifest = artifact.parents[1] / "manifests" / manifest_name
    record: dict[str, Any] = {
        "path": rel_or_abs(artifact),
        "sha256": sha256_file(artifact),
        "size_bytes": artifact.stat().st_size,
    }
    if manifest.is_file():
        manifest_doc = json.loads(manifest.read_text(encoding="utf-8"))
        record["manifest"] = rel_or_abs(manifest)
        record["manifest_sha256"] = sha256_file(manifest)
        record["manifest_artifact_sha256"] = manifest_doc.get("artifact", {}).get("sha256")
        record["manifest_matches_artifact"] = record["manifest_artifact_sha256"] == record["sha256"]
        if not record["manifest_matches_artifact"]:
            raise AcceptanceFailure(f"manifest {manifest} does not match artifact bytes {artifact}")
    return record


def assert_sploit_extracts(result: CommandResult, flag: str, aml_id: str) -> None:
    if result.returncode != 0:
        raise AcceptanceFailure(f"{aml_id} sploit failed before extracting flag: {command_failure_message(result)}")
    if flag not in result.stdout:
        raise AcceptanceFailure(f"{aml_id} sploit did not print expected flag: stdout={redact(result.stdout)} stderr={redact(result.stderr)}")


def assert_sploit_blocked(result: CommandResult, flag: str, aml_id: str) -> None:
    if flag in result.stdout:
        raise AcceptanceFailure(f"{aml_id} fixed service still leaked the flag: stdout={redact(result.stdout)}")
    if result.returncode == 0:
        raise AcceptanceFailure(f"{aml_id} fixed service sploit exited 0 without flag; expected blocked extraction failure")


def assert_public_attack_data_safe(attack_data: dict[str, Any]) -> None:
    serialized = json.dumps(attack_data, sort_keys=True).lower()
    forbidden = (
        "flag",
        "private_state",
        "checker_secret",
        "password",
        "session",
        "token",
        "confidential_comment",
        "casenote.body",
        "eddrecord",
        "store",
        "dedup_hint",
        "typology_hint",
        "entity_hint",
    )
    leaked = [marker for marker in forbidden if marker in serialized]
    if leaked:
        raise AcceptanceFailure(f"checker public attack data leaked forbidden markers: {', '.join(leaked)}")


def parse_attack_data(aml_id: str, stdout: str) -> dict[str, Any]:
    try:
        attack_data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AcceptanceFailure(f"{aml_id} checker PUT returned non-JSON public attack data") from exc
    if not isinstance(attack_data, dict):
        raise AcceptanceFailure(f"{aml_id} checker PUT returned malformed public attack data")
    return attack_data


def wait_ready(base_url: str) -> None:
    deadline = time.monotonic() + 90
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base_url + "/readyz", timeout=3) as response:
                body = response.read().decode("utf-8", errors="ignore")
                if response.status == 200 and "ok" in body.lower():
                    return
        except (OSError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(1)
    raise AcceptanceFailure(f"exact player artifact did not become ready: {last_error}")


def checker_env(secret: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["SENTINEL_AML_CHECKER_SECRET"] = secret or f"fh05-live-acceptance-{time.time_ns()}"
    return env


def materialize_player_source_from(source_root: Path, dest_root: Path) -> None:
    old_root = build_player_bundle.ROOT
    try:
        build_player_bundle.ROOT = source_root
        build_player_bundle.materialize_competition_source(dest_root)
    finally:
        build_player_bundle.ROOT = old_root


def source_service_env(database_url: str) -> dict[str, str]:
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    env["GOTOOLCHAIN"] = "local"
    env["GOFLAGS"] = "-mod=vendor"
    env["GOTELEMETRY"] = "off"
    env["GOCACHE"] = str(ROOT / "validation" / "exact-artifact-live" / "gocache")
    env["APPDATA"] = str(ROOT / "validation" / "exact-artifact-live" / "appdata")
    Path(env["GOCACHE"]).mkdir(parents=True, exist_ok=True)
    Path(env["APPDATA"]).mkdir(parents=True, exist_ok=True)
    return env


def start_process(command: list[str], cwd: Path, env: dict[str, str]) -> subprocess.Popen[str]:
    kwargs: dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], text=True, capture_output=True, timeout=10)
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def command_failure_message(result: CommandResult) -> str:
    return (
        f"command exited {result.returncode}: {command_label(result.command)}\n"
        f"stdout:\n{redact(result.stdout[-3000:])}\n"
        f"stderr:\n{redact(result.stderr[-3000:])}"
    )


def command_label(command: Iterable[str]) -> str:
    return " ".join(str(part) for part in command)


def command_slug(command: list[str]) -> str:
    return "-".join(Path(part).name if "/" in part or "\\" in part else part for part in command[:4]).replace(" ", "-")[:80]


def redact(text: str) -> str:
    redacted = text
    redacted = __import__("re").sub(r"(FLAG|CTF|SENTINEL)\{[^}\s]*\}", "[redacted]", redacted, flags=__import__("re").IGNORECASE)
    redacted = __import__("re").sub(r"(?i)(password|token|session|secret|flag)(\s*[=:]\s*)([^\s,;}\]]+)", r"\1\2[redacted]", redacted)
    return redacted


def safe_project_name(label: str, port: int) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in label).strip("-")
    return f"sentinel-aml-{safe[:24]}-{port}"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise AcceptanceFailure(f"missing {label}: {path}")


def aggregate(statuses: Iterable[str]) -> str:
    return "fail" if any(status != "pass" for status in statuses) else "pass"


def rel_or_abs(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--player-artifact", type=Path, default=DEFAULT_PLAYER_ARTIFACT)
    parser.add_argument("--admin-artifact", type=Path, default=DEFAULT_ADMIN_ARTIFACT)
    parser.add_argument("--validation-root", type=Path, default=DEFAULT_VALIDATION_ROOT)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY_OUTPUT)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    summary = run_acceptance(
        player_artifact=args.player_artifact,
        admin_artifact=args.admin_artifact,
        validation_root=args.validation_root,
        summary_output=args.summary_output,
        python=args.python,
        go=args.go,
        docker=args.docker,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
