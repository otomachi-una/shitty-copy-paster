#!/usr/bin/env python3
"""Run checker, sploit, and reference-fix matrix against exact artifacts."""

from __future__ import annotations

import argparse
import dataclasses
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
from pathlib import Path
from typing import Any, Iterable


PLAYER_ROOT = "sentinel-aml-player-source"
ADMIN_ROOT = "sentinel-aml-admin-organizer"
CHECKER_OK = 101
SUMMARY_SCHEMA = "sentinel-aml-exact-artifact-checker-sploit-fix-matrix.v1"


@dataclasses.dataclass(frozen=True)
class MatrixCase:
    aml_id: str
    place: int
    flag_store: str
    sploit: str
    fix_patch: str
    expected_path: str


@dataclasses.dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float


AML_CASES: tuple[MatrixCase, ...] = (
    MatrixCase("AML-1", 1, "CaseNote.body", "sploits/sentinel_aml/aml_dedup_preview.py", "fixes/sentinel_aml/aml_dedup_preview.patch", "/api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview"),
    MatrixCase("AML-2", 1, "CaseNote.body", "sploits/sentinel_aml/aml_audit_timeline.py", "fixes/sentinel_aml/aml_audit_timeline.patch", "/api/entities/{entity_hint}/activity"),
    MatrixCase("AML-3", 2, "EDDRecord.confidential_comment", "sploits/sentinel_aml/aml_related_graph.py", "fixes/sentinel_aml/aml_related_graph.patch", "/api/graph/entities/{entity_hint}/edd-summaries"),
    MatrixCase("AML-4", 1, "CaseNote.body", "sploits/sentinel_aml/aml_export_redaction.py", "fixes/sentinel_aml/aml_export_redaction.patch", "/api/exports/{export_id}"),
    MatrixCase("AML-5", 2, "EDDRecord.confidential_comment", "sploits/sentinel_aml/aml_network_room.py", "fixes/sentinel_aml/aml_network_room.patch", "/api/network/rooms/{room_id}/dossier"),
)

GO_FILE_RENAMES = {
    "internal/exporting/export_profile_linked_case.go": "internal/exporting/export_linked_evidence.go",
    "internal/graph/repository_entity_review.go": "internal/graph/repository_entity_summaries.go",
    "internal/httpapi/audit_profile_detail.go": "internal/httpapi/activity_views.go",
    "internal/httpapi/dedup_profile_case_match.go": "internal/httpapi/dedup_merge_preview.go",
    "internal/httpapi/export_profile_linked_case.go": "internal/httpapi/export_linked_cases.go",
    "internal/httpapi/graph_profile_entity_review.go": "internal/httpapi/entity_review_summaries.go",
    "internal/httpapi/network_room_profile_detail.go": "internal/httpapi/network_room_context.go",
    "internal/networkroom/dossier_profile_room_detail.go": "internal/networkroom/dossier_context.go",
    "internal/networkroom/repository_room_detail.go": "internal/networkroom/repository_context.go",
}
TEXT_REPLACEMENTS = {
    "caseMatchPreviewProfileEnabled": "caseMatchPreviewAvailable",
    "auditDetailProfileEnabled": "auditActivityViewsAvailable",
    "entityReviewSummaryProfileEnabled": "entityReviewSummariesAvailable",
    "linkedCaseExportProfileEnabled": "linkedCaseExportAvailable",
    "networkRoomDetailProfileEnabled": "networkRoomContextAvailable",
    "caseAuditViewsForProfile": "caseAuditViewsForActivityStream",
    "entityActivityViewsForProfile": "entityActivityViewsForActivityStream",
    "graphEDDSummariesResponseForProfile": "graphEDDSummariesResponseForEntityReview",
    "networkRoomDossierResponseForProfile": "networkRoomDossierResponseForSharedRoom",
    "populateExportLinkedCaseProfileData": "populateExportLinkedCaseData",
    "appendExportProfileData": "appendExportLinkedCaseData",
    "cloneExportProfileMaps": "cloneExportLinkedEvidenceMaps",
}


class MatrixFailure(RuntimeError):
    pass


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
            self.phases.append({"name": name, "status": "timeout", "elapsed_seconds": round(elapsed, 3), "timeout_seconds": timeout, "command": safe_command(command)})
            raise MatrixFailure(f"{name} timed out after {timeout:.0f}s") from exc
        except OSError as exc:
            elapsed = time.monotonic() - started
            self.phases.append({"name": name, "status": "fail", "elapsed_seconds": round(elapsed, 3), "command": safe_command(command), "message": str(exc)})
            raise MatrixFailure(f"{name} failed to start: {exc}") from exc

        elapsed = time.monotonic() - started
        result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr, elapsed)
        ok = result.returncode in expected_exit_codes
        phase = {
            "name": name,
            "status": "pass" if ok else "fail",
            "exit_code": result.returncode,
            "elapsed_seconds": round(elapsed, 3),
            "timeout_seconds": timeout,
            "command": safe_command(command),
        }
        if not ok:
            phase["stdout_tail"] = redact(result.stdout[-1200:])
            phase["stderr_tail"] = redact(result.stderr[-1200:])
        self.phases.append(phase)
        if check and not ok:
            raise MatrixFailure(command_failure_message(result))
        return result


class PlayerCompose:
    def __init__(self, player_root: Path, *, docker: str, recorder: PhaseRecorder, label: str) -> None:
        self.player_root = player_root
        self.docker = docker
        self.recorder = recorder
        self.api_port = free_port()
        self.ui_port = free_port()
        self.project = safe_project_name(label, self.api_port)
        self.env = os.environ.copy()
        self.env["SENTINEL_AML_API_PORT"] = str(self.api_port)
        self.env["SENTINEL_AML_HTTP_PORT"] = str(self.ui_port)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    def __enter__(self) -> "PlayerCompose":
        self.compose("config", timeout=45)
        for service in ("aml-migrate", "aml-api", "aml-worker", "aml-ui"):
            self.compose("build", "--no-cache", service, timeout=420)
        self.compose("up", "--no-build", "-d", timeout=180)
        wait_for_http(self.base_url + "/readyz", '"status":"ok"', timeout=120)
        wait_for_http(f"http://127.0.0.1:{self.ui_port}/", "Sentinel AML", timeout=120)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.compose("down", "--remove-orphans", "-v", timeout=120, check=False)

    def compose(self, *args: str, timeout: float, check: bool = True) -> CommandResult:
        return self.recorder.run(
            f"compose-{'-'.join(args[:2])}",
            [self.docker, "compose", "-p", self.project, *args],
            cwd=self.player_root,
            env=self.env,
            timeout=timeout,
            check=check,
        )


def check_exact_artifact_checker_sploit_fix_matrix(
    player_artifact: Path,
    admin_artifact: Path,
    *,
    validation_root: Path | None = None,
    python: str = sys.executable,
    docker: str = "docker",
    run_live: bool = True,
) -> dict[str, Any]:
    started = time.monotonic()
    recorder = PhaseRecorder()
    validation_root = validation_root or Path(tempfile.mkdtemp(prefix="sentinel-aml-exact-matrix."))
    summary: dict[str, Any] = {
        "schema": SUMMARY_SCHEMA,
        "status": "fail",
        "artifact_first": True,
        "repo_path_fallback": False,
        "artifacts": {
            "player": artifact_record(player_artifact),
            "admin": artifact_record(admin_artifact),
        },
        "checker": {"status": "not-run"},
        "flag_stores": {"status": "not-run"},
        "sploits": {"status": "not-run", "rows": []},
        "fixes": {"status": "not-run", "rows": []},
        "cleanup": {"attempted": False, "status": "not-run"},
        "phases": recorder.phases,
    }
    try:
        if player_artifact.is_dir() or admin_artifact.is_dir():
            raise MatrixFailure("inputs must be transfer tar.gz artifacts, not repository or extracted directories")
        clean_dir(validation_root)
        extracted = extract_artifacts(player_artifact, admin_artifact, validation_root)
        preflight = static_preflight(extracted["player"], extracted["admin"])
        summary["preflight"] = preflight
        if preflight["status"] != "pass":
            raise MatrixFailure("exact artifact matrix preflight failed")
        if not run_live:
            summary["status"] = "external-required"
            summary["external_required"] = "live Docker checker/sploit/fix matrix was not requested"
            return summary
        docker_status = docker_available(docker)
        summary["docker"] = docker_status
        if docker_status["status"] != "pass":
            summary["status"] = "external-required"
            summary["external_required"] = docker_status["message"]
            return summary
        runtime = run_vulnerable_runtime(extracted["player"], extracted["admin"], python=python, docker=docker, recorder=recorder)
        fixes = run_fixed_runtime(extracted["player"], extracted["admin"], validation_root / "fixed-player-source", python=python, docker=docker, recorder=recorder)
        summary.update(runtime)
        summary["fixes"] = fixes
        summary["status"] = aggregate([runtime["checker"]["status"], runtime["flag_stores"]["status"], runtime["sploits"]["status"], fixes["status"]])
    except Exception as exc:
        if summary["status"] != "external-required":
            summary["status"] = "fail"
        summary["error"] = redact(str(exc))
    finally:
        summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
        summary["phases"] = recorder.phases
        summary["cleanup"] = cleanup_validation_root(validation_root)
    return summary


def static_preflight(player_root: Path, admin_root: Path) -> dict[str, Any]:
    required = [
        *(f"sploits/sentinel_aml/{item.sploit.rsplit('/', 1)[1]}" for item in AML_CASES),
        *(f"fixes/sentinel_aml/{item.fix_patch.rsplit('/', 1)[1]}" for item in AML_CASES),
        "checkers/sentinel_aml/checker.py",
        "checkers/sentinel_aml/checker_lib.py",
        "README_ADMIN.md",
    ]
    missing = [path for path in required if not (admin_root / path).is_file()]
    player_required = ["Dockerfile", "docker-compose.yml", "Makefile", "cmd/aml-api/main.go", "internal/httpapi/server.go"]
    missing.extend(f"player:{path}" for path in player_required if not (player_root / path).is_file())
    return {
        "status": "pass" if not missing else "fail",
        "missing": missing,
        "sploit_count": len(AML_CASES),
        "fix_count": len(AML_CASES),
        "source": "extracted exact player/admin artifacts",
    }


def run_vulnerable_runtime(player_root: Path, admin_root: Path, *, python: str, docker: str, recorder: PhaseRecorder) -> dict[str, Any]:
    checker_status = {"status": "pass", "check": "pass", "havoc": "pass", "noise_lifecycle": "not-run"}
    sploit_rows: list[dict[str, Any]] = []
    stores: dict[str, dict[str, Any]] = {}
    with PlayerCompose(player_root, docker=docker, recorder=recorder, label="p06-player") as service:
        checker(admin_root, python, "check", service.base_url, recorder=recorder, phase_name="checker-check")
        checker(admin_root, python, "havoc", service.base_url, recorder=recorder, phase_name="checker-havoc")
        noise = optional_checker(admin_root, python, "putnoise", service.base_url, "p06", recorder=recorder, phase_name="checker-putnoise")
        if noise.returncode == CHECKER_OK:
            getnoise = optional_checker(admin_root, python, "getnoise", service.base_url, noise.stderr.strip(), recorder=recorder, phase_name="checker-getnoise")
            checker_status["noise_lifecycle"] = "pass" if getnoise.returncode == CHECKER_OK else f"not-available: exit={getnoise.returncode}"
        else:
            checker_status["noise_lifecycle"] = f"not-available: exit={noise.returncode}"
        for item in AML_CASES:
            flag = f"SENTINEL{{P06_{item.aml_id.replace('-', '_')}_{time.time_ns()}}}"
            secret = f"p06-{item.aml_id}-{time.time_ns()}"
            put = checker(admin_root, python, "put", service.base_url, flag, str(item.place), secret=secret, recorder=recorder, phase_name=f"{item.aml_id}-checker-put")
            private_state = put.stderr.strip()
            attack_data = normalize_attack_data(item, json.loads(put.stdout))
            assert_public_attack_data_safe(attack_data)
            sploit = run_sploit(admin_root, python, item, service.api_port, attack_data, recorder=recorder, phase_name=f"{item.aml_id}-sploit")
            assert_sploit_extracts(sploit, flag, item)
            checker(admin_root, python, "get", service.base_url, private_state, flag, str(item.place), secret=secret, recorder=recorder, phase_name=f"{item.aml_id}-checker-get")
            checker(admin_root, python, "check", service.base_url, secret=secret, recorder=recorder, phase_name=f"{item.aml_id}-checker-check-after")
            sploit_rows.append({"aml": item.aml_id, "place": item.place, "flag_store": item.flag_store, "status": "pass", "sploit": item.sploit, "flag_sha256": sha256_text(flag), "expected_path": item.expected_path})
            stores[item.flag_store] = {"status": "pass", "place": item.place}
    return {
        "checker": checker_status,
        "flag_stores": {"status": "pass" if {"CaseNote.body", "EDDRecord.confidential_comment"} <= set(stores) else "fail", "stores": stores},
        "sploits": {"status": "pass", "expected_count": len(AML_CASES), "passed_count": len(sploit_rows), "rows": sploit_rows},
    }


def run_fixed_runtime(player_root: Path, admin_root: Path, fixed_root: Path, *, python: str, docker: str, recorder: PhaseRecorder) -> dict[str, Any]:
    clean_dir(fixed_root)
    shutil.copytree(player_root, fixed_root, dirs_exist_ok=True)
    prepare_patchable_player_source(fixed_root)
    remapped: list[str] = []
    for item in AML_CASES:
        patch = remap_patch((admin_root / item.fix_patch).read_text(encoding="utf-8"))
        patch_path = fixed_root.parent / f"{Path(item.fix_patch).stem}.player-source.patch"
        patch_path.write_text(patch, encoding="utf-8")
        patch_arg = str(patch_path.resolve())
        recorder.run(f"{item.aml_id}-fix-apply-check", git_apply_command(patch_arg, check=True), cwd=fixed_root, timeout=30)
        recorder.run(f"{item.aml_id}-fix-apply", git_apply_command(patch_arg, check=False), cwd=fixed_root, timeout=30)
        remapped.append(item.fix_patch)
    rows: list[dict[str, Any]] = []
    with PlayerCompose(fixed_root, docker=docker, recorder=recorder, label="p06-fixed") as service:
        checker(admin_root, python, "check", service.base_url, recorder=recorder, phase_name="fixed-checker-check")
        for item in AML_CASES:
            flag = f"SENTINEL{{P06_FIXED_{item.aml_id.replace('-', '_')}_{time.time_ns()}}}"
            secret = f"p06-fixed-{item.aml_id}-{time.time_ns()}"
            put = checker(admin_root, python, "put", service.base_url, flag, str(item.place), secret=secret, recorder=recorder, phase_name=f"{item.aml_id}-fixed-checker-put")
            private_state = put.stderr.strip()
            attack_data = normalize_attack_data(item, json.loads(put.stdout))
            sploit = run_sploit(admin_root, python, item, service.api_port, attack_data, recorder=recorder, phase_name=f"{item.aml_id}-fixed-sploit-blocked", expected_exit_codes=(1,))
            assert_sploit_blocked(sploit, flag, item)
            checker(admin_root, python, "get", service.base_url, private_state, flag, str(item.place), secret=secret, recorder=recorder, phase_name=f"{item.aml_id}-fixed-checker-get")
            checker(admin_root, python, "check", service.base_url, secret=secret, recorder=recorder, phase_name=f"{item.aml_id}-fixed-checker-check-after")
            rows.append({"aml": item.aml_id, "place": item.place, "flag_store": item.flag_store, "status": "pass", "fix_patch": item.fix_patch, "sploit_exit": sploit.returncode})
    return {"status": "pass", "expected_count": len(AML_CASES), "passed_count": len(rows), "patches_applied": remapped, "rows": rows}


def checker(admin_root: Path, python: str, action: str, base_url: str, *args: str, recorder: PhaseRecorder, phase_name: str, secret: str | None = None) -> CommandResult:
    env = os.environ.copy()
    env["SENTINEL_AML_CHECKER_SECRET"] = secret or f"p06-checker-{action}-{time.time_ns()}"
    checker_path = (admin_root / "checkers" / "sentinel_aml" / "checker.py").resolve()
    result = recorder.run(
        phase_name,
        [python, str(checker_path), action, base_url, *args],
        cwd=admin_root,
        env=env,
        timeout=75,
        check=False,
        expected_exit_codes=(CHECKER_OK,),
    )
    if result.returncode != CHECKER_OK:
        raise MatrixFailure(command_failure_message(result))
    return result


def optional_checker(admin_root: Path, python: str, action: str, base_url: str, *args: str, recorder: PhaseRecorder, phase_name: str) -> CommandResult:
    env = os.environ.copy()
    env["SENTINEL_AML_CHECKER_SECRET"] = f"p06-optional-{action}-{time.time_ns()}"
    checker_path = (admin_root / "checkers" / "sentinel_aml" / "checker.py").resolve()
    result = recorder.run(
        phase_name,
        [python, str(checker_path), action, base_url, *args],
        cwd=admin_root,
        env=env,
        timeout=75,
        check=False,
        expected_exit_codes=(CHECKER_OK, 102, 103, 104, 110),
    )
    if result.returncode != CHECKER_OK and recorder.phases:
        recorder.phases[-1]["status"] = "not-available"
    return result


def run_sploit(admin_root: Path, python: str, item: MatrixCase, port: int, attack_data: dict[str, Any], *, recorder: PhaseRecorder, phase_name: str, expected_exit_codes: tuple[int, ...] = (0,)) -> CommandResult:
    sploit_path = (admin_root / item.sploit).resolve()
    return recorder.run(
        phase_name,
        [python, str(sploit_path), "127.0.0.1", str(port), json.dumps(attack_data, sort_keys=True), "--timeout", "8"],
        cwd=admin_root,
        timeout=75,
        check=False,
        expected_exit_codes=expected_exit_codes,
    )


def remap_patch(text: str) -> str:
    remapped = text
    for old, new in GO_FILE_RENAMES.items():
        remapped = remapped.replace(old, new)
    for old, new in TEXT_REPLACEMENTS.items():
        remapped = remapped.replace(old, new)
    return remapped


def git_apply_command(patch_path: str, *, check: bool) -> list[str]:
    command = ["git", "apply"]
    if check:
        command.append("--check")
    command.extend(["--whitespace=nowarn", "--ignore-whitespace", "--exclude=*_test.go", patch_path])
    return command


def prepare_patchable_player_source(player_root: Path) -> None:
    path = player_root / "internal/networkroom/repository_context.go"
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if text.startswith("package "):
        text = "\n" + text
    path.write_text(text, encoding="utf-8", newline="\n")


def normalize_attack_data(item: MatrixCase, attack_data: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(attack_data)
    if item.aml_id == "AML-2" and not (
        str(normalized.get("entity_ref", "")).strip() or str(normalized.get("party_ref", "")).strip()
    ):
        raise MatrixFailure("AML-2 public attack data lacks entity_ref or party_ref")
    return normalized


def extract_artifacts(player_artifact: Path, admin_artifact: Path, validation_root: Path) -> dict[str, Path]:
    player_extract = validation_root / "player"
    admin_extract = validation_root / "admin"
    safe_extract(player_artifact, player_extract, PLAYER_ROOT)
    safe_extract(admin_artifact, admin_extract, ADMIN_ROOT)
    return {"player": player_extract / PLAYER_ROOT, "admin": admin_extract / ADMIN_ROOT}


def safe_extract(archive_path: Path, destination: Path, expected_root: str) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination_resolved = destination.resolve()
    with gzip.open(archive_path, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        for member in archive.getmembers():
            if not member.name.startswith(f"{expected_root}/"):
                raise MatrixFailure(f"unexpected archive root in {archive_path}: {member.name}")
            target = (destination / member.name).resolve()
            try:
                target.relative_to(destination_resolved)
            except ValueError as exc:
                raise MatrixFailure(f"unsafe archive member path: {member.name}") from exc
        archive.extractall(destination)


def docker_available(docker: str) -> dict[str, str]:
    if shutil.which(docker) is None:
        return {"status": "external-required", "message": f"{docker!r} executable was not found"}
    for command in ([docker, "--version"], [docker, "compose", "version"], [docker, "info"]):
        try:
            completed = subprocess.run(command, text=True, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "external-required", "message": f"{' '.join(command)} unavailable: {exc}"}
        if completed.returncode != 0:
            return {"status": "external-required", "message": f"{' '.join(command)} exited {completed.returncode}: {redact((completed.stderr or completed.stdout).strip())}"}
    return {"status": "pass", "message": "docker, compose plugin, and daemon are available"}


def assert_sploit_extracts(result: CommandResult, flag: str, item: MatrixCase) -> None:
    if result.returncode != 0:
        raise MatrixFailure(f"{item.aml_id} sploit did not exit 0")
    if flag not in result.stdout:
        raise MatrixFailure(f"{item.aml_id} sploit did not print expected token")


def assert_sploit_blocked(result: CommandResult, flag: str, item: MatrixCase) -> None:
    if flag in result.stdout:
        raise MatrixFailure(f"{item.aml_id} fixed runtime still exposed the protected value")
    if result.returncode == 0:
        raise MatrixFailure(f"{item.aml_id} fixed runtime sploit exited 0; expected blocked extraction failure")


def assert_public_attack_data_safe(attack_data: dict[str, Any]) -> None:
    serialized = json.dumps(attack_data, sort_keys=True).lower()
    leaked = [
        marker
        for marker in (
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
        if marker in serialized
    ]
    if leaked:
        raise MatrixFailure("checker public attack data leaked forbidden markers: " + ", ".join(leaked))


def wait_for_http(url: str, marker: str, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                body = response.read().decode("utf-8", errors="ignore")
                if response.status == 200 and marker in body:
                    return
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(1)
    raise MatrixFailure(f"HTTP endpoint did not become ready: {url}: {last_error}")


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def cleanup_validation_root(path: Path) -> dict[str, Any]:
    try:
        if path.exists():
            shutil.rmtree(path)
        return {"attempted": True, "status": "pass", "path": path.as_posix()}
    except OSError as exc:
        return {"attempted": True, "status": "fail", "path": path.as_posix(), "message": str(exc)}


def artifact_record(path: Path) -> dict[str, Any]:
    return {
        "path": path.as_posix(),
        "sha256": sha256_file(path) if path.is_file() else None,
        "size_bytes": path.stat().st_size if path.is_file() else None,
    }


def aggregate(statuses: Iterable[str]) -> str:
    return "fail" if any(status != "pass" for status in statuses) else "pass"


def command_failure_message(result: CommandResult) -> str:
    return f"command exited {result.returncode}: {' '.join(safe_command(result.command))}\nstdout:\n{redact(result.stdout[-1200:])}\nstderr:\n{redact(result.stderr[-1200:])}"


def safe_command(command: list[str]) -> list[str]:
    safe = [str(part) for part in command]
    if len(safe) >= 4 and safe[2] in {"put", "get"} and safe[1].endswith("checker.py"):
        if safe[2] == "put":
            safe[-2] = "[redacted]"
        if safe[2] == "get":
            safe[-3] = "[redacted]"
            safe[-2] = "[redacted]"
    if len(safe) >= 4 and safe[2] == "getnoise" and safe[1].endswith("checker.py"):
        safe[-1] = "[redacted]"
    return [redact(part) for part in safe]


def redact(text: str) -> str:
    redacted = re.sub(r"(?i)(FLAG|CTF|SENTINEL)\{[^}\s]*\}", "[redacted]", text)
    redacted = re.sub(r"(?i)(password|token|session|secret|flag|private_state)(\s*[=:]\s*)([^\s,;}\]]+)", r"\1\2[redacted]", redacted)
    return redacted


def safe_project_name(label: str, port: int) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in label).strip("-")
    return f"sentinel-aml-{safe[:24]}-{port}"


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


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--player-artifact", type=Path, required=True)
    parser.add_argument("--admin-artifact", type=Path, required=True)
    parser.add_argument("--validation-root", type=Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--json-report", type=Path)
    parser.add_argument("--static-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = check_exact_artifact_checker_sploit_fix_matrix(
        args.player_artifact,
        args.admin_artifact,
        validation_root=args.validation_root,
        python=args.python,
        docker=args.docker,
        run_live=not args.static_only,
    )
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
