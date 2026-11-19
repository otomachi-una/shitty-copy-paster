#!/usr/bin/env python3
"""Validate and run the Wave 33 packaging/productization regression gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, TextIO

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from run_go_release_tests import Runner, release_env, run_command


MAKE_TARGET = "wave33-gate"
ARTIFACT_FIRST_MAKE_TARGET = "artifact-first-gate"
DEFAULT_GATE_TIMEOUT = 285.0
DEFAULT_ARTIFACT_FIRST_SUMMARY = Path("out") / "artifact-first-validation-summary.json"
ARTIFACT_OUTPUT_ROOT = Path("out")
PLAYER_ARTIFACT = ARTIFACT_OUTPUT_ROOT / "artifacts" / "sentinel-aml-player-service.tar.gz"
PLAYER_SOURCE_ARTIFACT = ARTIFACT_OUTPUT_ROOT / "artifacts" / "sentinel-aml-player-source.tar.gz"
ADMIN_ARTIFACT = ARTIFACT_OUTPUT_ROOT / "artifacts" / "sentinel-aml-admin-organizer.tar.gz"
PLAYER_MANIFEST = ARTIFACT_OUTPUT_ROOT / "manifests" / "player_manifest.json"
PLAYER_SOURCE_MANIFEST = ARTIFACT_OUTPUT_ROOT / "manifests" / "player_source_manifest.json"
ADMIN_MANIFEST = ARTIFACT_OUTPUT_ROOT / "manifests" / "admin_manifest.json"
CHECKSUMS_FILE = ARTIFACT_OUTPUT_ROOT / "checksums" / "SHA256SUMS"
GO_PACKAGE_TIMEOUT = "60"
PLAYER_CANDIDATE = "tmp/wave33-player-service-candidate"
PLAYER_ALLOWLIST = "tmp/wave33-player-service-candidate.hygiene-allowlist.json"
ADMIN_CANDIDATE = "tmp/wave33-admin-checker-candidate"
GENERATED_CANDIDATE_PATHS = (
    PLAYER_CANDIDATE,
    PLAYER_ALLOWLIST,
    ADMIN_CANDIDATE,
)
EXPECTED_EXPLOITS = (
    "sploits/sentinel_aml/aml_dedup_preview.py",
    "sploits/sentinel_aml/aml_audit_timeline.py",
    "sploits/sentinel_aml/aml_related_graph.py",
    "sploits/sentinel_aml/aml_export_redaction.py",
    "sploits/sentinel_aml/aml_network_room.py",
)
EXPECTED_PATCHES = (
    "fixes/sentinel_aml/aml_dedup_preview.patch",
    "fixes/sentinel_aml/aml_audit_timeline.patch",
    "fixes/sentinel_aml/aml_related_graph.patch",
    "fixes/sentinel_aml/aml_export_redaction.patch",
    "fixes/sentinel_aml/aml_network_room.patch",
)
FORBIDDEN_ARCHIVE_MARKERS = (
    "release-archive",
    "build_release_archive.py",
    "final manifest",
    "checksum",
)
REQUIRED_REPORTS = (
    "docs/wave_reports/wave_33_packaging_boundary.md",
    "docs/wave_reports/wave_33_leak_scanner.md",
    "docs/wave_reports/wave_33_source_productization.md",
    "docs/wave_reports/wave_33_bundle_split.md",
    "docs/wave_reports/wave_33_player_docs.md",
)
BANNED_PLAYER_DOC_PATTERN = re.compile(
    r"aml-[1-5]|aml[1-5]|checker|flag|flag store|exploit|sploit|fixes|anti-aml|wave|internal gate|"
    r"attack_info|public_attack_data|LEAK_TARGET|MUST_NOT_LEAK|checker_secret|vulnerable",
    re.IGNORECASE,
)


def validate_wave33_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_makefile_target(repo_root),
        check_wave33_files(repo_root),
        check_phase_plan(repo_root),
        check_player_docs_clean(repo_root),
        check_candidate_builder_policy(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def validate_artifact_first_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_artifact_first_makefile_target(repo_root),
        check_artifact_first_files(repo_root),
        check_artifact_first_phase_plan(repo_root),
        check_artifact_first_docs(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def command_phase_specs(python: str, go: str, *, cache_dir: str | None = None, appdata_dir: str | None = None) -> list[dict[str, Any]]:
    phases: list[dict[str, Any]] = [
        {
            "name": "wave33-static-tests",
            "command": [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_wave33_gate.py"],
            "timeout": 60,
            "env": "python",
        },
        {
            "name": "player-candidate-tests",
            "command": [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_player_bundle*.py"],
            "timeout": 60,
            "env": "python",
        },
        {
            "name": "repository-submission-hygiene-strict",
            "command": [python, "-B", "scripts/check_repository_submission_hygiene.py"],
            "timeout": 30,
            "env": "python",
        },
        {
            "name": "player-candidate-build",
            "command": [
                python,
                "-B",
                "scripts/build_player_bundle.py",
                "--output-dir",
                PLAYER_CANDIDATE,
                "--allowlist-out",
                PLAYER_ALLOWLIST,
            ],
            "timeout": 30,
            "env": "python",
        },
        {
            "name": "admin-candidate-build",
            "command": [python, "-B", "scripts/build_admin_bundle.py", "--output-dir", ADMIN_CANDIDATE],
            "timeout": 30,
            "env": "python",
        },
        {
            "name": "repository-submission-hygiene-local-staging",
            "command": [python, "-B", "scripts/check_repository_submission_hygiene.py", "--allow-wave33-local-candidates"],
            "timeout": 30,
            "env": "python",
        },
        {
            "name": "player-candidate-hygiene",
            "command": [
                python,
                "-B",
                "scripts/check_player_bundle_hygiene.py",
                PLAYER_CANDIDATE,
                "--allowlist",
                PLAYER_ALLOWLIST,
            ],
            "timeout": 30,
            "env": "python",
        },
        {
            "name": "participant-doc-hygiene",
            "command": [python, "-B", "scripts/check_player_bundle_hygiene.py", "packaging/player"],
            "timeout": 30,
            "env": "python",
        },
        {
            "name": "checker-tests",
            "command": [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_checker_*.py"],
            "timeout": 60,
            "env": "python",
        },
        {
            "name": "competition-matrix-tests",
            "command": [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_competition_matrix_gate.py"],
            "timeout": 60,
            "env": "python",
        },
        {
            "name": "competition-matrix-gate",
            "command": [python, "-B", "scripts/check_competition_matrix_gate.py"],
            "timeout": 30,
            "env": "python",
        },
    ]
    phases.extend(
        {
            "name": f"sploit-syntax:{relative}",
            "command": [python, "-B", "-m", "py_compile", relative],
            "timeout": 20,
            "env": "python",
        }
        for relative in EXPECTED_EXPLOITS
    )
    phases.extend(
        {
            "name": f"fix-patch-check:{relative}",
            "command": ["git", "apply", "--check", "--whitespace=error", relative],
            "timeout": 20,
            "env": "ambient",
        }
        for relative in EXPECTED_PATCHES
    )
    phases.extend(
        [
            {
                "name": "vulnerable-profile-runner",
                "command": shared_go_runner_command(
                    python,
                    "scripts/run_vulnerable_profile_tests.py",
                    go=go,
                    cache_dir=cache_dir,
                    appdata_dir=appdata_dir,
                ),
                "timeout": 180,
                "env": "python",
            },
            {
                "name": "release-profile-go-tests",
                "command": shared_go_runner_command(
                    python,
                    "scripts/run_go_release_tests.py",
                    go=go,
                    cache_dir=cache_dir,
                    appdata_dir=appdata_dir,
                ),
                "timeout": 150,
                "env": "python",
            },
            {
                "name": "go-vet",
                "command": [go, "vet", "./..."],
                "timeout": 60,
                "env": "go",
            },
            {
                "name": "go-build",
                "command": [go, "build", "./cmd/aml-api", "./cmd/aml-worker"],
                "timeout": 60,
                "env": "go",
            },
            {
                "name": "docs-tree",
                "command": [python, "-B", "scripts/check_docs_tree.py"],
                "timeout": 30,
                "env": "python",
            },
            {
                "name": "forcad-config",
                "command": [python, "-B", "scripts/validate_forcad_config.py"],
                "timeout": 30,
                "env": "python",
            },
            {
                "name": "cleanup-wave33-generated-candidates",
                "command": [
                    python,
                    "-B",
                    "scripts/check_wave33_gate.py",
                    "--cleanup-only",
                ],
                "timeout": 20,
                "env": "python",
            },
        ]
    )
    return phases


def artifact_first_phase_specs(
    python: str,
    go: str,
    *,
    docker: str,
    output_root: Path = ARTIFACT_OUTPUT_ROOT,
    repository_submission: Path | None = None,
) -> list[dict[str, Any]]:
    player_artifact = output_root / "artifacts" / PLAYER_ARTIFACT.name
    player_source_artifact = output_root / "artifacts" / PLAYER_SOURCE_ARTIFACT.name
    admin_artifact = output_root / "artifacts" / ADMIN_ARTIFACT.name
    player_manifest = output_root / "manifests" / PLAYER_MANIFEST.name
    phases: list[dict[str, Any]] = [
        {
            "name": "clean-generated",
            "command": [
                python,
                "-B",
                "scripts/check_repository_submission_hygiene.py",
                "--clean-generated",
                "--preserve-frontend-ui-build",
                ".",
            ],
            "timeout": 30,
            "env": "python",
            "artifact": "workspace",
        },
        {
            "name": "verify-frontend-ui-source-scan",
            "command": frontend_npm_command("security:scan:source"),
            "timeout": 30,
            "env": "ambient",
            "artifact": "player-service",
        },
        {
            "name": "verify-frontend-ui-dist-scan",
            "command": frontend_npm_command("security:scan:dist"),
            "timeout": 30,
            "env": "ambient",
            "artifact": "player-service",
        },
        {
            "name": "build-transfer-artifacts",
            "command": [python, "-B", "scripts/build_artifacts.py", "--output-root", str(output_root)],
            "timeout": 90,
            "env": "python",
            "artifact": "player-service admin-organizer",
        },
        {
            "name": "verify-artifact-inventory",
            "command": [python, "-B", "scripts/build_artifacts.py", "--output-root", str(output_root), "--verify-only"],
            "timeout": 30,
            "env": "python",
            "artifact": "transfer-artifacts",
        },
        {
            "name": "verify-player-source-manifest",
            "command": [python, "-B", "scripts/check_player_source_manifest.py", "--output-root", str(output_root)],
            "timeout": 30,
            "env": "python",
            "artifact": "player-source",
        },
        {
            "name": "verify-player-source-hygiene",
            "command": [python, "-B", "scripts/check_player_source_hygiene.py", str(player_source_artifact)],
            "timeout": 30,
            "env": "python",
            "artifact": "player-source",
        },
        {
            "name": "verify-side-view-lexicon",
            "command": [python, "-B", "scripts/check_side_view_lexicon.py", str(player_source_artifact), "--require-artifact"],
            "timeout": 30,
            "env": "python",
            "artifact": "player-source",
        },
        {
            "name": "verify-semantic-red-herrings",
            "command": [python, "-B", "scripts/check_semantic_red_herrings.py"],
            "timeout": 30,
            "env": "python",
            "artifact": "player-source",
        },
        {
            "name": "verify-player-artifact-hygiene",
            "command": [python, "-B", "scripts/check_player_bundle_hygiene.py", str(player_artifact)],
            "timeout": 30,
            "env": "python",
            "artifact": "player-service",
        },
        {
            "name": "verify-admin-artifact-hygiene",
            "command": [python, "-B", "scripts/check_admin_bundle_hygiene.py", str(admin_artifact)],
            "timeout": 30,
            "env": "python",
            "artifact": "admin-organizer",
        },
    ]
    if repository_submission is not None:
        phases.append(
            {
                "name": "verify-repository-submission-hygiene",
                "command": [python, "-B", "scripts/check_repository_submission_hygiene.py", str(repository_submission)],
                "timeout": 30,
                "env": "python",
                "artifact": "repository-submission",
            }
        )
    phases.extend(
        [
            {
                "name": "verify-player-ui-artifact",
                "command": [
                    python,
                    "-B",
                    "scripts/check_wave33_gate.py",
                    "--artifact-first-ui-check",
                    "--player-manifest",
                    str(player_manifest),
                ],
                "timeout": 20,
                "env": "python",
                "artifact": "player-service",
            },
            {
                "name": "verify-player-runtime-profile-evidence",
                "command": [
                    python,
                    "-B",
                    "scripts/check_competition_runtime_profile.py",
                    "--mode",
                    "binary",
                    "--player-manifest",
                    str(player_manifest),
                    "--player-artifact",
                    str(player_artifact),
                ],
                "timeout": 30,
                "env": "python",
                "artifact": "player-service",
            },
            {
                "name": "verify-admin-checker-sploit-fix-matrix-evidence",
                "command": [python, "-B", "scripts/check_competition_matrix_gate.py"],
                "timeout": 30,
                "env": "python",
                "artifact": "admin-organizer",
            },
            {
                "name": "verify-artifact-live-acceptance-binding",
                "command": [python, "-B", "scripts/check_artifact_first_live_acceptance.py", "--output-root", str(output_root)],
                "timeout": 30,
                "env": "python",
                "artifact": "transfer-artifacts",
            },
        ]
    )
    return phases


def run_gate(
    repo_root: Path,
    *,
    python: str,
    go: str,
    runner: Runner = run_command,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    gate_timeout: float = DEFAULT_GATE_TIMEOUT,
) -> int:
    validation = validate_wave33_gate(repo_root)
    print(json.dumps(validation, indent=2, sort_keys=True), file=stdout, flush=True)
    if validation["status"] != "pass":
        return 1

    started_gate = time.monotonic()
    gate_deadline = started_gate + gate_timeout
    with tempfile.TemporaryDirectory(prefix="sentinel-aml-wave33-gocache.") as cache_dir:
        with tempfile.TemporaryDirectory(prefix="sentinel-aml-wave33-appdata.") as appdata_dir:
            with tempfile.TemporaryDirectory(prefix="sentinel-aml-wave33-tools.") as tool_dir:
                prepare_tool_shims(Path(tool_dir), python)
                phases = command_phase_specs(python, go, cache_dir=cache_dir, appdata_dir=appdata_dir)
                print(
                    f"wave33-gate: starting {len(phases)} bounded phases gate_timeout={gate_timeout:.1f}s",
                    file=stdout,
                    flush=True,
                )
                print(f"wave33-gate: shared GOCACHE={cache_dir}", file=stdout, flush=True)
                print(f"wave33-gate: shared APPDATA={appdata_dir}", file=stdout, flush=True)
                for index, phase in enumerate(phases, start=1):
                    started = time.monotonic()
                    remaining = gate_deadline - started
                    if remaining <= 5:
                        total = started - started_gate
                        print(
                            f"wave33-gate: aggregate deadline reached before {phase['name']} elapsed={total:.3f}s",
                            file=stderr,
                            flush=True,
                        )
                        cleanup_generated_candidates(repo_root)
                        return 1
                    phase_timeout = min(float(phase["timeout"]), max(1.0, remaining - 2.0))
                    command = [str(part) for part in phase["command"]]
                    print(
                        f"wave33-gate: phase {index}/{len(phases)} start {phase['name']} timeout={phase_timeout:.1f}s remaining={remaining:.1f}s",
                        file=stdout,
                        flush=True,
                    )
                    print(f"wave33-gate: command {subprocess.list2cmdline(command)}", file=stdout, flush=True)
                    try:
                        completed = runner(
                            command,
                            cwd=repo_root,
                            env=phase_env(
                                str(phase["env"]),
                                cache_dir=cache_dir,
                                appdata_dir=appdata_dir,
                                tool_dir=tool_dir,
                            ),
                            timeout=phase_timeout,
                        )
                    except subprocess.TimeoutExpired as exc:
                        elapsed = time.monotonic() - started
                        print(f"wave33-gate: phase {phase['name']} timed out after {elapsed:.3f}s", file=stderr, flush=True)
                        if exc.output:
                            print(exc.output, end="" if str(exc.output).endswith("\n") else "\n", file=stdout, flush=True)
                        if exc.stderr:
                            print(exc.stderr, end="" if str(exc.stderr).endswith("\n") else "\n", file=stderr, flush=True)
                        cleanup_generated_candidates(repo_root)
                        return 1

                    if completed.stdout:
                        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n", file=stdout, flush=True)
                    if completed.stderr:
                        print(completed.stderr, end="" if completed.stderr.endswith("\n") else "\n", file=stderr, flush=True)
                    elapsed = time.monotonic() - started
                    print(
                        f"wave33-gate: phase {index}/{len(phases)} {phase['name']} exit={completed.returncode} elapsed={elapsed:.3f}s",
                        file=stdout,
                        flush=True,
                    )
                    if completed.returncode != 0:
                        total = time.monotonic() - started_gate
                        print(f"wave33-gate: failed after {total:.3f}s", file=stderr, flush=True)
                        cleanup_generated_candidates(repo_root)
                        return completed.returncode
    cleanup_generated_candidates(repo_root)
    total = time.monotonic() - started_gate
    print(f"wave33-gate: pass elapsed={total:.3f}s", file=stdout, flush=True)
    return 0


def run_artifact_first_gate(
    repo_root: Path,
    *,
    python: str,
    go: str,
    docker: str,
    output_root: Path = ARTIFACT_OUTPUT_ROOT,
    repository_submission: Path | None = None,
    summary_out: Path = DEFAULT_ARTIFACT_FIRST_SUMMARY,
    runner: Runner = run_command,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    gate_timeout: float = DEFAULT_GATE_TIMEOUT,
) -> int:
    validation = validate_artifact_first_gate(repo_root)
    print(json.dumps(validation, indent=2, sort_keys=True), file=stdout, flush=True)
    if validation["status"] != "pass":
        write_artifact_first_summary(
            repo_root,
            output_root=output_root,
            summary_out=summary_out,
            status="fail",
            started=time.monotonic(),
            phases=[],
            external_gates=artifact_first_external_gates(docker),
            message="static validation failed",
            gate_timeout=gate_timeout,
        )
        return 1

    started_gate = time.monotonic()
    deadline = started_gate + gate_timeout
    phases = artifact_first_phase_specs(
        python,
        go,
        docker=docker,
        output_root=output_root,
        repository_submission=repository_submission,
    )
    phase_results: list[dict[str, Any]] = []
    print(
        f"artifact-first-gate: starting {len(phases)} bounded phases gate_timeout={gate_timeout:.1f}s",
        file=stdout,
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix="sentinel-aml-artifact-first-pycache.") as pycache:
        for index, phase in enumerate(phases, start=1):
            started = time.monotonic()
            remaining = deadline - started
            if remaining <= 5:
                total = started - started_gate
                message = f"aggregate deadline reached before {phase['name']}"
                print(f"artifact-first-gate: {message} elapsed={total:.3f}s", file=stderr, flush=True)
                phase_results.append(phase_result(phase, "fail", elapsed=0.0, message=message))
                write_artifact_first_summary(
                    repo_root,
                    output_root=output_root,
                    summary_out=summary_out,
                    status="fail",
                    started=started_gate,
                    phases=phase_results,
                    external_gates=artifact_first_external_gates(docker),
                    message=message,
                    gate_timeout=gate_timeout,
                )
                return 1
            timeout = min(float(phase["timeout"]), max(1.0, remaining - 2.0))
            command = [str(part) for part in phase["command"]]
            print(
                f"artifact-first-gate: phase {index}/{len(phases)} start {phase['name']} artifact={phase['artifact']} timeout={timeout:.1f}s remaining={remaining:.1f}s",
                file=stdout,
                flush=True,
            )
            print(f"artifact-first-gate: command {subprocess.list2cmdline(command)}", file=stdout, flush=True)
            try:
                completed = runner(
                    command,
                    cwd=repo_root,
                    env=phase_env(str(phase["env"]), tool_dir=None, cache_dir=None, appdata_dir=None)
                    if str(phase["env"]) != "python"
                    else python_phase_env(pycache),
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as exc:
                elapsed = time.monotonic() - started
                message = f"timeout after {elapsed:.3f}s"
                print(f"artifact-first-gate: phase {phase['name']} timed out after {elapsed:.3f}s", file=stderr, flush=True)
                if exc.output:
                    print(exc.output, end="" if str(exc.output).endswith("\n") else "\n", file=stdout, flush=True)
                if exc.stderr:
                    print(exc.stderr, end="" if str(exc.stderr).endswith("\n") else "\n", file=stderr, flush=True)
                phase_results.append(phase_result(phase, "fail", elapsed=elapsed, message=message, exit_code=1))
                write_artifact_first_summary(
                    repo_root,
                    output_root=output_root,
                    summary_out=summary_out,
                    status="fail",
                    started=started_gate,
                    phases=phase_results,
                    external_gates=artifact_first_external_gates(docker),
                    message=message,
                    gate_timeout=gate_timeout,
                )
                return 1
            except OSError as exc:
                elapsed = time.monotonic() - started
                message = f"launch failed after {elapsed:.3f}s: {exc}"
                print(f"artifact-first-gate: phase {phase['name']} launch failed after {elapsed:.3f}s: {exc}", file=stderr, flush=True)
                phase_results.append(phase_result(phase, "fail", elapsed=elapsed, message=message, exit_code=1))
                write_artifact_first_summary(
                    repo_root,
                    output_root=output_root,
                    summary_out=summary_out,
                    status="fail",
                    started=started_gate,
                    phases=phase_results,
                    external_gates=artifact_first_external_gates(docker),
                    message=message,
                    gate_timeout=gate_timeout,
                )
                return 1

            if completed.stdout:
                print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n", file=stdout, flush=True)
            if completed.stderr:
                print(completed.stderr, end="" if completed.stderr.endswith("\n") else "\n", file=stderr, flush=True)
            elapsed = time.monotonic() - started
            print(
                f"artifact-first-gate: phase {index}/{len(phases)} {phase['name']} exit={completed.returncode} elapsed={elapsed:.3f}s",
                file=stdout,
                flush=True,
            )
            status = "pass" if completed.returncode == 0 else "fail"
            phase_results.append(phase_result(phase, status, elapsed=elapsed, exit_code=completed.returncode))
            if completed.returncode != 0:
                total = time.monotonic() - started_gate
                print(f"artifact-first-gate: failed after {total:.3f}s", file=stderr, flush=True)
                write_artifact_first_summary(
                    repo_root,
                    output_root=output_root,
                    summary_out=summary_out,
                    status="fail",
                    started=started_gate,
                    phases=phase_results,
                    external_gates=artifact_first_external_gates(docker),
                    message=f"{phase['name']} exit={completed.returncode}",
                    gate_timeout=gate_timeout,
                )
                return completed.returncode

    evidence = collect_artifact_evidence(repo_root, output_root)
    status = "pass" if artifact_evidence_complete(evidence) else "fail"
    summary_path = write_artifact_first_summary(
        repo_root,
        output_root=output_root,
        summary_out=summary_out,
        status=status,
        started=started_gate,
        phases=phase_results,
        external_gates=artifact_first_external_gates(docker),
        message="" if status == "pass" else "required artifact evidence missing",
        gate_timeout=gate_timeout,
        artifact_evidence=evidence,
    )
    total = time.monotonic() - started_gate
    print(f"artifact-first-gate: validation summary {summary_path}", file=stdout, flush=True)
    print(f"artifact-first-gate: {status} elapsed={total:.3f}s", file=stdout if status == "pass" else stderr, flush=True)
    return 0 if status == "pass" else 1


def python_phase_env(pycache: str) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPYCACHEPREFIX"] = pycache
    return env


def phase_result(
    phase: dict[str, Any],
    status: str,
    *,
    elapsed: float,
    exit_code: int | None = None,
    message: str = "",
) -> dict[str, Any]:
    return {
        "name": phase["name"],
        "artifact": phase["artifact"],
        "status": status,
        "exit_code": exit_code,
        "elapsed_seconds": round(elapsed, 3),
        "timeout_seconds": phase["timeout"],
        "message": message,
    }


def write_artifact_first_summary(
    repo_root: Path,
    *,
    output_root: Path,
    summary_out: Path,
    status: str,
    started: float,
    phases: list[dict[str, Any]],
    external_gates: list[dict[str, Any]],
    message: str,
    gate_timeout: float,
    artifact_evidence: dict[str, Any] | None = None,
) -> Path:
    if artifact_evidence is None:
        artifact_evidence = collect_artifact_evidence(repo_root, output_root)
    runtime_validation = artifact_first_runtime_validation(artifact_evidence, external_gates)
    summary_path = summary_out if summary_out.is_absolute() else repo_root / summary_out
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "schema": "sentinel-aml-artifact-first-gate.v1",
        "status": status,
        "message": message,
        "bounded_runtime_seconds": gate_timeout,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "phases": phases,
        "player_artifact_sha256": artifact_evidence.get("player_artifact", {}).get("sha256"),
        "player_source_artifact_sha256": artifact_evidence.get("player_source_artifact", {}).get("sha256"),
        "admin_artifact_sha256": artifact_evidence.get("admin_artifact", {}).get("sha256"),
        "artifact_evidence": artifact_evidence,
        "runtime_validation": runtime_validation,
        "external_gates": external_gates,
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary_path


def collect_artifact_evidence(repo_root: Path, output_root: Path) -> dict[str, Any]:
    paths = {
        "player_source_artifact": output_root / "artifacts" / PLAYER_SOURCE_ARTIFACT.name,
        "player_artifact": output_root / "artifacts" / PLAYER_ARTIFACT.name,
        "admin_artifact": output_root / "artifacts" / ADMIN_ARTIFACT.name,
        "player_source_manifest": output_root / "manifests" / PLAYER_SOURCE_MANIFEST.name,
        "player_manifest": output_root / "manifests" / PLAYER_MANIFEST.name,
        "admin_manifest": output_root / "manifests" / ADMIN_MANIFEST.name,
        "checksums": output_root / "checksums" / CHECKSUMS_FILE.name,
    }
    evidence: dict[str, Any] = {}
    for key, relative in paths.items():
        path = relative if relative.is_absolute() else repo_root / relative
        evidence[key] = {
            "path": relative.as_posix(),
            "exists": path.is_file(),
            "sha256": sha256_path(path) if path.is_file() else None,
            "size_bytes": path.stat().st_size if path.is_file() else None,
        }
    return evidence


def artifact_evidence_complete(evidence: dict[str, Any]) -> bool:
    return all(bool(item.get("exists")) for item in evidence.values())


def artifact_first_runtime_validation(
    artifact_evidence: dict[str, Any],
    external_gates: list[dict[str, Any]],
) -> dict[str, Any]:
    gate_by_name = {str(gate.get("name")): gate for gate in external_gates}
    runtime_smoke = gate_status(
        gate_by_name,
        "runtime-smoke-from-player-artifact",
        artifact="player_artifact",
        artifact_sha256=artifact_evidence.get("player_artifact", {}).get("sha256"),
    )
    checker = gate_status(
        gate_by_name,
        "checker-check-havoc-from-admin-artifact",
        artifact="admin_artifact",
        artifact_sha256=artifact_evidence.get("admin_artifact", {}).get("sha256"),
        required_modes=["CHECK", "HAVOC"],
    )
    sploit_matrix = gate_status(
        gate_by_name,
        "five-sploits-from-admin-artifact",
        artifact="admin_artifact",
        artifact_sha256=artifact_evidence.get("admin_artifact", {}).get("sha256"),
        expected_count=5,
    )
    fix_workflow = gate_status(
        gate_by_name,
        "five-fixes-accepted-workflow",
        artifact="admin_artifact",
        artifact_sha256=artifact_evidence.get("admin_artifact", {}).get("sha256"),
        expected_count=5,
    )
    matrix_status = gate_status(
        gate_by_name,
        "checker-sploit-fix-matrix-against-deployed-player-runtime",
        artifact="admin_artifact",
        artifact_sha256=artifact_evidence.get("admin_artifact", {}).get("sha256"),
    )
    return {
        "player_artifact_sha256": artifact_evidence.get("player_artifact", {}).get("sha256"),
        "admin_artifact_sha256": artifact_evidence.get("admin_artifact", {}).get("sha256"),
        "runtime_smoke": runtime_smoke,
        "checker_check_havoc": checker,
        "sploit_matrix": sploit_matrix,
        "fix_workflow": fix_workflow,
        "matrix_status": matrix_status,
    }


def gate_status(
    gate_by_name: dict[str, dict[str, Any]],
    name: str,
    **extra: Any,
) -> dict[str, Any]:
    gate = gate_by_name.get(name, {})
    result: dict[str, Any] = {
        "name": name,
        "status": gate.get("status", "external-required"),
        "reason": gate.get("reason", "Exact-artifact live validation was not run by this bounded local gate."),
    }
    if "docker_available" in gate:
        result["docker_available"] = gate["docker_available"]
    result.update(extra)
    return result


def artifact_first_external_gates(docker: str) -> list[dict[str, Any]]:
    docker_path = shutil.which(docker)
    reason = "Docker command is unavailable in this gate environment." if docker_path is None else "Requires a deployed player runtime; this bounded artifact gate records the live obligation without mutating deployment state."
    return [
        {
            "name": "runtime-smoke-from-player-artifact",
            "status": "external-required",
            "docker_available": docker_path is not None,
            "reason": reason,
        },
        {
            "name": "checker-check-havoc-from-admin-artifact",
            "status": "external-required",
            "docker_available": docker_path is not None,
            "reason": "Run CHECK and HAVOC from the admin artifact against the runtime deployed from the exact player artifact.",
        },
        {
            "name": "five-sploits-from-admin-artifact",
            "status": "external-required",
            "docker_available": docker_path is not None,
            "reason": "Run the five reference sploits from the admin artifact against the runtime deployed from the exact player artifact.",
        },
        {
            "name": "five-fixes-accepted-workflow",
            "status": "external-required",
            "docker_available": docker_path is not None,
            "reason": "Validate the five accepted fixes through the documented fix workflow against exact-artifact runtime evidence.",
        },
        {
            "name": "checker-sploit-fix-matrix-against-deployed-player-runtime",
            "status": "external-required",
            "docker_available": docker_path is not None,
            "reason": "Run live checker/sploit/fix matrix evidence against the deployed player runtime using the admin artifact contents.",
        },
    ]


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cleanup_generated_candidates(repo_root: Path) -> None:
    root = repo_root.resolve()
    for relative in GENERATED_CANDIDATE_PATHS:
        target = (root / relative).resolve()
        if not target.exists():
            continue
        if not is_allowed_cleanup_target(root, target):
            raise RuntimeError(f"refusing to clean path outside ignored candidate area: {target}")
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    tmp_dir = root / "tmp"
    try:
        tmp_dir.rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def is_allowed_cleanup_target(repo_root: Path, target: Path) -> bool:
    try:
        relative = target.relative_to(repo_root)
    except ValueError:
        return False
    return bool(relative.parts) and relative.parts[0] == "tmp"


def shared_go_runner_command(
    python: str,
    script: str,
    *,
    go: str,
    cache_dir: str | None,
    appdata_dir: str | None,
) -> list[str]:
    command = [python, "-B", script, "--go", go, "--package-timeout", GO_PACKAGE_TIMEOUT]
    if cache_dir and appdata_dir:
        command.extend(["--cache-dir", cache_dir, "--appdata-dir", appdata_dir])
    return command


def frontend_npm_command(script_name: str) -> list[str]:
    npm = "npm.cmd" if os.name == "nt" and shutil.which("npm.cmd") else "npm"
    return [npm, "--prefix", "frontend", "run", script_name]


def prepare_tool_shims(tool_dir: Path, python: str) -> None:
    if shutil.which("python"):
        return
    resolved_python = shutil.which(python)
    if not resolved_python:
        return
    shim = tool_dir / "python"
    if os.name == "nt":
        shim = tool_dir / "python.cmd"
        shim.write_text(f'@"{resolved_python}" %*\n', encoding="utf-8")
        return
    try:
        shim.symlink_to(resolved_python)
    except OSError:
        shim.write_text(f'#!/bin/sh\nexec "{resolved_python}" "$@"\n', encoding="utf-8")
        shim.chmod(0o755)


def phase_env(
    kind: str,
    *,
    cache_dir: str | None = None,
    appdata_dir: str | None = None,
    tool_dir: str | None = None,
) -> dict[str, str]:
    if kind == "python":
        env = os.environ.copy()
        env["PYTHONPYCACHEPREFIX"] = tempfile.mkdtemp(prefix="sentinel-aml-wave33-pycache.")
        if tool_dir:
            env["PATH"] = os.pathsep.join([tool_dir, env.get("PATH", "")])
        if cache_dir and appdata_dir:
            env["SENTINEL_AML_SHARED_GOCACHE"] = cache_dir
            env["SENTINEL_AML_SHARED_APPDATA"] = appdata_dir
        return env
    if kind == "go":
        if tool_dir:
            base = os.environ.copy()
            base["PATH"] = os.pathsep.join([tool_dir, base.get("PATH", "")])
        else:
            base = os.environ
        if cache_dir and appdata_dir:
            return release_env(base, cache_dir, appdata_dir)
        return release_env(
            base,
            tempfile.mkdtemp(prefix="sentinel-aml-wave33-gocache."),
            tempfile.mkdtemp(prefix="sentinel-aml-wave33-appdata."),
        )
    env = os.environ.copy()
    if tool_dir:
        env["PATH"] = os.pathsep.join([tool_dir, env.get("PATH", "")])
    return env


def run_artifact_first_ui_check(player_manifest: Path) -> int:
    result = validate_player_ui_artifact(player_manifest)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


def validate_player_ui_artifact(player_manifest: Path) -> dict[str, Any]:
    if not player_manifest.is_file():
        return {
            "status": "fail",
            "checks": [
                {
                    "name": "player-ui-artifact",
                    "path": str(player_manifest),
                    "status": "fail",
                    "message": "player manifest missing",
                }
            ],
        }
    manifest = json.loads(player_manifest.read_text(encoding="utf-8"))
    files = [str(entry.get("path", "")) for entry in manifest.get("files", [])]
    ui_files = [path for path in files if "/ui/" in path]
    components = {
        component.get("key"): component
        for component in manifest.get("delivered_components", [])
        if isinstance(component, dict)
    }
    ui_component = components.get("participant-ui")
    forbidden = [
        path
        for path in ui_files
        if path.lower().endswith(".map")
        or ".tsbuildinfo" in path.lower()
        or "/node_modules/" in path.lower()
        or "/src/" in path.lower()
    ]
    missing_required = [
        suffix
        for suffix in ("ui/index.html", "ui/runtime-config.js")
        if not any(path.endswith("/" + suffix) for path in files)
    ]
    component_ok = isinstance(ui_component, dict) and ui_component.get("included") is True and ui_component.get("required") is True
    ok = not forbidden and not missing_required and component_ok
    return {
        "status": "pass" if ok else "fail",
        "checks": [
            {
                "name": "player-ui-artifact",
                "path": str(player_manifest),
                "status": "pass" if ok else "fail",
                "message": (
                    f"ui_files={len(ui_files)}"
                    if ok
                    else f"missing_required={missing_required} component_ok={component_ok} forbidden_ui_members={forbidden}"
                ),
            }
        ],
    }


def check_makefile_target(repo_root: Path) -> dict[str, str]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, MAKE_TARGET)
    phony_targets = phony_entries(makefile)
    required = (
        "$(PYTHON) -B scripts/check_wave33_gate.py --run --go $(GO) --python $(PYTHON)",
    )
    missing = [line for line in required if line not in target]
    forbidden = [marker for marker in FORBIDDEN_ARCHIVE_MARKERS if marker.lower() in target.lower()]
    ok = bool(target) and MAKE_TARGET in phony_targets and not missing and not forbidden
    return {
        "name": "wave33-make-target-archive-free",
        "path": "Makefile",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"target_present={bool(target)} phony={MAKE_TARGET in phony_targets} missing={missing} forbidden={forbidden}",
    }


def check_artifact_first_makefile_target(repo_root: Path) -> dict[str, str]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, ARTIFACT_FIRST_MAKE_TARGET)
    phony_targets = phony_entries(makefile)
    required = "$(PYTHON) -B scripts/check_wave33_gate.py --artifact-first --go $(GO) --python $(PYTHON) --docker $(DOCKER)"
    missing = [] if required in target else [required]
    forbidden = [
        marker
        for marker in ("go test ./...", "go vet ./...", "release-archive", "build_release_archive.py")
        if marker.lower() in target.lower()
    ]
    ok = bool(target) and ARTIFACT_FIRST_MAKE_TARGET in phony_targets and not missing and not forbidden
    return {
        "name": "artifact-first-make-target-runs-aggregate-gate",
        "path": "Makefile",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"target_present={bool(target)} phony={ARTIFACT_FIRST_MAKE_TARGET in phony_targets} missing={missing} forbidden={forbidden}",
    }


def check_artifact_first_files(repo_root: Path) -> dict[str, str]:
    required = (
        "scripts/build_artifacts.py",
        "scripts/check_artifacts.py",
        "scripts/check_artifact_hygiene.py",
        "scripts/check_player_source_hygiene.py",
        "scripts/check_side_view_lexicon.py",
        "scripts/check_semantic_red_herrings.py",
        "scripts/check_player_source_manifest.py",
        "scripts/check_artifact_first_live_acceptance.py",
        "scripts/check_player_bundle_hygiene.py",
        "scripts/check_admin_bundle_hygiene.py",
        "scripts/check_repository_submission_hygiene.py",
        "scripts/check_competition_runtime_profile.py",
        "scripts/check_competition_matrix_gate.py",
        "tests/test_wave33_gate.py",
        "tests/test_artifact_hygiene.py",
        "tests/test_repository_submission_hygiene.py",
        "tests/test_side_view_lexicon.py",
        "tests/test_semantic_red_herrings.py",
        "tests/test_ctf_shaped_strings_removed.py",
        "tests/test_player_source_exact_hash_binding.py",
        "docs/wave_reports/wave_33_artifact_first_gate.md",
    )
    missing = [relative for relative in required if not (repo_root / relative).is_file()]
    return {
        "name": "artifact-first-gate-files-present",
        "path": "scripts tests docs/wave_reports",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing={missing}",
    }


def check_artifact_first_phase_plan(repo_root: Path) -> dict[str, str]:
    phases = artifact_first_phase_specs("python", "go", docker="docker")
    names = [str(phase["name"]) for phase in phases]
    joined = "\n".join(" ".join(str(part) for part in phase["command"]) for phase in phases).replace("\\", "/").replace("npm.cmd", "npm")
    required_order = (
        "clean-generated",
        "verify-frontend-ui-source-scan",
        "verify-frontend-ui-dist-scan",
        "build-transfer-artifacts",
        "verify-artifact-inventory",
        "verify-player-source-manifest",
        "verify-player-source-hygiene",
        "verify-side-view-lexicon",
        "verify-semantic-red-herrings",
        "verify-player-artifact-hygiene",
        "verify-admin-artifact-hygiene",
        "verify-player-ui-artifact",
        "verify-player-runtime-profile-evidence",
        "verify-admin-checker-sploit-fix-matrix-evidence",
        "verify-artifact-live-acceptance-binding",
    )
    missing_names = [name for name in required_order if name not in names]
    ordered = not missing_names and [names.index(name) for name in required_order] == sorted(names.index(name) for name in required_order)
    required_markers = (
        "scripts/check_repository_submission_hygiene.py --clean-generated --preserve-frontend-ui-build .",
        "npm --prefix frontend run security:scan:source",
        "npm --prefix frontend run security:scan:dist",
        "scripts/build_artifacts.py --output-root out",
        "scripts/build_artifacts.py --output-root out --verify-only",
        "scripts/check_player_source_manifest.py --output-root out",
        "scripts/check_player_source_hygiene.py out/artifacts/sentinel-aml-player-source.tar.gz",
        "scripts/check_side_view_lexicon.py out/artifacts/sentinel-aml-player-source.tar.gz --require-artifact",
        "scripts/check_semantic_red_herrings.py",
        "scripts/check_player_bundle_hygiene.py out/artifacts/sentinel-aml-player-service.tar.gz",
        "scripts/check_admin_bundle_hygiene.py out/artifacts/sentinel-aml-admin-organizer.tar.gz",
        "scripts/check_competition_runtime_profile.py --mode binary",
        "scripts/check_competition_matrix_gate.py",
        "scripts/check_artifact_first_live_acceptance.py --output-root out",
    )
    missing_markers = [marker for marker in required_markers if marker not in joined]
    forbidden = [marker for marker in ("go test ./...", "go vet ./...", "release-archive") if marker in joined]
    ok = ordered and not missing_markers and not forbidden
    return {
        "name": "artifact-first-phase-plan-builds-then-tests-transfer-bytes",
        "path": "scripts/check_wave33_gate.py",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"missing_names={missing_names} ordered={ordered} missing_markers={missing_markers} forbidden={forbidden}",
    }


def check_artifact_first_docs(repo_root: Path) -> dict[str, str]:
    text = read(repo_root, "docs/12_testing_strategy.md") + "\n" + read(repo_root, "docs/13_roadmap.md")
    report = read(repo_root, "docs/wave_reports/wave_33_artifact_first_gate.md")
    required = (
        "artifact-first-gate",
        "out/artifact-first-validation-summary.json",
        "transfer artifacts",
        "external-required",
        "player artifact SHA-256",
        "runtime smoke status",
    )
    combined = re.sub(r"\s+", " ", text + "\n" + report)
    missing = [marker for marker in required if marker not in combined]
    return {
        "name": "artifact-first-docs-describe-aggregate-gate",
        "path": "docs/12_testing_strategy.md docs/13_roadmap.md docs/wave_reports/wave_33_artifact_first_gate.md",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing={missing}",
    }


def check_wave33_files(repo_root: Path) -> dict[str, str]:
    required = (
        "scripts/build_player_bundle.py",
        "scripts/build_admin_bundle.py",
        "scripts/check_player_bundle_hygiene.py",
        "tests/test_player_bundle_build.py",
        "tests/test_player_bundle_hygiene.py",
        "packaging/player/README.md",
        "packaging/player/TROUBLESHOOTING.md",
        *REQUIRED_REPORTS,
    )
    missing = [relative for relative in required if not (repo_root / relative).is_file()]
    return {
        "name": "wave33-packaging-productization-files-present",
        "path": "scripts tests packaging/player docs/wave_reports",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing={missing}",
    }


def check_phase_plan(repo_root: Path) -> dict[str, str]:
    phases = command_phase_specs("python", "go")
    names = [str(phase["name"]) for phase in phases]
    commands = [" ".join(str(part) for part in phase["command"]) for phase in phases]
    required_labels = (
        "player-candidate-tests",
        "repository-submission-hygiene-strict",
        "player-candidate-build",
        "admin-candidate-build",
        "repository-submission-hygiene-local-staging",
        "player-candidate-hygiene",
        "participant-doc-hygiene",
        "checker-tests",
        "competition-matrix-tests",
        "competition-matrix-gate",
        "vulnerable-profile-runner",
        "release-profile-go-tests",
        "go-vet",
        "go-build",
        "docs-tree",
        "forcad-config",
        "cleanup-wave33-generated-candidates",
    )
    missing_labels = [label for label in required_labels if label not in names]
    missing_exploits = [relative for relative in EXPECTED_EXPLOITS if relative not in "\n".join(commands)]
    missing_patches = [relative for relative in EXPECTED_PATCHES if relative not in "\n".join(commands)]
    missing_files = [relative for relative in (*EXPECTED_EXPLOITS, *EXPECTED_PATCHES) if not (repo_root / relative).is_file()]
    forbidden = [
        f"{phase['name']}: {marker}"
        for phase in phases
        for marker in FORBIDDEN_ARCHIVE_MARKERS
        if marker.lower() in " ".join(str(part) for part in phase["command"]).lower()
    ]
    ok = not missing_labels and not missing_exploits and not missing_patches and not missing_files and not forbidden
    return {
        "name": "wave33-phase-plan-preserves-ad-stability-and-package-hygiene",
        "path": "scripts/check_wave33_gate.py",
        "status": "pass" if ok else "fail",
        "message": ""
        if ok
        else f"missing_labels={missing_labels} missing_exploits={missing_exploits} missing_patches={missing_patches} missing_files={missing_files} forbidden={forbidden}",
    }


def check_player_docs_clean(repo_root: Path) -> dict[str, str]:
    findings: list[str] = []
    for path in sorted((repo_root / "packaging" / "player").glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in BANNED_PLAYER_DOC_PATTERN.finditer(text):
            findings.append(f"{path.relative_to(repo_root).as_posix()}: {match.group(0)}")
    return {
        "name": "wave33-participant-docs-sanitized",
        "path": "packaging/player",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings[:20]),
    }


def check_candidate_builder_policy(repo_root: Path) -> dict[str, str]:
    player = read(repo_root, "scripts/build_player_bundle.py")
    admin = read(repo_root, "scripts/build_admin_bundle.py")
    required_player = (
        "SOURCE_DIRS",
        "sanitize_go_source",
        "LEGACY_PROFILE_TAGS",
        "SOURCE_TOKEN_REPLACEMENTS",
        "ensure_candidate_output_allowed",
    )
    required_admin = (
        "CHECKER_FILES",
        "config.yml",
        "ensure_candidate_output_allowed",
    )
    missing = [f"player:{marker}" for marker in required_player if marker not in player]
    missing.extend(f"admin:{marker}" for marker in required_admin if marker not in admin)
    forbidden = []
    for relative, text in (("scripts/build_player_bundle.py", player), ("scripts/build_admin_bundle.py", admin)):
        for marker in ("tarfile", "zipfile", "build_release_archive", "sha256", "release-archive"):
            if marker in text:
                forbidden.append(f"{relative}: {marker}")
    return {
        "name": "wave33-candidate-builders-allowlisted-and-not-final-archives",
        "path": "scripts/build_player_bundle.py scripts/build_admin_bundle.py",
        "status": "pass" if not missing and not forbidden else "fail",
        "message": "" if not missing and not forbidden else f"missing={missing} forbidden={forbidden}",
    }


def phony_entries(makefile: str) -> set[str]:
    entries: set[str] = set()
    for line in makefile.splitlines():
        if line.startswith(".PHONY:"):
            entries.update(line.removeprefix(".PHONY:").split())
    return entries


def make_target_block(text: str, target_name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target_name)}:\s*(?:#.*)?$", text)
    if not match:
        return ""
    next_target = re.search(r"(?m)^[A-Za-z0-9_.-]+:\s*(?:#.*)?$", text[match.end() :])
    end = match.end() + next_target.start() if next_target else len(text)
    return text[match.start() : end]


def read(repo_root: Path, relative: str) -> str:
    path = repo_root / relative
    return path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else ""


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="execute bounded Wave 33 regression phases")
    parser.add_argument("--artifact-first", action="store_true", help="execute bounded artifact-first aggregate phases")
    parser.add_argument("--artifact-first-ui-check", action="store_true", help="validate required generated player UI artifact members")
    parser.add_argument("--cleanup-only", action="store_true", help="remove known Wave 33 generated candidate trees")
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--gate-timeout", type=float, default=DEFAULT_GATE_TIMEOUT)
    parser.add_argument("--output-root", type=Path, default=ARTIFACT_OUTPUT_ROOT)
    parser.add_argument("--repository-submission", type=Path)
    parser.add_argument("--summary-out", type=Path, default=DEFAULT_ARTIFACT_FIRST_SUMMARY)
    parser.add_argument("--player-manifest", type=Path, default=PLAYER_MANIFEST)
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    if args.artifact_first_ui_check:
        return run_artifact_first_ui_check(args.player_manifest)
    if args.cleanup_only:
        cleanup_generated_candidates(repo_root)
        print("wave33-gate: generated candidates cleaned")
        return 0
    if args.run:
        if args.gate_timeout <= 0:
            parser.error("--gate-timeout must be positive")
        return run_gate(repo_root, python=args.python, go=args.go, gate_timeout=args.gate_timeout)
    if args.artifact_first:
        if args.gate_timeout <= 0:
            parser.error("--gate-timeout must be positive")
        return run_artifact_first_gate(
            repo_root,
            python=args.python,
            go=args.go,
            docker=args.docker,
            output_root=args.output_root,
            repository_submission=args.repository_submission,
            summary_out=args.summary_out,
            gate_timeout=args.gate_timeout,
        )
    result = validate_wave33_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
