#!/usr/bin/env python3
"""Validate and run the archive-free Sentinel AML A/D stability gate."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, TextIO

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from run_go_release_tests import Runner, release_env, run_command


MAKE_TARGET = "ad-stability-gate"
DEFAULT_GATE_TIMEOUT = 285.0
GO_PACKAGE_TIMEOUT = "60"
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
REQUIRED_MAKE_TARGET_LINES = (
    "$(PYTHON) -B scripts/check_ad_stability_gate.py --run --go $(GO) --python $(PYTHON)",
)
FORBIDDEN_ARCHIVE_MARKERS = (
    "release-archive",
    "build_release_archive.py",
    "player-bundle",
    "player bundle",
    "release-manifest",
    "final manifest",
    "checksum",
)
REQUIRED_PHASE_LABELS = (
    "ad-stability-static-tests",
    "checker-tests",
    "competition-matrix-tests",
    "go-release-runner-tests",
    "vulnerable-profile-runner-tests",
    "ad-stability-static-validation",
    "competition-matrix-validation",
    "wave29-behavioral-evidence-validation",
    "sploit-syntax",
    "fix-patch-check",
    "vulnerable-profile-runner",
    "release-profile-go-tests",
    "go-vet",
    "go-build",
    "docs-tree",
    "forcad-config",
)


def validate_ad_stability_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_makefile_target(repo_root),
        check_phase_plan(repo_root),
        check_runner_uses_bounded_process_trees(repo_root),
        check_docs(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def command_phase_specs(python: str, go: str, *, cache_dir: str | None = None, appdata_dir: str | None = None) -> list[dict[str, Any]]:
    phases: list[dict[str, Any]] = [
        {
            "name": "ad-stability-static-tests",
            "command": [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_ad_stability_gate.py"],
            "timeout": 60,
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
            "name": "go-release-runner-tests",
            "command": [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_run_go_release_tests.py"],
            "timeout": 60,
            "env": "python",
        },
        {
            "name": "vulnerable-profile-runner-tests",
            "command": [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_run_vulnerable_profile_tests.py"],
            "timeout": 60,
            "env": "python",
        },
        {
            "name": "ad-stability-static-validation",
            "command": [python, "-B", "scripts/check_ad_stability_gate.py"],
            "timeout": 30,
            "env": "python",
        },
        {
            "name": "competition-matrix-validation",
            "command": [python, "-B", "scripts/check_competition_matrix_gate.py"],
            "timeout": 30,
            "env": "python",
        },
        {
            "name": "wave29-behavioral-evidence-validation",
            "command": [python, "-B", "scripts/check_wave29_gate.py"],
            "timeout": 60,
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
    validation = validate_ad_stability_gate(repo_root)
    print(json.dumps(validation, indent=2, sort_keys=True), file=stdout, flush=True)
    if validation["status"] != "pass":
        return 1

    gate_started = time.monotonic()
    gate_deadline = gate_started + gate_timeout
    with tempfile.TemporaryDirectory(prefix="sentinel-aml-ad-stability-gocache.") as cache_dir:
        with tempfile.TemporaryDirectory(prefix="sentinel-aml-ad-stability-appdata.") as appdata_dir:
            with tempfile.TemporaryDirectory(prefix="sentinel-aml-ad-stability-tools.") as tool_dir:
                prepare_tool_shims(Path(tool_dir), python)
                phases = command_phase_specs(python, go, cache_dir=cache_dir, appdata_dir=appdata_dir)
                print(
                    f"ad-stability-gate: starting {len(phases)} bounded phases gate_timeout={gate_timeout:.1f}s",
                    file=stdout,
                    flush=True,
                )
                print(f"ad-stability-gate: shared GOCACHE={cache_dir}", file=stdout, flush=True)
                print(f"ad-stability-gate: shared APPDATA={appdata_dir}", file=stdout, flush=True)
                for index, phase in enumerate(phases, start=1):
                    started = time.monotonic()
                    remaining = gate_deadline - started
                    if remaining <= 5:
                        total = started - gate_started
                        print(
                            f"ad-stability-gate: aggregate deadline reached before {phase['name']} elapsed={total:.3f}s",
                            file=stderr,
                            flush=True,
                        )
                        return 1
                    phase_timeout = min(float(phase["timeout"]), max(1.0, remaining - 2.0))
                    command = [str(part) for part in phase["command"]]
                    print(
                        f"ad-stability-gate: phase {index}/{len(phases)} start {phase['name']} timeout={phase_timeout:.1f}s remaining={remaining:.1f}s",
                        file=stdout,
                        flush=True,
                    )
                    print(f"ad-stability-gate: command {subprocess.list2cmdline(command)}", file=stdout, flush=True)
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
                        print(
                            f"ad-stability-gate: phase {phase['name']} timed out after {elapsed:.3f}s",
                            file=stderr,
                            flush=True,
                        )
                        if exc.output:
                            print(exc.output, end="" if str(exc.output).endswith("\n") else "\n", file=stdout, flush=True)
                        if exc.stderr:
                            print(exc.stderr, end="" if str(exc.stderr).endswith("\n") else "\n", file=stderr, flush=True)
                        return 1

                    if completed.stdout:
                        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n", file=stdout, flush=True)
                    if completed.stderr:
                        print(completed.stderr, end="" if completed.stderr.endswith("\n") else "\n", file=stderr, flush=True)
                    elapsed = time.monotonic() - started
                    print(
                        f"ad-stability-gate: phase {index}/{len(phases)} {phase['name']} exit={completed.returncode} elapsed={elapsed:.3f}s",
                        file=stdout,
                        flush=True,
                    )
                    if completed.returncode != 0:
                        total = time.monotonic() - gate_started
                        print(f"ad-stability-gate: failed after {total:.3f}s", file=stderr, flush=True)
                        return completed.returncode

    total = time.monotonic() - gate_started
    print(f"ad-stability-gate: pass elapsed={total:.3f}s", file=stdout, flush=True)
    return 0


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
        env["PYTHONPYCACHEPREFIX"] = tempfile.mkdtemp(prefix="sentinel-aml-ad-stability-pycache.")
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
            tempfile.mkdtemp(prefix="sentinel-aml-ad-stability-gocache."),
            tempfile.mkdtemp(prefix="sentinel-aml-ad-stability-appdata."),
        )
    env = os.environ.copy()
    if tool_dir:
        env["PATH"] = os.pathsep.join([tool_dir, env.get("PATH", "")])
    return env


def check_makefile_target(repo_root: Path) -> dict[str, Any]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, MAKE_TARGET)
    phony_targets = phony_entries(makefile)
    missing = [line for line in REQUIRED_MAKE_TARGET_LINES if line not in target]
    forbidden = [marker for marker in FORBIDDEN_ARCHIVE_MARKERS if marker.lower() in target.lower()]
    ok = bool(target) and MAKE_TARGET in phony_targets and not missing and not forbidden
    return {
        "name": "ad-stability-make-target-archive-free",
        "path": "Makefile",
        "status": "pass" if ok else "fail",
        "message": ""
        if ok
        else f"target_present={bool(target)} phony={MAKE_TARGET in phony_targets} missing={missing} forbidden={forbidden}",
    }


def check_phase_plan(repo_root: Path) -> dict[str, Any]:
    phases = command_phase_specs("python", "go")
    commands = [" ".join(str(part) for part in phase["command"]) for phase in phases]
    names = [str(phase["name"]) for phase in phases]
    missing_files = [relative for relative in (*EXPECTED_EXPLOITS, *EXPECTED_PATCHES) if not (repo_root / relative).is_file()]
    missing_labels = [
        label
        for label in REQUIRED_PHASE_LABELS
        if label not in names and not any(name.startswith(label + ":") for name in names)
    ]
    missing_exploit_checks = [
        relative
        for relative in EXPECTED_EXPLOITS
        if [cmd for cmd in commands if "py_compile" in cmd and relative in cmd] == []
    ]
    missing_patch_checks = [
        relative
        for relative in EXPECTED_PATCHES
        if [cmd for cmd in commands if "git apply --check --whitespace=error" in cmd and relative in cmd] == []
    ]
    forbidden = [
        f"{phase['name']}: {marker}"
        for phase in phases
        for marker in FORBIDDEN_ARCHIVE_MARKERS
        if marker.lower() in " ".join(str(part) for part in phase["command"]).lower()
    ]
    ok = not missing_files and not missing_labels and not missing_exploit_checks and not missing_patch_checks and not forbidden
    return {
        "name": "ad-stability-phase-plan-covers-behavior-not-packaging",
        "path": "scripts/check_ad_stability_gate.py",
        "status": "pass" if ok else "fail",
        "message": ""
        if ok
        else (
            f"missing_files={missing_files} missing_labels={missing_labels} "
            f"missing_exploit_checks={missing_exploit_checks} missing_patch_checks={missing_patch_checks} forbidden={forbidden}"
        ),
    }


def check_runner_uses_bounded_process_trees(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, "scripts/check_ad_stability_gate.py")
    required = (
        "from run_go_release_tests import Runner, release_env, run_command",
        "runner: Runner = run_command",
        "phase_timeout = min(float(phase[\"timeout\"])",
        "timeout=phase_timeout",
        "subprocess.TimeoutExpired",
    )
    missing = [marker for marker in required if marker not in text]
    forbidden_marker = "subprocess." + "run("
    forbidden = [forbidden_marker] if forbidden_marker in text else []
    return {
        "name": "ad-stability-runner-process-tree-bounded",
        "path": "scripts/check_ad_stability_gate.py scripts/run_go_release_tests.py",
        "status": "pass" if not missing and not forbidden else "fail",
        "message": "" if not missing and not forbidden else f"missing={missing} forbidden={forbidden}",
    }


def check_docs(repo_root: Path) -> dict[str, Any]:
    required = (
        "Archive-Free Stability Gate",
        "`make ad-stability-gate`",
        "does not build release archives",
        "Release/package gates",
        "archive generation, player bundles, final manifests, and checksums",
    )
    text = re.sub(r"\s+", " ", read(repo_root, "docs/12_testing_strategy.md"))
    missing = [marker for marker in required if marker not in text]
    return {
        "name": "ad-stability-docs-separate-stability-from-release-packaging",
        "path": "docs/12_testing_strategy.md",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing={missing}",
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
    parser.add_argument("--run", action="store_true", help="execute the archive-free stability phases after static validation")
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--gate-timeout", type=float, default=DEFAULT_GATE_TIMEOUT)
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    if args.run:
        if args.gate_timeout <= 0:
            parser.error("--gate-timeout must be positive")
        return run_gate(repo_root, python=args.python, go=args.go, gate_timeout=args.gate_timeout)
    result = validate_ad_stability_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
