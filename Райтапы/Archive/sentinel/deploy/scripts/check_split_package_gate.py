#!/usr/bin/env python3
"""Validate and run the final split-package gate without publishing archives."""

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
from typing import Any, TextIO

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from run_go_release_tests import Runner, run_command


MAKE_TARGET = "final-split-package-gate"
DEFAULT_GATE_TIMEOUT = 285.0
PLAYER_CANDIDATE = "tmp/final-split-player-service-candidate"
PLAYER_ALLOWLIST = "tmp/final-split-player-service-candidate.hygiene-allowlist.json"
ADMIN_CANDIDATE = "tmp/final-split-admin-checker-candidate"
DEFAULT_PACKAGE_DATABASE_URL = "postgres://sentinel:sentinel@localhost:55434/sentinel_aml?sslmode=disable"
DEFAULT_PACKAGE_BASE_URL = "http://127.0.0.1:18081"
FORBIDDEN_ARCHIVE_MARKERS = (
    "release-archive",
    "build_release_archive.py",
    "build_release_archive",
    "final manifest",
    "checksum",
)


def validate_split_package_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_makefile_target(repo_root),
        check_required_files(repo_root),
        check_phase_plan(repo_root),
        check_docs(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def command_phase_specs(
    python: str,
    go: str,
    *,
    docker: str,
    database_url: str = DEFAULT_PACKAGE_DATABASE_URL,
    base_url: str = DEFAULT_PACKAGE_BASE_URL,
    host_player_runtime: bool = False,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    return [
        {
            "name": "split-package-static-tests",
            "command": [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_split_package_gate.py"],
            "timeout": 60,
            "env": "python",
            "artifact": "organizer",
        },
        {
            "name": "player-package-runtime-proof",
            "command": player_runtime_command(
                python,
                go,
                docker,
                database_url=database_url,
                base_url=base_url,
                host_player_runtime=host_player_runtime,
                repo_root=repo_root,
            ),
            "timeout": 150,
            "env": "python",
            "artifact": "player-service",
        },
        {
            "name": "player-final-hygiene",
            "command": [
                python,
                "-B",
                "scripts/check_player_bundle_hygiene.py",
                PLAYER_CANDIDATE,
                "--allowlist",
                PLAYER_ALLOWLIST,
                "--require-runtime-ready",
            ],
            "timeout": 30,
            "env": "python",
            "artifact": "player-service",
        },
        {
            "name": "admin-package-tests",
            "command": [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_admin_bundle_build.py"],
            "timeout": 30,
            "env": "python",
            "artifact": "admin-checker",
        },
        {
            "name": "admin-package-build",
            "command": [python, "-B", "scripts/build_admin_bundle.py", "--output-dir", ADMIN_CANDIDATE],
            "timeout": 20,
            "env": "python",
            "artifact": "admin-checker",
        },
        {
            "name": "admin-inventory-gate",
            "command": [python, "-B", "scripts/check_admin_bundle_hygiene.py", ADMIN_CANDIDATE],
            "timeout": 20,
            "env": "python",
            "artifact": "admin-checker",
        },
        {
            "name": "admin-forcad-config",
            "command": [python, "-B", "scripts/validate_forcad_config.py", f"{ADMIN_CANDIDATE}/config.yml"],
            "timeout": 20,
            "env": "python",
            "artifact": "admin-checker",
        },
        {
            "name": "cleanup-generated-candidates",
            "command": [
                python,
                "-B",
                "scripts/check_split_package_gate.py",
                "--cleanup-only",
                "--player-candidate",
                PLAYER_CANDIDATE,
                "--player-allowlist",
                PLAYER_ALLOWLIST,
                "--admin-candidate",
                ADMIN_CANDIDATE,
            ],
            "timeout": 20,
            "env": "python",
            "artifact": "organizer",
        },
        {
            "name": "organizer-ad-stability-gate",
            "command": [
                python,
                "-B",
                "scripts/check_ad_stability_gate.py",
                "--run",
                "--go",
                go,
                "--python",
                python,
                "--gate-timeout",
                "180",
            ],
            "timeout": 190,
            "env": "python",
            "artifact": "organizer",
        },
        {
            "name": "archive-hygiene",
            "command": [python, "-B", "scripts/check_archive_hygiene.py"],
            "timeout": 30,
            "env": "python",
            "artifact": "organizer",
        },
        {
            "name": "repository-submission-hygiene",
            "command": [python, "-B", "scripts/check_repository_submission_hygiene.py"],
            "timeout": 30,
            "env": "python",
            "artifact": "organizer",
        },
        {
            "name": "docs-tree",
            "command": [python, "-B", "scripts/check_docs_tree.py"],
            "timeout": 30,
            "env": "python",
            "artifact": "organizer",
        },
        {
            "name": "organizer-forcad-config",
            "command": [python, "-B", "scripts/validate_forcad_config.py"],
            "timeout": 20,
            "env": "python",
            "artifact": "organizer",
        },
    ]


def run_gate(
    repo_root: Path,
    *,
    python: str,
    go: str,
    docker: str,
    database_url: str,
    base_url: str,
    runner: Runner = run_command,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    gate_timeout: float = DEFAULT_GATE_TIMEOUT,
) -> int:
    validation = validate_split_package_gate(repo_root)
    print(json.dumps(validation, indent=2, sort_keys=True), file=stdout, flush=True)
    if validation["status"] != "pass":
        return 1

    statuses = initial_artifact_statuses()
    started_gate = time.monotonic()
    deadline = started_gate + gate_timeout
    host_player_runtime = should_use_windows_host_player_runtime(go, docker)
    phases = command_phase_specs(
        python,
        go,
        docker=docker,
        database_url=database_url,
        base_url=base_url,
        host_player_runtime=host_player_runtime,
        repo_root=repo_root,
    )
    print(f"final-split-package-gate: starting {len(phases)} bounded phases gate_timeout={gate_timeout:.1f}s", file=stdout, flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-aml-split-pycache.") as pycache:
            for index, phase in enumerate(phases, start=1):
                started = time.monotonic()
                remaining = deadline - started
                if remaining <= 5:
                    print(
                        f"final-split-package-gate: aggregate deadline reached before {phase['name']} elapsed={started - started_gate:.3f}s",
                        file=stderr,
                        flush=True,
                    )
                    return finish_gate(statuses, stdout, started_gate, 1)
                timeout = min(float(phase["timeout"]), max(1.0, remaining - 2.0))
                command = [str(part) for part in phase["command"]]
                print(
                    f"final-split-package-gate: phase {index}/{len(phases)} start {phase['name']} artifact={phase['artifact']} timeout={timeout:.1f}s remaining={remaining:.1f}s",
                    file=stdout,
                    flush=True,
                )
                print(f"final-split-package-gate: command {subprocess.list2cmdline(command)}", file=stdout, flush=True)
                try:
                    completed = runner(
                        command,
                        cwd=repo_root,
                        env=phase_env(str(phase["env"]), pycache),
                        timeout=timeout,
                    )
                except subprocess.TimeoutExpired as exc:
                    elapsed = time.monotonic() - started
                    print(f"final-split-package-gate: phase {phase['name']} timed out after {elapsed:.3f}s", file=stderr, flush=True)
                    if exc.output:
                        print(exc.output, end="" if str(exc.output).endswith("\n") else "\n", file=stdout, flush=True)
                    if exc.stderr:
                        print(exc.stderr, end="" if str(exc.stderr).endswith("\n") else "\n", file=stderr, flush=True)
                    mark_artifact_failed(statuses, str(phase["artifact"]), str(phase["name"]), "timeout")
                    cleanup_candidates(repo_root, PLAYER_CANDIDATE, PLAYER_ALLOWLIST, ADMIN_CANDIDATE)
                    return finish_gate(statuses, stdout, started_gate, 1)

                if completed.stdout:
                    print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n", file=stdout, flush=True)
                if completed.stderr:
                    print(completed.stderr, end="" if completed.stderr.endswith("\n") else "\n", file=stderr, flush=True)
                elapsed = time.monotonic() - started
                print(
                    f"final-split-package-gate: phase {index}/{len(phases)} {phase['name']} exit={completed.returncode} elapsed={elapsed:.3f}s",
                    file=stdout,
                    flush=True,
                )
                if completed.returncode != 0:
                    mark_artifact_failed(statuses, str(phase["artifact"]), str(phase["name"]), f"exit={completed.returncode}")
                    cleanup_candidates(repo_root, PLAYER_CANDIDATE, PLAYER_ALLOWLIST, ADMIN_CANDIDATE)
                    return finish_gate(statuses, stdout, started_gate, completed.returncode)
                mark_phase_passed(statuses, str(phase["artifact"]), str(phase["name"]))
    finally:
        cleanup_candidates(repo_root, PLAYER_CANDIDATE, PLAYER_ALLOWLIST, ADMIN_CANDIDATE)

    return finish_gate(statuses, stdout, started_gate, 0)


def initial_artifact_statuses() -> dict[str, Any]:
    return {
        "player-service": {
            "status": "pending",
            "candidate_path": PLAYER_CANDIDATE,
            "final_archive_created": False,
            "evidence": [],
        },
        "admin-checker": {
            "status": "pending",
            "candidate_path": ADMIN_CANDIDATE,
            "final_archive_created": False,
            "evidence": [],
        },
        "organizer-internal": {
            "status": "pending",
            "final_archive_created": False,
            "evidence": [],
        },
    }


def mark_phase_passed(statuses: dict[str, Any], artifact: str, phase: str) -> None:
    key = "organizer-internal" if artifact == "organizer" else artifact
    statuses[key]["status"] = "pass"
    statuses[key]["evidence"].append(phase)


def mark_artifact_failed(statuses: dict[str, Any], artifact: str, phase: str, message: str) -> None:
    key = "organizer-internal" if artifact == "organizer" else artifact
    statuses[key]["status"] = "fail"
    statuses[key]["evidence"].append(f"{phase}: {message}")


def finish_gate(statuses: dict[str, Any], stdout: TextIO, started: float, exit_code: int) -> int:
    for status in statuses.values():
        if status["status"] == "pending":
            status["status"] = "not-run"
    result = {
        "artifact_statuses": statuses,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "final_archives_created": False,
        "status": "pass" if exit_code == 0 else "fail",
    }
    print(json.dumps(result, indent=2, sort_keys=True), file=stdout, flush=True)
    if exit_code == 0:
        print(f"final-split-package-gate: pass elapsed={time.monotonic() - started:.3f}s", file=stdout, flush=True)
    return exit_code


def phase_env(kind: str, pycache: str) -> dict[str, str]:
    env = os.environ.copy()
    if kind == "python":
        env["PYTHONPYCACHEPREFIX"] = pycache
    return env


def should_use_windows_host_player_runtime(go: str, docker: str) -> bool:
    if os.name == "nt":
        return False
    if not (go.lower().endswith(".exe") or docker.lower().endswith(".exe")):
        return False
    return shutil.which("powershell.exe") is not None


def player_runtime_command(
    python: str,
    go: str,
    docker: str,
    *,
    database_url: str,
    base_url: str,
    host_player_runtime: bool = False,
    repo_root: Path | None = None,
) -> list[str]:
    if not host_player_runtime:
        return [
            python,
            "-B",
            "scripts/check_player_package_runtime.py",
            "--output-dir",
            PLAYER_CANDIDATE,
            "--allowlist-out",
            PLAYER_ALLOWLIST,
            "--go",
            go,
            "--docker",
            docker,
            "--database-url",
            database_url,
            "--base-url",
            base_url,
        ]
    if repo_root is None:
        raise ValueError("repo_root is required for host player runtime")
    command = (
        "$ErrorActionPreference = 'Stop'; "
        f"Set-Location -LiteralPath {powershell_quote(windows_path_for_wsl(repo_root))}; "
        "python -B scripts\\check_player_package_runtime.py "
        f"--output-dir {powershell_quote(PLAYER_CANDIDATE)} "
        f"--allowlist-out {powershell_quote(PLAYER_ALLOWLIST)} "
        f"--go {powershell_quote(strip_exe_suffix(go))} "
        f"--docker {powershell_quote(strip_exe_suffix(docker))} "
        f"--database-url {powershell_quote(database_url)} "
        f"--base-url {powershell_quote(base_url)}; "
        "exit $LASTEXITCODE"
    )
    return ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]


def strip_exe_suffix(command: str) -> str:
    return command[:-4] if command.lower().endswith(".exe") else command


def windows_path_for_wsl(path: Path) -> str:
    resolved = path.resolve()
    as_posix = resolved.as_posix()
    if as_posix.startswith("/mnt/") and len(as_posix) >= 7 and as_posix[6] == "/":
        drive = as_posix[5].upper()
        rest = as_posix[7:].replace("/", "\\")
        return f"{drive}:\\{rest}"
    return str(resolved)


def powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def cleanup_candidates(repo_root: Path, *relatives: str) -> None:
    root = repo_root.resolve()
    for relative in relatives:
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


def check_makefile_target(repo_root: Path) -> dict[str, str]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, MAKE_TARGET)
    phony_targets = phony_entries(makefile)
    required = "$(PYTHON) -B scripts/check_split_package_gate.py --run --go $(GO) --python $(PYTHON) --docker $(DOCKER)"
    missing = [] if required in target else [required]
    forbidden = [marker for marker in FORBIDDEN_ARCHIVE_MARKERS if marker.lower() in target.lower()]
    ok = bool(target) and MAKE_TARGET in phony_targets and not missing and not forbidden
    return {
        "name": "final-split-package-make-target-archive-free",
        "path": "Makefile",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"target_present={bool(target)} phony={MAKE_TARGET in phony_targets} missing={missing} forbidden={forbidden}",
    }


def check_required_files(repo_root: Path) -> dict[str, str]:
    required = (
        "scripts/check_split_package_gate.py",
        "scripts/check_player_package_runtime.py",
        "scripts/check_player_bundle_hygiene.py",
        "scripts/build_player_bundle.py",
        "scripts/build_admin_bundle.py",
        "scripts/check_admin_bundle_hygiene.py",
        "scripts/check_ad_stability_gate.py",
        "scripts/check_archive_hygiene.py",
        "scripts/check_repository_submission_hygiene.py",
        "scripts/check_docs_tree.py",
        "scripts/validate_forcad_config.py",
        "tests/test_split_package_gate.py",
        "tests/test_admin_bundle_build.py",
        "tests/test_player_bundle_build.py",
        "tests/test_player_bundle_hygiene.py",
        "docs/wave_reports/wave_34_final_split_package_gate.md",
    )
    missing = [relative for relative in required if not (repo_root / relative).is_file()]
    return {
        "name": "final-split-package-files-present",
        "path": "scripts tests docs/wave_reports",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing={missing}",
    }


def check_phase_plan(repo_root: Path) -> dict[str, str]:
    phases = command_phase_specs("python", "go", docker="docker")
    names = [str(phase["name"]) for phase in phases]
    joined = "\n".join(" ".join(str(part) for part in phase["command"]) for phase in phases)
    required_names = (
        "player-package-runtime-proof",
        "player-final-hygiene",
        "admin-package-tests",
        "admin-package-build",
        "admin-inventory-gate",
        "admin-forcad-config",
        "cleanup-generated-candidates",
        "organizer-ad-stability-gate",
        "archive-hygiene",
        "repository-submission-hygiene",
        "docs-tree",
        "organizer-forcad-config",
    )
    required_markers = (
        "scripts/check_player_package_runtime.py",
        "scripts/check_player_bundle_hygiene.py",
        "--require-runtime-ready",
        "scripts/build_admin_bundle.py",
        "scripts/check_admin_bundle_hygiene.py",
        "scripts/check_ad_stability_gate.py --run",
        "scripts/check_archive_hygiene.py",
        "scripts/check_repository_submission_hygiene.py",
        "scripts/check_docs_tree.py",
        "scripts/validate_forcad_config.py",
    )
    missing_names = [name for name in required_names if name not in names]
    missing_markers = [marker for marker in required_markers if marker not in joined]
    forbidden = [marker for marker in FORBIDDEN_ARCHIVE_MARKERS if marker.lower() in joined.lower()]
    ok = not missing_names and not missing_markers and not forbidden
    return {
        "name": "final-split-package-phase-plan-separates-artifacts",
        "path": "scripts/check_split_package_gate.py",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"missing_names={missing_names} missing_markers={missing_markers} forbidden={forbidden}",
    }


def check_docs(repo_root: Path) -> dict[str, str]:
    required = (
        "Final Split-Package Gate",
        "`make final-split-package-gate`",
        "player-service",
        "admin/checker",
        "organizer-internal",
        "does not create final archives",
    )
    text = re.sub(r"\s+", " ", read(repo_root, "docs/12_testing_strategy.md"))
    report = read(repo_root, "docs/wave_reports/wave_34_final_split_package_gate.md")
    combined = text + "\n" + report
    missing = [marker for marker in required if marker not in combined]
    return {
        "name": "final-split-package-docs-describe-boundary",
        "path": "docs/12_testing_strategy.md docs/wave_reports/wave_34_final_split_package_gate.md",
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


def aggregate_status(checks: list[dict[str, str]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="execute split-package validation phases")
    parser.add_argument("--cleanup-only", action="store_true", help="remove gate-generated candidate trees")
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--database-url", default=os.environ.get("SENTINEL_AML_SPLIT_GATE_DATABASE_URL", DEFAULT_PACKAGE_DATABASE_URL))
    parser.add_argument("--base-url", default=os.environ.get("SENTINEL_AML_SPLIT_GATE_BASE_URL", DEFAULT_PACKAGE_BASE_URL))
    parser.add_argument("--gate-timeout", type=float, default=DEFAULT_GATE_TIMEOUT)
    parser.add_argument("--player-candidate", default=PLAYER_CANDIDATE)
    parser.add_argument("--player-allowlist", default=PLAYER_ALLOWLIST)
    parser.add_argument("--admin-candidate", default=ADMIN_CANDIDATE)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    if args.cleanup_only:
        cleanup_candidates(repo_root, args.player_candidate, args.player_allowlist, args.admin_candidate)
        print("final-split-package-gate: generated candidates cleaned")
        return 0
    if args.run:
        if args.gate_timeout <= 0:
            raise SystemExit("--gate-timeout must be positive")
        return run_gate(
            repo_root,
            python=args.python,
            go=args.go,
            docker=args.docker,
            database_url=args.database_url,
            base_url=args.base_url,
            gate_timeout=args.gate_timeout,
        )
    result = validate_split_package_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
