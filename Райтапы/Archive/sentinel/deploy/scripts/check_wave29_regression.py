#!/usr/bin/env python3
"""Run Wave 29 end-to-end checker, exploit, and fix regression evidence."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, TextIO


Runner = Callable[..., subprocess.CompletedProcess[str]]

PYTHON_TEST_PATTERNS = (
    "test_competition_matrix_gate.py",
    "test_wave29_gate.py",
)
EXPLOITS = (
    "sploits/sentinel_aml/aml_dedup_preview.py",
    "sploits/sentinel_aml/aml_audit_timeline.py",
    "sploits/sentinel_aml/aml_related_graph.py",
    "sploits/sentinel_aml/aml_export_redaction.py",
    "sploits/sentinel_aml/aml_network_room.py",
)
SCENARIOS = (
    {
        "name": "AML-1 dedup preview",
        "patch": "fixes/sentinel_aml/aml_dedup_preview.patch",
        "tag": "aml1_vulnerable",
        "vulnerable_packages": ("./internal/httpapi",),
        "fixed_packages": ("./internal/httpapi",),
    },
    {
        "name": "AML-2 audit timeline",
        "patch": "fixes/sentinel_aml/aml_audit_timeline.patch",
        "tag": "aml2_vulnerable",
        "vulnerable_packages": ("./internal/httpapi",),
        "fixed_packages": ("./internal/httpapi",),
    },
    {
        "name": "AML-3 related graph",
        "patch": "fixes/sentinel_aml/aml_related_graph.patch",
        "tag": "aml3_vulnerable",
        "vulnerable_packages": ("./internal/httpapi", "./internal/graph"),
        "fixed_packages": ("./internal/httpapi", "./internal/graph"),
    },
    {
        "name": "AML-4 export redaction",
        "patch": "fixes/sentinel_aml/aml_export_redaction.patch",
        "tag": "aml4_vulnerable",
        "vulnerable_packages": ("./internal/httpapi", "./internal/exporting"),
        "fixed_packages": ("./internal/httpapi",),
    },
    {
        "name": "AML-5 network room",
        "patch": "fixes/sentinel_aml/aml_network_room.patch",
        "tag": "aml5_vulnerable",
        "vulnerable_packages": ("./internal/httpapi", "./internal/networkroom"),
        "fixed_packages": ("./internal/httpapi", "./internal/networkroom"),
    },
)


def validate_wave29_regression(
    repo_root: Path,
    *,
    python: str = sys.executable,
    go: str = "go",
    runner: Runner = subprocess.run,
    progress: TextIO | None = None,
) -> dict[str, Any]:
    planned_checks = (
        ("checker regression", lambda: check_checker_regression(repo_root, python=python, runner=runner)),
        ("matrix and Wave 29 Python evidence", lambda: check_matrix_and_wave29_python_evidence(repo_root, python=python, runner=runner)),
        ("reference sploit compile", lambda: check_exploit_compile(repo_root, python=python, runner=runner)),
        ("focused vulnerable build tags", lambda: check_vulnerable_build_tags(repo_root, go=go, runner=runner)),
        ("cumulative reference fix matrix", lambda: check_patch_scenarios_in_clean_copies(repo_root, python=python, go=go, runner=runner, progress=progress)),
    )
    checks = []
    for label, check_fn in planned_checks:
        started = time.monotonic()
        if progress is not None:
            print(f"wave29 regression: start {label}", file=progress, flush=True)
        check = check_fn()
        check["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if progress is not None:
            print(f"wave29 regression: {check['status']} {label} ({check['elapsed_seconds']}s)", file=progress, flush=True)
        checks.append(check)
    return {"status": aggregate_status(checks), "checks": checks}


def check_checker_regression(repo_root: Path, *, python: str, runner: Runner) -> dict[str, Any]:
    command = [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_checker_*.py"]
    completed = run_checked(command, cwd=repo_root, runner=runner, timeout=60, env=python_env())
    return command_check("wave29-checker-put-get-and-check-havoc-regression", "tests/test_checker_*.py", completed)


def check_matrix_and_wave29_python_evidence(repo_root: Path, *, python: str, runner: Runner) -> dict[str, Any]:
    failures: list[str] = []
    env = python_env()
    for pattern in PYTHON_TEST_PATTERNS:
        command = [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", pattern]
        completed = run_checked(command, cwd=repo_root, runner=runner, timeout=60, env=env)
        if completed.returncode != 0:
            failures.append(f"{pattern}: {command_detail(completed)}")
    return {
        "name": "wave29-matrix-and-full-gate-python-evidence",
        "path": "tests/test_competition_matrix_gate.py tests/test_wave29_gate.py",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_exploit_compile(repo_root: Path, *, python: str, runner: Runner) -> dict[str, Any]:
    failures: list[str] = []
    env = python_env()
    for relative in EXPLOITS:
        command = [python, "-B", "-m", "py_compile", relative]
        completed = run_checked(command, cwd=repo_root, runner=runner, timeout=20, env=env)
        if completed.returncode != 0:
            failures.append(f"{relative}: {command_detail(completed)}")
    return {
        "name": "wave29-all-five-exploits-compile-without-repo-cache",
        "path": "sploits/sentinel_aml",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_vulnerable_build_tags(repo_root: Path, *, go: str, runner: Runner) -> dict[str, Any]:
    failures: list[str] = []
    env = go_env()
    for scenario in SCENARIOS:
        command = [go, "test", "-p", "1", "-timeout", "120s", "-count=1", "-tags", str(scenario["tag"]), *scenario["vulnerable_packages"]]
        completed = run_checked(command, cwd=repo_root, runner=runner, timeout=150, env=env)
        if completed.returncode != 0:
            failures.append(f"{scenario['tag']}: {command_detail(completed)}")
    return {
        "name": "wave29-vulnerable-build-tags-pass-independently",
        "path": "internal/httpapi internal/networkroom internal/exporting internal/graph",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_patch_scenarios_in_clean_copies(
    repo_root: Path,
    *,
    python: str,
    go: str,
    runner: Runner,
    progress: TextIO | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    scenario_results: list[dict[str, str]] = []
    fixed_go_env = go_env()
    checker_env = python_env()
    with tempfile.TemporaryDirectory(prefix="sentinel-aml-wave29-regression.", dir=patch_checkout_temp_parent(repo_root, go)) as tmp:
        checkout = copy_clean_repo(repo_root, Path(tmp) / "repo")
        for scenario in SCENARIOS:
            if progress is not None:
                print(f"wave29 regression: apply {scenario['name']} patch", file=progress, flush=True)
            apply_command = ["git", "apply", "--whitespace=error", str(scenario["patch"])]
            applied = run_checked(apply_command, cwd=checkout, runner=runner, timeout=30, env=os.environ.copy())
            if applied.returncode != 0:
                failures.append(f"{scenario['name']} patch apply: {command_detail(applied)}")
                continue

            go_command = [go, "test", "-timeout", "120s", "-count=1", "-tags", str(scenario["tag"]), *scenario["fixed_packages"]]
            fixed = run_checked(go_command, cwd=checkout, runner=runner, timeout=150, env=fixed_go_env)
            if fixed.returncode != 0:
                failures.append(f"{scenario['name']} fixed tagged proof: {command_detail(fixed)}")
                continue

            scenario_results.append({"scenario": str(scenario["name"]), "status": "pass"})
        checker_command = [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_checker_*.py"]
        checker = run_checked(checker_command, cwd=checkout, runner=runner, timeout=60, env=checker_env)
        if checker.returncode != 0:
            failures.append(f"checker regression after cumulative patches: {command_detail(checker)}")
    return {
        "name": "wave29-reference-fixes-apply-in-clean-copy-and-preserve-checker",
        "path": "fixes/sentinel_aml tests/test_checker_*.py internal",
        "status": "pass" if not failures and len(scenario_results) == len(SCENARIOS) else "fail",
        "message": "" if not failures and len(scenario_results) == len(SCENARIOS) else "; ".join(failures),
        "scenarios": scenario_results,
    }


def copy_clean_repo(repo_root: Path, destination: Path) -> Path:
    ignore = shutil.ignore_patterns(
        ".git",
        ".gocache",
        ".appdata",
        ".pytest_cache",
        "__pycache__",
        "*.pyc",
        "coverage.out",
        "*.coverprofile",
        "*.test",
    )
    shutil.copytree(repo_root, destination, ignore=ignore)
    return destination


def patch_checkout_temp_parent(repo_root: Path, go: str) -> str | None:
    if os.name == "nt" or not go.lower().endswith(".exe"):
        return None
    repo_posix = repo_root.resolve().as_posix()
    if repo_posix.startswith("/mnt/"):
        return str(repo_root.resolve().parent)
    return None


def run_checked(command: list[str], *, cwd: Path, runner: Runner, timeout: int, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    try:
        return runner(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(command, 124, exc.output or "", exc.stderr or f"timed out after {timeout}s")
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def python_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPYCACHEPREFIX"] = tempfile.mkdtemp(prefix="sentinel-aml-wave29-pycache.")
    return env


def go_env() -> dict[str, str]:
    env = os.environ.copy()
    env["GOTOOLCHAIN"] = "local"
    env["GOFLAGS"] = "-mod=vendor"
    env["GOTELEMETRY"] = "off"
    env["GOCACHE"] = tempfile.mkdtemp(prefix="sentinel-aml-wave29-gocache.")
    env["APPDATA"] = tempfile.mkdtemp(prefix="sentinel-aml-wave29-appdata.")
    return env


def command_check(name: str, path: str, completed: subprocess.CompletedProcess[str]) -> dict[str, str]:
    return {
        "name": name,
        "path": path,
        "status": "pass" if completed.returncode == 0 else "fail",
        "message": "" if completed.returncode == 0 else command_detail(completed),
    }


def command_detail(completed: subprocess.CompletedProcess[str]) -> str:
    output = (completed.stderr or completed.stdout or "").strip()
    if len(output) > 1000:
        output = output[:1000] + "...[truncated]"
    return f"exit={completed.returncode} {output}".strip()


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    go = "go"
    python = sys.executable
    if "--go" in args:
        index = args.index("--go")
        go = args[index + 1]
    if "--python" in args:
        index = args.index("--python")
        python = args[index + 1]
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave29_regression(repo_root, python=python, go=go, progress=sys.stderr)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
