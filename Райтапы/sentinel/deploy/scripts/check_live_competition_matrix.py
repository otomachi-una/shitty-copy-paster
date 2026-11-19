#!/usr/bin/env python3
"""Live black-box competition matrix for Sentinel AML.

Default mode performs fast static validation. Use --run to start PostgreSQL,
the Go API, the worker, run checker PUT/GET/CHECK/HAVOC, execute the real
reference sploits, and repeat against isolated reference-fix copies.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CHECKER_OK = 101
COMPETITION_TAGS = "case_match_preview audit_detail_view entity_review_summary linked_case_export_detail network_room_detail"
DEFAULT_DATABASE_URL_TEMPLATE = "postgres://sentinel:sentinel@localhost:{port}/sentinel_aml_test?sslmode=disable"
SECRET_MARKERS = ("checker_secret", "private_state", "password", "session", "token")


@dataclasses.dataclass(frozen=True)
class AMLCase:
    aml_id: str
    place: int
    flag_store: str
    sploit: str
    fix_patch: str
    expected_path: str


AML_CASES: tuple[AMLCase, ...] = (
    AMLCase("AML-1", 1, "CaseNote.body", "sploits/sentinel_aml/aml_dedup_preview.py", "fixes/sentinel_aml/aml_dedup_preview.patch", "/api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview"),
    AMLCase("AML-2", 1, "CaseNote.body", "sploits/sentinel_aml/aml_audit_timeline.py", "fixes/sentinel_aml/aml_audit_timeline.patch", "/api/entities/{entity_hint}/activity"),
    AMLCase("AML-3", 2, "EDDRecord.confidential_comment", "sploits/sentinel_aml/aml_related_graph.py", "fixes/sentinel_aml/aml_related_graph.patch", "/api/graph/entities/{entity_hint}/edd-summaries"),
    AMLCase("AML-4", 1, "CaseNote.body", "sploits/sentinel_aml/aml_export_redaction.py", "fixes/sentinel_aml/aml_export_redaction.patch", "/api/exports/{export_id}"),
    AMLCase("AML-5", 2, "EDDRecord.confidential_comment", "sploits/sentinel_aml/aml_network_room.py", "fixes/sentinel_aml/aml_network_room.patch", "/api/network/rooms/{room_id}/dossier"),
)


class MatrixFailure(RuntimeError):
    pass


@dataclasses.dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float


class CommandRunner:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.commands: list[list[str]] = []

    def run(self, command: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout: float = 30, check: bool = True) -> CommandResult:
        self.commands.append(command)
        if self.dry_run:
            return CommandResult(command, 0, "", "", 0.0)
        start = time.monotonic()
        try:
            completed = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise MatrixFailure(f"command timed out after {timeout:.0f}s: {' '.join(command)}") from exc
        result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr, time.monotonic() - start)
        if check and result.returncode != 0:
            raise MatrixFailure(command_failure_message(result))
        return result


def command_failure_message(result: CommandResult) -> str:
    return (
        f"command exited {result.returncode}: {' '.join(result.command)}\n"
        f"stdout:\n{result.stdout[-4000:]}\n"
        f"stderr:\n{result.stderr[-4000:]}"
    )


def phase_plan() -> list[str]:
    phases: list[str] = [
        "static-preflight",
        "vulnerable:start-postgres-api-worker",
        "vulnerable:checker-check",
        "vulnerable:checker-havoc",
    ]
    for item in AML_CASES:
        phases.extend(
            [
                f"{item.aml_id}:checker-put",
                f"{item.aml_id}:reference-sploit-extracts-flag",
                f"{item.aml_id}:checker-get",
                f"{item.aml_id}:checker-check",
                f"{item.aml_id}:checker-havoc",
                f"{item.aml_id}:apply-reference-fix-isolated-copy",
                f"{item.aml_id}:fixed-start-postgres-api-worker",
                f"{item.aml_id}:fixed-checker-put",
                f"{item.aml_id}:fixed-reference-sploit-blocked",
                f"{item.aml_id}:fixed-checker-get",
                f"{item.aml_id}:fixed-checker-check",
                f"{item.aml_id}:fixed-checker-havoc",
            ]
        )
    return phases


def static_checks(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    required = [
        "checkers/sentinel_aml/checker.py",
        "cmd/aml-api/main.go",
        "cmd/aml-worker/main.go",
        "docker-compose.yml",
        "scripts/migrate/main.go",
    ]
    for item in AML_CASES:
        required.extend([item.sploit, item.fix_patch])
    for rel in required:
        path = repo_root / rel
        checks.append({"name": f"required:{rel}", "status": "pass" if path.exists() else "fail", "message": "" if path.exists() else "missing"})

    ids = [item.aml_id for item in AML_CASES]
    checks.append({"name": "aml1-through-aml5-present", "status": "pass" if ids == ["AML-1", "AML-2", "AML-3", "AML-4", "AML-5"] else "fail", "message": ",".join(ids)})
    checks.append({"name": "phase-plan-includes-fixes", "status": "pass" if all(f"{item.aml_id}:fixed-reference-sploit-blocked" in phase_plan() for item in AML_CASES) else "fail", "message": ""})
    checks.append({"name": "phase-plan-includes-checker-check-havoc", "status": "pass" if all(f"{item.aml_id}:checker-check" in phase_plan() and f"{item.aml_id}:checker-havoc" in phase_plan() for item in AML_CASES) else "fail", "message": ""})

    script_text = (repo_root / "scripts/check_live_competition_matrix.py").read_text(encoding="utf-8")
    forbidden = ["ps" + "ql ", "SEL" + "ECT ", "sql" + "ite3", "/api/de" + "bug", "/api/ad" + "min"]
    leaks = [marker for marker in forbidden if marker in script_text]
    checks.append({"name": "no-direct-db-or-debug-shortcuts", "status": "pass" if not leaks else "fail", "message": ", ".join(leaks)})

    status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
    return {"status": status, "checks": checks, "phase_plan": phase_plan()}


def normalize_attack_data_for_aml(item: AMLCase, attack_data: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(attack_data)
    if item.aml_id == "AML-2" and not (
        str(normalized.get("entity_ref", "")).strip() or str(normalized.get("party_ref", "")).strip()
    ):
        raise MatrixFailure("AML-2 public attack data lacks entity_ref or party_ref")
    return normalized


class ServiceInstance:
    def __init__(self, repo_root: Path, *, docker: str, go: str, runner: CommandRunner, label: str, api_port: int, pg_port: int, tags: str = COMPETITION_TAGS) -> None:
        self.repo_root = repo_root
        self.docker = docker
        self.go = go
        self.runner = runner
        self.label = label
        self.api_port = api_port
        self.pg_port = pg_port
        self.tags = tags
        self.project = safe_project_name(label)
        self.database_url = DEFAULT_DATABASE_URL_TEMPLATE.format(port=pg_port)
        self.env = live_env(os.environ, self.database_url, pg_port)
        self.api_process: subprocess.Popen[str] | None = None
        self.worker_process: subprocess.Popen[str] | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    def __enter__(self) -> "ServiceInstance":
        self.runner.run(compose_command(self.docker, self.project, "up", "-d", "postgres"), cwd=self.repo_root, env=self.env, timeout=90)
        self.wait_for_postgres()
        self.runner.run([self.go, "run", "-tags", self.tags, "./scripts/migrate"], cwd=self.repo_root, env=self.env, timeout=90)
        self.api_process = start_process([self.go, "run", "-tags", self.tags, "./cmd/aml-api", "-addr", f"127.0.0.1:{self.api_port}"], self.repo_root, self.env)
        self.worker_process = start_process([self.go, "run", "-tags", self.tags, "./cmd/aml-worker", "--interval", "1ms"], self.repo_root, self.env)
        self.wait_for_health()
        time.sleep(3)
        if self.worker_process is not None and self.worker_process.poll() is not None:
            stdout, stderr = self.worker_process.communicate(timeout=1)
            raise MatrixFailure(f"{self.label}: worker exited during startup code={self.worker_process.returncode} stdout={stdout[-2000:]} stderr={stderr[-2000:]}")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        for process in (self.worker_process, self.api_process):
            if process is not None:
                terminate_process_tree(process)
        self.runner.run(compose_command(self.docker, self.project, "down", "--remove-orphans", "-v"), cwd=self.repo_root, env=self.env, timeout=90, check=False)

    def wait_for_postgres(self) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            result = self.runner.run(compose_command(self.docker, self.project, "exec", "-T", "postgres", "pg_isready", "-U", "sentinel", "-d", "sentinel_aml_test"), cwd=self.repo_root, env=self.env, timeout=10, check=False)
            if result.returncode == 0:
                return
            time.sleep(1)
        raise MatrixFailure(f"{self.label}: postgres did not become healthy")

    def wait_for_health(self) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            for name, process in (("api", self.api_process), ("worker", self.worker_process)):
                if process is not None and process.poll() is not None:
                    stdout, stderr = process.communicate(timeout=1)
                    raise MatrixFailure(f"{self.label}: {name} exited early code={process.returncode} stdout={stdout[-2000:]} stderr={stderr[-2000:]}")
            try:
                with urllib.request.urlopen(self.base_url + "/healthz", timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.5)
        raise MatrixFailure(f"{self.label}: api health did not become ready")


def live_env(base_env: dict[str, str], database_url: str, pg_port: int) -> dict[str, str]:
    env = dict(base_env)
    env["DATABASE_URL"] = database_url
    env["SENTINEL_AML_POSTGRES_PORT"] = str(pg_port)
    env["GOTOOLCHAIN"] = "local"
    env["GOFLAGS"] = "-mod=vendor"
    env["GOTELEMETRY"] = "off"
    return env


def compose_command(docker: str, project: str, *args: str) -> list[str]:
    return [docker, "compose", "-p", project, *args]


def safe_project_name(label: str) -> str:
    return "sentinel-aml-live-" + "".join(ch.lower() if ch.isalnum() else "-" for ch in label)[:32].strip("-")


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


def checker_command(python: str, action: str, *args: str) -> list[str]:
    return [python, str(ROOT / "checkers/sentinel_aml/checker.py"), action, *args]


def run_checker(
    runner: CommandRunner,
    python: str,
    action: str,
    host: str,
    *args: str,
    timeout: float = 45,
    secret: str | None = None,
) -> CommandResult:
    env = None
    if secret is not None or action in ("check", "havoc"):
        env = dict(os.environ)
        env["SENTINEL_AML_CHECKER_SECRET"] = secret or f"live-matrix-{action}-{time.time_ns()}"
    result = runner.run(checker_command(python, action, host, *args), cwd=ROOT, env=env, timeout=timeout, check=False)
    if result.returncode != CHECKER_OK:
        raise MatrixFailure(command_failure_message(result))
    if action != "put" and contains_secret_marker(result.stderr):
        raise MatrixFailure(f"checker {action} leaked secret marker in stderr")
    return result


def checker_put(runner: CommandRunner, python: str, host: str, flag: str, place: int, secret: str) -> tuple[str, dict[str, Any]]:
    result = run_checker(runner, python, "put", host, flag, str(place), secret=secret)
    private_state = result.stderr.strip()
    attack_data = json.loads(result.stdout)
    if not isinstance(private_state, str) or private_state == "" or not isinstance(attack_data, dict):
        raise MatrixFailure(f"checker put returned malformed PFR streams: stdout={result.stdout!r} stderr={result.stderr!r}")
    if contains_secret_marker(json.dumps(attack_data, sort_keys=True).lower()):
        raise MatrixFailure("checker public attack data leaked private marker")
    return private_state, attack_data


def contains_secret_marker(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in SECRET_MARKERS)


def run_sploit(runner: CommandRunner, python: str, item: AMLCase, host: str, port: int, attack_data: dict[str, Any], *, timeout: float = 60) -> CommandResult:
    return runner.run(
        [python, str(ROOT / item.sploit), host, str(port), json.dumps(attack_data, sort_keys=True), "--timeout", "8"],
        cwd=ROOT,
        timeout=timeout,
        check=False,
    )


def assert_sploit_extracts(result: CommandResult, flag: str, item: AMLCase) -> None:
    if result.returncode != 0:
        raise MatrixFailure(f"{item.aml_id} sploit failed before extracting flag: {command_failure_message(result)}")
    if flag not in result.stdout:
        raise MatrixFailure(f"{item.aml_id} sploit did not print expected flag. stdout={result.stdout!r} stderr={result.stderr!r}")


def assert_sploit_blocked(result: CommandResult, flag: str, item: AMLCase) -> None:
    if flag in result.stdout:
        raise MatrixFailure(f"{item.aml_id} fixed profile still leaked the flag: stdout={result.stdout!r}")
    if result.returncode == 0:
        raise MatrixFailure(f"{item.aml_id} fixed profile sploit exited 0 without flag; expected explicit extraction failure")


def copy_repo_for_fix(repo_root: Path, item: AMLCase) -> tempfile.TemporaryDirectory[str]:
    temp = tempfile.TemporaryDirectory(prefix=f"sentinel-aml-{item.aml_id.lower()}-fixed.")
    target = Path(temp.name) / "repo"
    ignore = shutil.ignore_patterns(".git", "tmp", "__pycache__", "*.pyc", ".gocache*", ".appdata*", "*.exe")
    shutil.copytree(repo_root, target, ignore=ignore)
    return temp


def apply_reference_fix(runner: CommandRunner, fixed_root: Path, item: AMLCase) -> None:
    runner.run(["git", "apply", "--check", "--whitespace=nowarn", item.fix_patch], cwd=fixed_root, timeout=30)
    runner.run(["git", "apply", "--whitespace=nowarn", item.fix_patch], cwd=fixed_root, timeout=30)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_live_matrix(repo_root: Path, *, python: str, go: str, docker: str) -> dict[str, Any]:
    started = time.monotonic()
    runner = CommandRunner()
    evidence: dict[str, Any] = {"status": "pass", "rows": [], "environment": {"python": python, "go": go, "docker": docker, "tags": COMPETITION_TAGS}}
    static = static_checks(repo_root)
    if static["status"] != "pass":
        raise MatrixFailure("static preflight failed")

    with ServiceInstance(repo_root, docker=docker, go=go, runner=runner, label="vulnerable", api_port=free_port(), pg_port=free_port()) as service:
        run_checker(runner, python, "check", service.base_url)
        run_checker(runner, python, "havoc", service.base_url)
        for item in AML_CASES:
            row = run_vulnerable_row(runner, python, service, item)
            evidence["rows"].append(row)

    for item in AML_CASES:
        with copy_repo_for_fix(repo_root, item) as temp:
            fixed_root = Path(temp) / "repo"
            apply_reference_fix(runner, fixed_root, item)
            with ServiceInstance(fixed_root, docker=docker, go=go, runner=runner, label=f"{item.aml_id}-fixed", api_port=free_port(), pg_port=free_port()) as fixed_service:
                row = run_fixed_row(runner, python, fixed_service, item)
                evidence["rows"].append(row)

    evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return evidence


def run_vulnerable_row(runner: CommandRunner, python: str, service: ServiceInstance, item: AMLCase) -> dict[str, Any]:
    flag = f"SENTINEL{{W34_{item.aml_id.replace('-', '_')}_{int(time.time() * 1000)}}}"
    secret = f"live-matrix-{item.aml_id}-vulnerable-{time.time_ns()}"
    private_state, attack_data = checker_put(runner, python, service.base_url, flag, item.place, secret)
    attack_data = normalize_attack_data_for_aml(item, attack_data)
    sploit = run_sploit(runner, python, item, "127.0.0.1", service.api_port, attack_data)
    assert_sploit_extracts(sploit, flag, item)
    run_checker(runner, python, "get", service.base_url, private_state, flag, str(item.place), secret=secret)
    run_checker(runner, python, "check", service.base_url, secret=secret)
    run_checker(runner, python, "havoc", service.base_url, secret=secret)
    return {"aml": item.aml_id, "profile": "vulnerable", "status": "pass", "place": item.place, "path": item.expected_path, "sploit_elapsed": round(sploit.elapsed, 3)}


def run_fixed_row(runner: CommandRunner, python: str, service: ServiceInstance, item: AMLCase) -> dict[str, Any]:
    flag = f"SENTINEL{{W34_FIXED_{item.aml_id.replace('-', '_')}_{int(time.time() * 1000)}}}"
    secret = f"live-matrix-{item.aml_id}-fixed-{time.time_ns()}"
    private_state, attack_data = checker_put(runner, python, service.base_url, flag, item.place, secret)
    attack_data = normalize_attack_data_for_aml(item, attack_data)
    sploit = run_sploit(runner, python, item, "127.0.0.1", service.api_port, attack_data)
    assert_sploit_blocked(sploit, flag, item)
    run_checker(runner, python, "get", service.base_url, private_state, flag, str(item.place), secret=secret)
    run_checker(runner, python, "check", service.base_url, secret=secret)
    run_checker(runner, python, "havoc", service.base_url, secret=secret)
    return {"aml": item.aml_id, "profile": "fixed", "status": "pass", "place": item.place, "path": item.expected_path, "sploit_exit": sploit.returncode}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Sentinel AML live black-box competition matrix")
    parser.add_argument("--run", action="store_true", help="run the full live Docker/PostgreSQL/API/worker matrix")
    parser.add_argument("--python", default=sys.executable, help="Python executable")
    parser.add_argument("--go", default="go", help="Go executable")
    parser.add_argument("--docker", default="docker", help="Docker executable")
    parser.add_argument("--json-output", type=Path, help="write machine-readable evidence JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = run_live_matrix(ROOT, python=args.python, go=args.go, docker=args.docker) if args.run else static_checks(ROOT)
    except MatrixFailure as exc:
        result = {"status": "fail", "error": str(exc)}
    if args.json_output:
        args.json_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
