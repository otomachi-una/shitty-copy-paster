#!/usr/bin/env python3
"""Run archive-free live runtime smoke for Sentinel AML."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from run_go_release_tests import run_command


DEFAULT_DATABASE_URL = "postgres://sentinel:sentinel@postgres:5432/sentinel_aml_test?sslmode=disable"
DEFAULT_BASE_URL = "http://127.0.0.1:18080"
SECRET_MARKERS = ("runtime-smoke-private-note", "runtime-smoke-confidential-edd")


class SmokeFailure(RuntimeError):
    pass


def runtime_env(base_env: dict[str, str], database_url: str, cache_dir: str, appdata_dir: str) -> dict[str, str]:
    env = dict(base_env)
    env["DATABASE_URL"] = database_url
    env["GOTOOLCHAIN"] = "local"
    env["GOFLAGS"] = "-mod=vendor"
    env["GOTELEMETRY"] = "off"
    env["GOCACHE"] = cache_dir
    env["APPDATA"] = appdata_dir
    env["WSLENV"] = merge_wslenv(env.get("WSLENV", ""), ("DATABASE_URL",))
    return env


def merge_wslenv(existing: str, names: tuple[str, ...]) -> str:
    entries = [entry for entry in existing.split(":") if entry]
    present = {entry.split("/", 1)[0] for entry in entries}
    entries.extend(name for name in names if name not in present)
    return ":".join(entries)


def run_runtime_smoke(
    repo_root: Path,
    *,
    go: str,
    docker: str,
    database_url: str,
    base_url: str,
    skip_if_docker_unavailable: bool,
    migrate_package: str = "./scripts/migrate",
    compose_file: Path | None = None,
    compose_env_file: Path | None = None,
    stdout=sys.stdout,
    stderr=sys.stderr,
) -> int:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="sentinel-aml-runtime-gocache.") as cache_dir:
        with tempfile.TemporaryDirectory(prefix="sentinel-aml-runtime-appdata.") as appdata_dir:
            env = runtime_env(os.environ, database_url, cache_dir, appdata_dir)
            try:
                check_docker(repo_root, docker, skip_if_docker_unavailable, stdout, stderr, compose_file, compose_env_file)
            except SmokeFailure as exc:
                print(f"runtime-smoke: docker unavailable: {exc}", file=stderr, flush=True)
                return 77 if skip_if_docker_unavailable else 1
            try:
                if compose_file is not None:
                    try:
                        run_phase(
                            "compose-stack-up",
                            docker_compose_command(docker, compose_file, "up", "--build", "-d", env_file=compose_env_file),
                            repo_root,
                            env,
                            180,
                            stdout,
                            stderr,
                        )
                        wait_for_http_health(base_url, stdout)
                        exercise_http_workflow(repo_root, go, env, base_url, stdout, stderr)
                    finally:
                        run_phase(
                            "compose-stack-down",
                            docker_compose_command(docker, compose_file, "down", "--remove-orphans", "-v", env_file=compose_env_file),
                            repo_root,
                            env,
                            90,
                            stdout,
                            stderr,
                        )
                    print(f"runtime-smoke: pass elapsed={time.monotonic() - started:.3f}s", file=stdout, flush=True)
                    return 0
                run_phase(
                    "postgres-up",
                    docker_compose_command(docker, compose_file, "up", "-d", "postgres", env_file=compose_env_file),
                    repo_root,
                    env,
                    90,
                    stdout,
                    stderr,
                )
                wait_for_postgres(repo_root, docker, env, database_url, stdout, stderr, compose_file, compose_env_file)
                run_phase("migrations", [go, "run", migrate_package], repo_root, env, 90, stdout, stderr)
                run_worker_twice(repo_root, go, env, stdout, stderr)
                with start_api(repo_root, go, env, base_url, stdout, stderr):
                    exercise_http_workflow(repo_root, go, env, base_url, stdout, stderr)
            except (SmokeFailure, subprocess.TimeoutExpired) as exc:
                print(f"runtime-smoke: fail {exc}", file=stderr, flush=True)
                return 1
    print(f"runtime-smoke: pass elapsed={time.monotonic() - started:.3f}s", file=stdout, flush=True)
    return 0


def check_docker(
    repo_root: Path,
    docker: str,
    skip_if_docker_unavailable: bool,
    stdout,
    stderr,
    compose_file: Path | None = None,
    compose_env_file: Path | None = None,
) -> None:
    print("runtime-smoke: phase docker-available start timeout=20s", file=stdout, flush=True)
    completed = run_command(
        docker_compose_command(docker, compose_file, "config", "--services", env_file=compose_env_file),
        cwd=repo_root,
        env=os.environ,
        timeout=20,
    )
    if completed.stdout:
        print(completed.stdout, end="", file=stdout, flush=True)
    if completed.stderr:
        print(completed.stderr, end="", file=stderr, flush=True)
    if completed.returncode != 0:
        message = "docker compose config failed; full acceptance requires Docker/PostgreSQL"
        if skip_if_docker_unavailable:
            raise SmokeFailure(message + " (skip mode requested)")
        raise SmokeFailure(message)
    print("runtime-smoke: phase docker-available exit=0", file=stdout, flush=True)


def docker_compose_command(docker: str, compose_file: Path | None, *args: str, env_file: Path | None = None) -> list[str]:
    command = [docker, "compose"]
    if env_file is not None:
        command.extend(["--env-file", env_file.as_posix()])
    if compose_file is not None:
        command.extend(["-f", compose_file.as_posix()])
    command.extend(args)
    return command


def run_phase(command_name: str, command: list[str], cwd: Path, env: dict[str, str], timeout: float, stdout, stderr) -> None:
    start = time.monotonic()
    print(f"runtime-smoke: phase {command_name} start timeout={timeout:.0f}s", file=stdout, flush=True)
    print(f"runtime-smoke: command {' '.join(command)}", file=stdout, flush=True)
    completed = run_command(command, cwd=cwd, env=env, timeout=timeout)
    if completed.stdout:
        print(completed.stdout, end="", file=stdout, flush=True)
    if completed.stderr:
        print(completed.stderr, end="", file=stderr, flush=True)
    elapsed = time.monotonic() - start
    print(f"runtime-smoke: phase {command_name} exit={completed.returncode} elapsed={elapsed:.3f}s", file=stdout, flush=True)
    if completed.returncode != 0:
        raise SmokeFailure(f"{command_name} exited {completed.returncode}")


def wait_for_postgres(
    repo_root: Path,
    docker: str,
    env: dict[str, str],
    database_url: str,
    stdout,
    stderr,
    compose_file: Path | None = None,
    compose_env_file: Path | None = None,
) -> None:
    parsed = urllib.parse.urlsplit(database_url)
    database = parsed.path.lstrip("/") or "sentinel_aml_test"
    user = urllib.parse.unquote(parsed.username or "sentinel")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        completed = run_command(
            docker_compose_command(
                docker,
                compose_file,
                "exec",
                "-T",
                "postgres",
                "pg_isready",
                "-U",
                user,
                "-d",
                database,
                env_file=compose_env_file,
            ),
            cwd=repo_root,
            env=env,
            timeout=10,
        )
        if completed.returncode == 0:
            print("runtime-smoke: postgres health exit=0", file=stdout, flush=True)
            return
        if completed.stderr:
            print(completed.stderr, end="", file=stderr, flush=True)
        time.sleep(1)
    raise SmokeFailure("postgres did not become healthy within 60s")


def wait_for_http_health(base_url: str, stdout) -> None:
    deadline = time.monotonic() + 90
    health_url = base_url.rstrip("/") + "/healthz"
    while time.monotonic() < deadline:
        try:
            response = request_json("GET", health_url, expected_status=200, timeout=2)
        except SmokeFailure:
            time.sleep(0.5)
            continue
        if response.get("status") == "ok":
            print("runtime-smoke: gateway health exit=0", file=stdout, flush=True)
            return
    raise SmokeFailure("HTTP gateway health did not become ready within 90s")


def run_worker_twice(repo_root: Path, go: str, env: dict[str, str], stdout, stderr) -> None:
    for index in range(1, 3):
        run_phase(f"worker-restart-{index}", [go, "run", "./cmd/aml-worker", "--once"], repo_root, env, 30, stdout, stderr)


class start_api:
    def __init__(self, repo_root: Path, go: str, env: dict[str, str], base_url: str, stdout, stderr) -> None:
        self.repo_root = repo_root
        self.go = go
        self.env = env
        self.base_url = base_url.rstrip("/")
        self.stdout = stdout
        self.stderr = stderr
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> "start_api":
        host, port = bind_host_port(self.base_url)
        command = [self.go, "run", "./cmd/aml-api", "-addr", f"{host}:{port}"]
        print("runtime-smoke: phase api-start start timeout=60s", file=self.stdout, flush=True)
        print(f"runtime-smoke: command {' '.join(command)}", file=self.stdout, flush=True)
        popen_kwargs: dict[str, object] = {}
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        self.process = subprocess.Popen(
            command,
            cwd=self.repo_root,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **popen_kwargs,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate(timeout=1)
                raise SmokeFailure(f"api exited during startup code={self.process.returncode} stdout={stdout} stderr={stderr}")
            try:
                response = request_json("GET", self.base_url + "/healthz", expected_status=200, timeout=2)
            except SmokeFailure:
                time.sleep(0.5)
                continue
            if response.get("status") == "ok":
                print("runtime-smoke: api health exit=0", file=self.stdout, flush=True)
                return self
        terminate_process_tree(self.process)
        raise SmokeFailure("api health did not become ready within 60s")

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            terminate_process_tree(self.process)
        stdout, stderr = self.process.communicate(timeout=1)
        if stdout:
            print(stdout, end="", file=self.stdout, flush=True)
        if stderr:
            print(stderr, end="", file=self.stderr, flush=True)
        graceful = "aml-api stopped" in stdout
        print(f"runtime-smoke: api-stop exit={self.process.returncode} graceful={str(graceful).lower()}", file=self.stdout, flush=True)


def exercise_http_workflow(repo_root: Path, go: str, env: dict[str, str], base_url: str, stdout, stderr) -> None:
    suffix = str(int(time.time() * 1000))
    username = f"runtime_smoke_{suffix}"
    password = f"runtime-smoke-pass-{suffix}"
    entity_hint = f"runtime-smoke-entity-{suffix}"
    print("runtime-smoke: phase api-workflow start timeout=60s", file=stdout, flush=True)
    auth = request_json("POST", base_url + "/api/auth/register", {"username": username, "password": password}, expected_status=201)
    token = auth["session"]["token"]
    login = request_json("POST", base_url + "/api/auth/login", {"username": username, "password": password}, expected_status=200)
    token = login["session"]["token"]
    request_json("GET", base_url + "/api/auth/me", token=token, expected_status=200)

    customer = request_json(
        "POST",
        base_url + "/api/customers",
        {
            "display_name": "Runtime Smoke Customer",
            "customer_type": "individual",
            "country": "US",
            "registration_number": f"runtime-smoke-{suffix}",
            "risk_level": "medium",
            "entity_hint": entity_hint,
            "status": "active",
        },
        token=token,
        expected_status=201,
    )
    customer_id = customer["id"]
    account = request_json(
        "POST",
        base_url + f"/api/customers/{customer_id}/accounts",
        {"iban_like": f"RTSMOKE{suffix}", "currency": "USD", "status": "active"},
        token=token,
        expected_status=201,
    )
    transaction = request_json(
        "POST",
        base_url + "/api/transactions",
        {
            "account_id": account["id"],
            "counterparty_name": "High Risk Counterparty",
            "counterparty_country": "IR",
            "counterparty_fingerprint": f"runtime-smoke-fp-{suffix}",
            "amount": "25000.00",
            "currency": "USD",
            "direction": "outbound",
            "purpose": "runtime smoke sanctions review",
            "trace_id": f"runtime-smoke-trace-{suffix}",
        },
        token=token,
        expected_status=201,
    )
    alerts = request_json("GET", base_url + "/api/alerts/queue", token=token, expected_status=200)["alerts"]
    matching_alert = next((alert for alert in alerts if alert["transaction_id"] == transaction["id"]), None)
    if matching_alert is None:
        raise SmokeFailure("transaction did not create deterministic alert")
    alert_id = matching_alert["id"]
    request_json("POST", base_url + f"/api/alerts/{alert_id}/claim", token=token, expected_status=200)
    case = request_json(
        "POST",
        base_url + f"/api/alerts/{alert_id}/case",
        {
            "public_summary": "Runtime smoke case",
            "status": "OPEN",
            "dedup_hint": f"runtime-smoke-dedup-{suffix}",
        },
        token=token,
        expected_status=201,
    )
    case_id = case["id"]
    note_body = f"runtime-smoke-private-note-{suffix}"
    edd_comment = f"runtime-smoke-confidential-edd-{suffix}"
    request_json("POST", base_url + f"/api/cases/{case_id}/notes", {"visibility": "private", "body": note_body}, token=token, expected_status=201)
    notes = request_json("GET", base_url + f"/api/cases/{case_id}/notes", token=token, expected_status=200)
    assert_contains(notes, note_body, "owner case-note readback")
    edd = request_json(
        "POST",
        base_url + f"/api/customers/{customer_id}/edd",
        {
            "source_of_funds": "verified payroll",
            "risk_rationale": "runtime smoke deterministic review",
            "confidential_comment": edd_comment,
            "review_status": "IN_REVIEW",
        },
        token=token,
        expected_status=201,
    )
    assert_contains(edd, edd_comment, "owner EDD create readback")
    edd_read = request_json("GET", base_url + f"/api/customers/{customer_id}/edd", token=token, expected_status=200)
    assert_contains(edd_read, edd_comment, "owner EDD get readback")

    related_auth = request_json(
        "POST",
        base_url + "/api/auth/register",
        {"username": f"runtime_smoke_related_{suffix}", "password": password},
        expected_status=201,
    )
    related_token = related_auth["session"]["token"]
    related_customer = request_json(
        "POST",
        base_url + "/api/customers",
        {
            "display_name": "Runtime Smoke Related Customer",
            "customer_type": "organization",
            "country": "US",
            "registration_number": f"runtime-smoke-related-{suffix}",
            "risk_level": "medium",
            "entity_hint": entity_hint,
            "status": "active",
        },
        token=related_token,
        expected_status=201,
    )
    related_account = request_json(
        "POST",
        base_url + f"/api/customers/{related_customer['id']}/accounts",
        {"iban_like": f"RTSMOKEREL{suffix}", "currency": "USD", "status": "active"},
        token=related_token,
        expected_status=201,
    )
    related_transaction = request_json(
        "POST",
        base_url + "/api/transactions",
        {
            "account_id": related_account["id"],
            "counterparty_name": "Related High Risk Counterparty",
            "counterparty_country": "IR",
            "counterparty_fingerprint": f"runtime-smoke-related-fp-{suffix}",
            "amount": "17500.00",
            "currency": "USD",
            "direction": "outbound",
            "purpose": "runtime smoke related sanctions review",
            "trace_id": f"runtime-smoke-related-trace-{suffix}",
        },
        token=related_token,
        expected_status=201,
    )
    related_alerts = request_json("GET", base_url + "/api/alerts/queue", token=related_token, expected_status=200)["alerts"]
    related_alert = next((alert for alert in related_alerts if alert["transaction_id"] == related_transaction["id"]), None)
    if related_alert is None:
        raise SmokeFailure("related transaction did not create deterministic alert")
    request_json("POST", base_url + f"/api/alerts/{related_alert['id']}/claim", token=related_token, expected_status=200)
    related_case = request_json(
        "POST",
        base_url + f"/api/alerts/{related_alert['id']}/case",
        {
            "public_summary": "Runtime smoke related case",
            "status": "OPEN",
            "dedup_hint": f"runtime-smoke-related-dedup-{suffix}",
        },
        token=related_token,
        expected_status=201,
    )

    run_phase("worker-network-room-materialize", [go, "run", "./cmd/aml-worker", "--once"], repo_root, env, 30, stdout, stderr)

    rooms_response = request_json("GET", base_url + "/api/network/rooms", token=token, expected_status=200)
    assert_not_contains(rooms_response, SECRET_MARKERS, "/api/network/rooms")
    matching_room = next(
        (
            room
            for room in rooms_response.get("rooms", [])
            if room.get("entity_hint") == entity_hint and room.get("typology_hint") == "high-risk-country"
        ),
        None,
    )
    if matching_room is None:
        raise SmokeFailure(f"worker did not materialize deterministic network room for {entity_hint}")
    if matching_room.get("case_count", 0) < 2 or matching_room.get("participant_count", 0) < 2:
        raise SmokeFailure(f"network room is missing matching case or participant links: {matching_room}")
    dossier = request_json("GET", base_url + f"/api/network/rooms/{matching_room['id']}/dossier", token=token, expected_status=200)
    assert_not_contains(dossier, SECRET_MARKERS, "/api/network/rooms/{room_id}/dossier")
    dossier_text = json.dumps(dossier, sort_keys=True)
    if str(case_id) not in dossier_text or str(related_case["id"]) not in dossier_text:
        raise SmokeFailure("network room dossier did not include both deterministic case references")

    side_views = [
        ("GET", f"/api/cases/{case_id}/timeline"),
        ("GET", f"/api/cases/{case_id}/duplicates"),
        ("GET", f"/api/graph/entities/{entity_hint}/edd-summaries"),
        ("GET", "/api/network/rooms"),
    ]
    for method, path in side_views:
        response = request_json(method, base_url + path, token=token, expected_status=200)
        assert_not_contains(response, SECRET_MARKERS, path)
    print("runtime-smoke: phase api-workflow exit=0", file=stdout, flush=True)


def request_json(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    *,
    token: str | None = None,
    expected_status: int,
    timeout: float = 5,
) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        status = exc.code
    except OSError as exc:
        raise SmokeFailure(f"{method} {url} failed: {exc}") from exc
    if status != expected_status:
        raise SmokeFailure(f"{method} {url} expected {expected_status}, got {status}: {payload}")
    return json.loads(payload) if payload.strip() else {}


def assert_contains(value: Any, marker: str, context: str) -> None:
    if marker not in json.dumps(value, sort_keys=True):
        raise SmokeFailure(f"{context} did not contain expected owner marker")


def assert_not_contains(value: Any, markers: tuple[str, ...], context: str) -> None:
    serialized = json.dumps(value, sort_keys=True)
    leaked = [marker for marker in markers if marker in serialized]
    if leaked:
        raise SmokeFailure(f"{context} leaked private markers: {leaked}")


def bind_host_port(base_url: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.port is None:
        raise SmokeFailure("--base-url must be an http URL with explicit host and port")
    host = parsed.hostname
    port = parsed.port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        if probe.connect_ex((host, port)) == 0:
            raise SmokeFailure(f"{base_url} is already in use")
    return host, port


def http_port_from_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.port is None:
        raise SmokeFailure("--base-url must include an explicit HTTP host port")
    return str(parsed.port)


def terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.wait(timeout=5)
            return
        except (OSError, subprocess.TimeoutExpired):
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            process.terminate()
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    if os.name == "nt":
        process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            process.kill()
    process.wait(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL))
    parser.add_argument("--base-url", default=os.environ.get("SENTINEL_AML_RUNTIME_SMOKE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--migrate-package", default=os.environ.get("SENTINEL_AML_MIGRATE_PACKAGE", "./scripts/migrate"))
    parser.add_argument("--compose-file", type=Path)
    parser.add_argument(
        "--skip-if-docker-unavailable",
        action="store_true",
        help="return 77 with a clear message when Docker/PostgreSQL is unavailable; this is not full acceptance",
    )
    args = parser.parse_args(argv)
    return run_runtime_smoke(
        Path(__file__).resolve().parents[1],
        go=args.go,
        docker=args.docker,
        database_url=args.database_url,
        base_url=args.base_url,
        skip_if_docker_unavailable=args.skip_if_docker_unavailable,
        migrate_package=args.migrate_package,
        compose_file=args.compose_file,
    )


if __name__ == "__main__":
    raise SystemExit(main())
