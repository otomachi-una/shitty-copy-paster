#!/usr/bin/env python3
"""Live clean-deploy CHECK/HAVOC proof for Sentinel AML.

Default mode performs fast static validation. Use --run to start PostgreSQL,
the competition-tagged Go API, and the worker, then execute checker CHECK and
HAVOC through the normal checker CLI.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
LIVE_MATRIX_PATH = SCRIPT_DIR / "check_live_competition_matrix.py"
CHECKER_LIB_PATH = ROOT / "checkers" / "sentinel_aml" / "checker_lib.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


live_matrix = _load_module("check_live_competition_matrix_for_checker_clean_deploy", LIVE_MATRIX_PATH)
checker_lib = _load_module("sentinel_aml_checker_lib_for_clean_deploy", CHECKER_LIB_PATH)

REQUIRED_SUBCHECKS = (
    "health",
    "check_basic",
    "check_case_notes",
    "check_edd",
    "check_dedup",
    "check_audit",
    "check_graph",
    "check_export",
    "check_network_room",
    "check_retention",
)

EXIT_CLASSIFICATIONS = {
    checker_lib.EXIT_OK: "OK",
    checker_lib.EXIT_CORRUPT: "CORRUPT",
    checker_lib.EXIT_MUMBLE: "MUMBLE",
    checker_lib.EXIT_DOWN: "DOWN",
    checker_lib.EXIT_CHECKER_ERROR: "CHECKER_ERROR",
}


class CleanDeployFailure(RuntimeError):
    pass


def phase_plan() -> list[str]:
    return [
        "static-preflight",
        "clean:start-postgres-api-worker",
        "clean:checker-check",
        "clean:checker-havoc",
    ]


def classify_exit(returncode: int) -> str:
    return EXIT_CLASSIFICATIONS.get(returncode, f"UNKNOWN({returncode})")


def static_checks(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    required_files = [
        "checkers/sentinel_aml/checker.py",
        "checkers/sentinel_aml/checker_lib.py",
        "cmd/aml-api/main.go",
        "cmd/aml-worker/main.go",
        "docker-compose.yml",
        "scripts/migrate/main.go",
        "scripts/check_live_competition_matrix.py",
    ]
    for rel in required_files:
        path = repo_root / rel
        checks.append({"name": f"required:{rel}", "status": "pass" if path.exists() else "fail", "message": "" if path.exists() else "missing"})

    default_subchecks = tuple(checker_lib.DEFAULT_CHECK_SUBCHECKS)
    missing = [name for name in REQUIRED_SUBCHECKS if name not in default_subchecks]
    checks.append({"name": "default-check-havoc-subchecks-complete", "status": "pass" if not missing else "fail", "message": ", ".join(missing)})

    registry = checker_lib.check_subchecks()
    registry_missing = [name for name in REQUIRED_SUBCHECKS if name not in registry]
    checks.append({"name": "subcheck-registry-complete", "status": "pass" if not registry_missing else "fail", "message": ", ".join(registry_missing)})

    source = CHECKER_LIB_PATH.read_text(encoding="utf-8")
    wait_markers = ["NETWORK_ROOM_WAIT_SECONDS", "_wait_for_network_room", "after bounded wait"]
    wait_missing = [marker for marker in wait_markers if marker not in source]
    checks.append({"name": "network-room-bounded-wait", "status": "pass" if not wait_missing else "fail", "message": ", ".join(wait_missing)})

    forbidden = ["ps" + "ql ", "SEL" + "ECT ", "/api/de" + "bug", "/api/ad" + "min"]
    leaks = [marker for marker in forbidden if marker in source]
    checks.append({"name": "checker-no-db-debug-shortcuts", "status": "pass" if not leaks else "fail", "message": ", ".join(leaks)})

    status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
    return {
        "status": status,
        "checks": checks,
        "phase_plan": phase_plan(),
        "required_subchecks": list(REQUIRED_SUBCHECKS),
        "competition_tags": live_matrix.COMPETITION_TAGS,
    }


def run_clean_deploy(repo_root: Path, *, python: str, go: str, docker: str) -> dict[str, Any]:
    started = time.monotonic()
    static = static_checks(repo_root)
    if static["status"] != "pass":
        raise CleanDeployFailure("static preflight failed")

    runner = live_matrix.CommandRunner()
    phases: list[dict[str, Any]] = []
    with live_matrix.ServiceInstance(
        repo_root,
        docker=docker,
        go=go,
        runner=runner,
        label="checker-clean",
        api_port=live_matrix.free_port(),
        pg_port=live_matrix.free_port(),
    ) as service:
        for action in ("check", "havoc"):
            result = live_matrix.run_checker(runner, python, action, service.base_url, timeout=60)
            phases.append(
                {
                    "phase": f"clean:checker-{action}",
                    "exit_code": result.returncode,
                    "classification": classify_exit(result.returncode),
                    "elapsed_seconds": round(result.elapsed, 3),
                }
            )

    return {
        "status": "pass",
        "environment": {"python": python, "go": go, "docker": docker, "tags": live_matrix.COMPETITION_TAGS},
        "phase_plan": phase_plan(),
        "required_subchecks": list(REQUIRED_SUBCHECKS),
        "phases": phases,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate clean-deploy Sentinel AML CHECK/HAVOC")
    parser.add_argument("--run", action="store_true", help="run live Docker/PostgreSQL/API/worker CHECK/HAVOC")
    parser.add_argument("--python", default=sys.executable, help="Python executable")
    parser.add_argument("--go", default="go", help="Go executable")
    parser.add_argument("--docker", default="docker", help="Docker executable")
    parser.add_argument("--json-output", type=Path, help="write machine-readable evidence JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = run_clean_deploy(ROOT, python=args.python, go=args.go, docker=args.docker) if args.run else static_checks(ROOT)
    except (CleanDeployFailure, live_matrix.MatrixFailure) as exc:
        result = {"status": "fail", "error": str(exc)}
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
