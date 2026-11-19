#!/usr/bin/env python3
"""Validate Wave 02 migration/auth integration and retained scope gates."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


EXPECTED_MIGRATIONS = ["000001_create_users_sessions.sql"]
EXPECTED_TABLES = {"users", "sessions"}
EXPECTED_ROUTES = {"/healthz", "/readyz", "/api/auth/register", "/api/auth/login", "/api/auth/me"}
EXPECTED_AUTH_ROUTES = {"/api/auth/register", "/api/auth/login", "/api/auth/me"}
EXPECTED_WAVE_REPORTS = [
    "docs/wave_reports/wave_02_W02-T01_handoff.md",
    "docs/wave_reports/wave_02_W02-T02_handoff.md",
    "docs/wave_reports/wave_02_W02-T03_handoff.md",
    "docs/wave_reports/wave_02_W02-F01_handoff.md",
    "docs/wave_reports/wave_02_W02-F02_handoff.md",
    "docs/wave_reports/wave_02_validation_summary.md",
]
FORBIDDEN_TABLES = {
    "customers",
    "accounts",
    "transactions",
    "alerts",
    "cases",
    "case_notes",
    "edd_records",
    "audit_events",
    "related_entities",
    "network_rooms",
}
FORBIDDEN_ROUTE_PREFIXES = ("/api/aml", "/api/customers", "/api/accounts", "/api/transactions", "/api/alerts", "/api/cases")
FORBIDDEN_ROUTE_NAMES = ("/de" + "bug", "/ad" + "min", "/api/de" + "bug", "/api/ad" + "min")
FORBIDDEN_RESPONSE_FIELDS = ("password_hash", "token_hash", "raw_db_row", "flag" + "_value", "secret" + "_for_checker")
FORBIDDEN_LOG_FIELDS = ("password", "password_hash", "token", "token_hash", "authorization")


def validate_wave02_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_migrations(repo_root))
    checks.extend(check_routes(repo_root))
    checks.extend(check_response_visibility(repo_root))
    checks.extend(check_logs(repo_root))
    checks.extend(check_no_exploit_scripts(repo_root))
    checks.extend(check_live_integration_gate(repo_root))
    checks.extend(check_wave_reports(repo_root))
    checks.extend(check_external_validator(repo_root, "docs-tree", "scripts/check_docs_tree.py", "validate_docs_tree"))
    checks.extend(check_external_validator(repo_root, "forcad-config", "scripts/validate_forcad_config.py", "validate_config"))
    return {"status": aggregate_status(checks), "checks": checks}


def check_migrations(repo_root: Path) -> list[dict[str, Any]]:
    migrations_dir = repo_root / "migrations"
    if not migrations_dir.is_dir():
        return [{"name": "migrations-present-ordered", "path": "migrations", "status": "fail", "message": "migrations directory is missing"}]

    names = sorted(path.name for path in migrations_dir.glob("*.sql") if path.is_file())
    checks = [
        {
            "name": "migrations-present-ordered",
            "path": "migrations",
            "status": "pass" if names == EXPECTED_MIGRATIONS and has_ordered_numeric_prefixes(names) else "fail",
            "message": "" if names == EXPECTED_MIGRATIONS else f"expected {EXPECTED_MIGRATIONS}, got {names}",
        }
    ]

    migration_text = "\n".join((migrations_dir / name).read_text(encoding="utf-8") for name in names)
    tables = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\b", migration_text))
    forbidden = sorted(tables & FORBIDDEN_TABLES)
    checks.append(
        {
            "name": "wave02-tables-only",
            "path": "migrations",
            "status": "pass" if tables == EXPECTED_TABLES and not forbidden else "fail",
            "message": "" if tables == EXPECTED_TABLES and not forbidden else f"tables={sorted(tables)} forbidden={forbidden}",
        }
    )
    return checks


def has_ordered_numeric_prefixes(names: list[str]) -> bool:
    prefixes: list[int] = []
    for name in names:
        match = re.match(r"^(\d+)_", name)
        if not match:
            return False
        prefixes.append(int(match.group(1)))
    return prefixes == sorted(prefixes)


def check_routes(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    if not server_path.is_file():
        return [{"name": "auth-routes-present", "path": "internal/httpapi/server.go", "status": "fail", "message": "server.go is missing"}]

    text = server_path.read_text(encoding="utf-8")
    routes = set(re.findall(r'mux\.HandleFunc\("([^"]+)"', text))
    forbidden_routes = sorted(
        route
        for route in routes
        if route in FORBIDDEN_ROUTE_NAMES or any(route.startswith(prefix) for prefix in FORBIDDEN_ROUTE_PREFIXES)
    )
    unknown_api_routes = sorted(route for route in routes if route.startswith("/api/") and route not in EXPECTED_AUTH_ROUTES)

    return [
        {
            "name": "auth-routes-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if EXPECTED_AUTH_ROUTES <= routes else "fail",
            "message": "" if EXPECTED_AUTH_ROUTES <= routes else f"routes={sorted(routes)}",
        },
        {
            "name": "registered-routes-in-scope",
            "path": "internal/httpapi/server.go",
            "status": "pass" if routes <= EXPECTED_ROUTES and not forbidden_routes and not unknown_api_routes else "fail",
            "message": "" if routes <= EXPECTED_ROUTES and not forbidden_routes and not unknown_api_routes else f"routes={sorted(routes)}",
        },
        {
            "name": "me-route-requires-auth",
            "path": "internal/httpapi/server.go",
            "status": "pass" if '"/api/auth/me", s.requireAuth(s.handleMe)' in text and "StatusUnauthorized" in text else "fail",
            "message": "" if '"/api/auth/me", s.requireAuth(s.handleMe)' in text else "me route is not wrapped by auth middleware",
        },
    ]


def check_response_visibility(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    service_path = repo_root / "internal" / "auth" / "service.go"
    text = "\n".join(path.read_text(encoding="utf-8") for path in (server_path, service_path) if path.is_file())
    leaked = sorted(marker for marker in FORBIDDEN_RESPONSE_FIELDS if marker in text)
    serializes_db_model = bool(re.search(r"json\.NewEncoder\([^)]*\)\.Encode\(\s*(?:user|session|result\.User|result)\s*\)", text))

    return [
        {
            "name": "auth-sensitive-fields-not-in-dtos",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked and not serializes_db_model else "fail",
            "message": "" if not leaked and not serializes_db_model else f"leaked={leaked} serializes_db_model={serializes_db_model}",
        }
    ]


def check_logs(repo_root: Path) -> list[dict[str, Any]]:
    go_files = [*sorted((repo_root / "cmd").rglob("*.go")), *sorted((repo_root / "internal").rglob("*.go"))]
    hits: list[str] = []
    for path in go_files:
        text = path.read_text(encoding="utf-8").lower()
        for line in text.splitlines():
            if "logger." not in line and "slog." not in line:
                continue
            if any(field in line for field in FORBIDDEN_LOG_FIELDS):
                hits.append(str(path.relative_to(repo_root)).replace(os.sep, "/"))
                break
    return [
        {
            "name": "logs-avoid-auth-secrets",
            "path": "cmd-and-internal",
            "status": "pass" if not hits else "fail",
            "message": "" if not hits else f"sensitive auth log markers found in: {', '.join(sorted(hits))}",
        }
    ]


def check_no_exploit_scripts(repo_root: Path) -> list[dict[str, Any]]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    files = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    return [
        {
            "name": "no-planned-vulnerability-exploits",
            "path": "sploits/sentinel_aml",
            "status": "pass" if not files else "fail",
            "message": "" if not files else f"unexpected exploit scripts: {', '.join(files)}",
        }
    ]


def check_live_integration_gate(repo_root: Path) -> list[dict[str, Any]]:
    test_path = repo_root / "internal" / "httpapi" / "live_postgres_integration_test.go"
    makefile_path = repo_root / "Makefile"
    compose_path = repo_root / "docker-compose.yml"
    test_text = test_path.read_text(encoding="utf-8") if test_path.is_file() else ""
    makefile_text = makefile_path.read_text(encoding="utf-8") if makefile_path.is_file() else ""
    compose_text = compose_path.read_text(encoding="utf-8") if compose_path.is_file() else ""

    env_name = "SENTINEL_AML_INTEGRATION_DATABASE_URL"
    required_test_markers = [
        "TestLivePostgresMigrationAuthIntegration",
        env_name,
        "t.Skip",
        "ApplyMigrations",
        "auth.NewRepository(database)",
        '"/api/auth/register"',
        '"/api/auth/login"',
        '"/api/auth/me"',
        "StatusUnauthorized",
        "password_hash",
        "token_hash",
    ]
    missing_test_markers = [marker for marker in required_test_markers if marker not in test_text]

    return [
        {
            "name": "live-postgres-integration-test-present",
            "path": "internal/httpapi/live_postgres_integration_test.go",
            "status": "pass" if test_path.is_file() and not missing_test_markers else "fail",
            "message": "" if test_path.is_file() and not missing_test_markers else f"missing markers: {', '.join(missing_test_markers)}",
        },
        {
            "name": "live-postgres-compose-present",
            "path": "docker-compose.yml",
            "status": "pass" if "postgres:" in compose_text and "sentinel_aml_test" in compose_text else "fail",
            "message": "" if "postgres:" in compose_text and "sentinel_aml_test" in compose_text else "postgres compose service missing",
        },
        {
            "name": "live-postgres-make-target-present",
            "path": "Makefile",
            "status": "pass" if "live-auth-integration:" in makefile_text and env_name in makefile_text else "fail",
            "message": "" if "live-auth-integration:" in makefile_text and env_name in makefile_text else "live auth integration target missing",
        },
    ]


def check_wave_reports(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path in EXPECTED_WAVE_REPORTS:
        full_path = repo_root / path
        checks.append(
            {
                "name": "wave02-handoff-present",
                "path": path,
                "status": "pass" if full_path.is_file() else "fail",
                "message": "" if full_path.is_file() else "required Wave 02 handoff is missing",
            }
        )
    return checks


def check_external_validator(repo_root: Path, name: str, script_path: str, function_name: str) -> list[dict[str, Any]]:
    path = repo_root / script_path
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        return [{"name": name, "path": script_path, "status": "fail", "message": "validator unavailable"}]

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    validator_arg = repo_root / "config.yml" if function_name == "validate_config" else repo_root
    result = getattr(module, function_name)(validator_arg)
    if isinstance(result, list):
        errors = result
        return [{"name": name, "path": script_path, "status": "pass" if not errors else "fail", "message": "; ".join(errors)}]
    return [{"name": name, "path": script_path, "status": result["status"], "message": "" if result["status"] == "pass" else json.dumps(result)}]


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave02_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
