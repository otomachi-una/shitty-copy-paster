#!/usr/bin/env python3
"""Validate Wave 03 domain/API integration and retained CTF guardrails."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


EXPECTED_MIGRATIONS = [
    "000001_create_users_sessions.sql",
    "000002_create_customers_accounts_transactions.sql",
]
EXPECTED_TABLES = {"users", "sessions", "customers", "accounts", "transactions"}
EXPECTED_ROUTES = {
    "/healthz",
    "/readyz",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/me",
    "/api/customers",
    "/api/customers/",
    "/api/accounts/",
    "/api/transactions",
    "/api/transactions/",
}
REQUIRED_PRODUCT_ROUTE_LINES = [
    'mux.HandleFunc("/api/customers", s.requireAuth(s.handleCustomersRoot))',
    'mux.HandleFunc("/api/customers/", s.requireAuth(s.handleCustomersSubtree))',
    'mux.HandleFunc("/api/accounts/", s.requireAuth(s.handleAccountsSubtree))',
    'mux.HandleFunc("/api/transactions", s.requireAuth(s.handleTransactionsRoot))',
    'mux.HandleFunc("/api/transactions/", s.requireAuth(s.handleTransactionsSubtree))',
]
REQUIRED_SERVER_MARKERS = [
    "CreateCustomerRequest",
    "CustomerResponse",
    "CreateAccountRequest",
    "AccountResponse",
    "CreateTransactionRequest",
    "TransactionResponse",
    "WithDomainRepositories",
    "invalid_path",
    "not_found",
    "ListByCustomerOwner",
]
EXPECTED_WAVE_REPORTS = [
    "docs/wave_reports/wave_03_W03-T01_handoff.md",
    "docs/wave_reports/wave_03_W03-T02_handoff.md",
    "docs/wave_reports/wave_03_W03-F01_handoff.md",
    "docs/wave_reports/wave_03_validation_summary.md",
]
EXPECTED_VENDOR_MODULES = {
    "github.com/jackc/pgpassfile": "v1.0.0",
    "github.com/jackc/pgservicefile": "v0.0.0-20240606120523-5a60cdf6a761",
    "github.com/jackc/pgx/v5": "v5.6.0",
    "github.com/jackc/puddle/v2": "v2.2.2",
    "golang.org/x/crypto": "v0.31.0",
    "golang.org/x/sync": "v0.10.0",
    "golang.org/x/text": "v0.21.0",
}
FORBIDDEN_TABLES = {
    "alerts",
    "cases",
    "case_notes",
    "edd_records",
    "audit_events",
    "related_entities",
    "exports",
    "network_rooms",
    "network_room_members",
    "flag_stores",
}
FORBIDDEN_ROUTE_PREFIXES = (
    "/api/aml",
    "/api/alerts",
    "/api/cases",
    "/api/case",
    "/api/edd",
    "/api/graph",
    "/api/export",
    "/api/exports",
    "/api/network",
    "/api/checker",
)
FORBIDDEN_ROUTE_NAMES = ("/de" + "bug", "/ad" + "min", "/api/de" + "bug", "/api/ad" + "min")
FORBIDDEN_RESPONSE_MARKERS = (
    "json:\"owner_user_id",
    "json:\"password_hash",
    "json:\"token_hash",
    "json:\"raw_db_row",
    "json:\"" + "flag" + "_value",
    "json:\"" + "secret" + "_for_checker",
)
FORBIDDEN_LOG_FIELDS = ("password", "password_hash", "token", "token_hash", "authorization")
FORBIDDEN_EXPLOIT_NAMES = [
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
]
EXPECTED_WAVE02_EXPANSION_FAILURES = {
    "migrations-present-ordered",
    "wave02-tables-only",
    "registered-routes-in-scope",
}


def validate_wave03_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_migrations(repo_root))
    checks.extend(check_routes(repo_root))
    checks.extend(check_repositories(repo_root))
    checks.extend(check_response_visibility(repo_root))
    checks.extend(check_logs(repo_root))
    checks.extend(check_no_exploit_scripts(repo_root))
    checks.extend(check_vendor(repo_root))
    checks.extend(check_live_gate(repo_root))
    checks.extend(check_wave_reports(repo_root))
    checks.extend(check_external_validator(repo_root, "docs-tree", "scripts/check_docs_tree.py", "validate_docs_tree"))
    checks.extend(check_external_validator(repo_root, "forcad-config", "scripts/validate_forcad_config.py", "validate_config"))
    checks.extend(check_external_validator(repo_root, "wave01-scope", "scripts/check_wave01_scope.py", "validate_wave01_scope"))
    checks.extend(check_wave02_invariants(repo_root))
    return {"status": aggregate_status(checks), "checks": checks}


def check_migrations(repo_root: Path) -> list[dict[str, Any]]:
    migrations_dir = repo_root / "migrations"
    if not migrations_dir.is_dir():
        return [{"name": "wave03-migrations-present-ordered", "path": "migrations", "status": "fail", "message": "migrations directory is missing"}]

    names = sorted(path.name for path in migrations_dir.glob("*.sql") if path.is_file())
    migration_text = "\n".join((migrations_dir / name).read_text(encoding="utf-8") for name in names)
    tables = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\b", migration_text))
    forbidden = sorted(tables & FORBIDDEN_TABLES)
    required_snippets = [
        "owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE",
        "customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE",
        "account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE",
        "CREATE INDEX customers_owner_user_id_idx",
        "CREATE INDEX accounts_customer_id_idx",
        "CREATE INDEX transactions_account_id_idx",
    ]
    missing = [snippet for snippet in required_snippets if snippet not in migration_text]

    return [
        {
            "name": "wave03-migrations-present-ordered",
            "path": "migrations",
            "status": "pass" if names == EXPECTED_MIGRATIONS and has_ordered_numeric_prefixes(names) else "fail",
            "message": "" if names == EXPECTED_MIGRATIONS else f"expected {EXPECTED_MIGRATIONS}, got {names}",
        },
        {
            "name": "wave03-tables-only",
            "path": "migrations",
            "status": "pass" if tables == EXPECTED_TABLES and not forbidden else "fail",
            "message": "" if tables == EXPECTED_TABLES and not forbidden else f"tables={sorted(tables)} forbidden={forbidden}",
        },
        {
            "name": "wave03-relationship-index-contracts",
            "path": "migrations",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing snippets: {', '.join(missing)}",
        },
    ]


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
        return [{"name": "wave03-routes-present", "path": "internal/httpapi/server.go", "status": "fail", "message": "server.go is missing"}]

    text = server_path.read_text(encoding="utf-8")
    routes = set(re.findall(r'mux\.HandleFunc\("([^"]+)"', text))
    missing_routes = sorted(EXPECTED_ROUTES - routes)
    extra_routes = sorted(routes - EXPECTED_ROUTES)
    missing_protection = [line for line in REQUIRED_PRODUCT_ROUTE_LINES if line not in text]
    missing_markers = [marker for marker in REQUIRED_SERVER_MARKERS if marker not in text]
    forbidden_routes = sorted(
        route
        for route in routes
        if route in FORBIDDEN_ROUTE_NAMES or any(route.startswith(prefix) for prefix in FORBIDDEN_ROUTE_PREFIXES)
    )
    forbidden_literals = [
        marker
        for marker in ('"/api/customers/{customer_id}/profile"', '"/api/customers/{customer_id}/risk"', '"/api/alerts"', '"/api/cases"', '"/api/edd"', '"/api/graph"', '"/api/export"', '"/api/network_rooms"')
        if marker in text
    ]

    return [
        {
            "name": "wave03-routes-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_routes and not extra_routes else "fail",
            "message": "" if not missing_routes and not extra_routes else f"missing={missing_routes} extra={extra_routes}",
        },
        {
            "name": "wave03-product-routes-require-auth",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_protection else "fail",
            "message": "" if not missing_protection else f"missing protected routes: {', '.join(missing_protection)}",
        },
        {
            "name": "wave03-route-handlers-and-dtos-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_markers else "fail",
            "message": "" if not missing_markers else f"missing markers: {', '.join(missing_markers)}",
        },
        {
            "name": "no-side-view-or-later-routes",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not forbidden_routes and not forbidden_literals else "fail",
            "message": "" if not forbidden_routes and not forbidden_literals else f"routes={forbidden_routes} literals={forbidden_literals}",
        },
    ]


def check_repositories(repo_root: Path) -> list[dict[str, Any]]:
    files = {
        "internal/customer/repository.go": ["GetByOwner", "owner_user_id = $1", "context.Context"],
        "internal/account/repository.go": ["GetByOwner", "ListByCustomerOwner", "JOIN customers", "owner_user_id = $1", "context.Context"],
        "internal/transaction/repository.go": ["GetByOwner", "ListByCustomerOwner", "JOIN accounts", "JOIN customers", "owner_user_id = $1", "context.Context"],
    }
    checks: list[dict[str, Any]] = []
    for relative, markers in files.items():
        path = repo_root / relative
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        missing = [marker for marker in markers if marker not in text]
        checks.append(
            {
                "name": "wave03-repository-owner-scope",
                "path": relative,
                "status": "pass" if path.is_file() and not missing else "fail",
                "message": "" if path.is_file() and not missing else f"missing markers: {', '.join(missing)}",
            }
        )
    return checks


def check_vendor(repo_root: Path) -> list[dict[str, Any]]:
    vendor_dir = repo_root / "vendor"
    modules_path = vendor_dir / "modules.txt"
    go_mod_text = (repo_root / "go.mod").read_text(encoding="utf-8") if (repo_root / "go.mod").is_file() else ""
    modules_text = modules_path.read_text(encoding="utf-8") if modules_path.is_file() else ""

    missing_modules: list[str] = []
    missing_dirs: list[str] = []
    for module, version in EXPECTED_VENDOR_MODULES.items():
        if f"# {module} {version}" not in modules_text:
            missing_modules.append(f"{module} {version}")
        module_dir = vendor_dir / Path(module)
        if not module_dir.exists():
            missing_dirs.append(module)

    has_toolchain = any(line.startswith("toolchain ") for line in go_mod_text.splitlines())
    makefile_text = (repo_root / "Makefile").read_text(encoding="utf-8") if (repo_root / "Makefile").is_file() else ""
    makefile_uses_vendor = "GOFLAGS=-mod=vendor" in makefile_text and "GO_OFFLINE_ENV" in makefile_text

    return [
        {
            "name": "offline-vendor-tree-present",
            "path": "vendor",
            "status": "pass" if vendor_dir.is_dir() and modules_path.is_file() and not missing_modules and not missing_dirs else "fail",
            "message": "" if vendor_dir.is_dir() and modules_path.is_file() and not missing_modules and not missing_dirs else f"missing_modules={missing_modules} missing_dirs={missing_dirs}",
        },
        {
            "name": "offline-go-mod-and-makefile-policy",
            "path": "go.mod Makefile",
            "status": "pass" if "go 1.22.0" in go_mod_text and not has_toolchain and makefile_uses_vendor else "fail",
            "message": "" if "go 1.22.0" in go_mod_text and not has_toolchain and makefile_uses_vendor else f"go_1_22={'go 1.22.0' in go_mod_text} has_toolchain={has_toolchain} makefile_uses_vendor={makefile_uses_vendor}",
        },
    ]


def check_response_visibility(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    leaked = sorted(marker for marker in FORBIDDEN_RESPONSE_MARKERS if marker in text)
    serializes_db_model = bool(
        re.search(r"json\.NewEncoder\([^)]*\)\.Encode\(\s*(?:customer|account|transaction|user|session|result)\s*\)", text)
    )
    return [
        {
            "name": "wave03-dtos-avoid-internal-fields",
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
            "name": "logs-avoid-sensitive-fields",
            "path": "cmd-and-internal",
            "status": "pass" if not hits else "fail",
            "message": "" if not hits else f"sensitive log markers found in: {', '.join(sorted(hits))}",
        }
    ]


def check_no_exploit_scripts(repo_root: Path) -> list[dict[str, Any]]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    files = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    planned = sorted(name for name in files if name in FORBIDDEN_EXPLOIT_NAMES)
    return [
        {
            "name": "no-wave03-exploit-scripts",
            "path": "sploits/sentinel_aml",
            "status": "pass" if not files and not planned else "fail",
            "message": "" if not files and not planned else f"unexpected exploit scripts: {', '.join(files)}",
        }
    ]


def check_live_gate(repo_root: Path) -> list[dict[str, Any]]:
    live_path = repo_root / "internal" / "httpapi" / "live_postgres_integration_test.go"
    makefile_path = repo_root / "Makefile"
    live_text = live_path.read_text(encoding="utf-8") if live_path.is_file() else ""
    makefile_text = makefile_path.read_text(encoding="utf-8") if makefile_path.is_file() else ""
    required_live_markers = [
        "TestLivePostgresWave03OwnerAPIIntegration",
        "SENTINEL_AML_INTEGRATION_DATABASE_URL",
        "ApplyMigrations",
        "WithDomainRepositories",
        '"/api/customers"',
        '"/api/transactions"',
        "http.StatusNotFound",
        "assertIntegrationResponseClean",
    ]
    missing_live = [marker for marker in required_live_markers if marker not in live_text]
    return [
        {
            "name": "wave03-live-owner-api-gate-present",
            "path": "internal/httpapi/live_postgres_integration_test.go",
            "status": "pass" if live_path.is_file() and not missing_live else "fail",
            "message": "" if live_path.is_file() and not missing_live else f"missing markers: {', '.join(missing_live)}",
        },
        {
            "name": "wave03-make-target-present",
            "path": "Makefile",
            "status": "pass" if "wave03-gate:" in makefile_text and "check_wave03_gate.py" in makefile_text else "fail",
            "message": "" if "wave03-gate:" in makefile_text and "check_wave03_gate.py" in makefile_text else "wave03-gate target missing",
        },
        {
            "name": "wave03-live-make-target-present",
            "path": "Makefile",
            "status": "pass" if "live-wave03-integration:" in makefile_text and "TestLivePostgresWave03OwnerAPIIntegration" in makefile_text else "fail",
            "message": "" if "live-wave03-integration:" in makefile_text and "TestLivePostgresWave03OwnerAPIIntegration" in makefile_text else "live Wave 03 integration target missing",
        },
    ]


def check_wave_reports(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path in EXPECTED_WAVE_REPORTS:
        full_path = repo_root / path
        checks.append(
            {
                "name": "wave03-report-present",
                "path": path,
                "status": "pass" if full_path.is_file() else "fail",
                "message": "" if full_path.is_file() else "required Wave 03 report is missing",
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


def check_wave02_invariants(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "scripts" / "check_wave02_gate.py"
    spec = importlib.util.spec_from_file_location("check_wave02_gate", path)
    if spec is None or spec.loader is None:
        return [{"name": "wave02-invariants", "path": "scripts/check_wave02_gate.py", "status": "fail", "message": "Wave 02 gate unavailable"}]

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.validate_wave02_gate(repo_root)
    failures = [check for check in result["checks"] if check["status"] == "fail"]
    failure_names = {check["name"] for check in failures}
    unexpected = sorted(failure_names - EXPECTED_WAVE02_EXPANSION_FAILURES)
    missing_expected = sorted(EXPECTED_WAVE02_EXPANSION_FAILURES - failure_names)
    status = "pass" if not unexpected and not missing_expected else "fail"
    message = ""
    if unexpected or missing_expected:
        message = f"unexpected={unexpected} missing_expected={missing_expected} failures={failures}"
    return [
        {
            "name": "wave02-invariants-retained-with-wave03-expansion",
            "path": "scripts/check_wave02_gate.py",
            "status": status,
            "message": message,
        }
    ]


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave03_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
