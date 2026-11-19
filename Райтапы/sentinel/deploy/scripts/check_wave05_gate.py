#!/usr/bin/env python3
"""Validate Wave 05 EDD integration, visibility, and release hygiene."""

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
    "000003_create_alerts_cases_notes.sql",
    "000004_create_edd_records.sql",
]
EXPECTED_TABLES = {
    "users",
    "sessions",
    "customers",
    "accounts",
    "transactions",
    "alerts",
    "cases",
    "case_notes",
    "edd_records",
}
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
    "/api/alerts/queue",
    "/api/alerts/",
    "/api/cases/",
}
REQUIRED_ROUTE_LINES = [
    'mux.HandleFunc("/api/customers", s.requireAuth(s.handleCustomersRoot))',
    'mux.HandleFunc("/api/customers/", s.requireAuth(s.handleCustomersSubtree))',
    'mux.HandleFunc("/api/accounts/", s.requireAuth(s.handleAccountsSubtree))',
    'mux.HandleFunc("/api/transactions", s.requireAuth(s.handleTransactionsRoot))',
    'mux.HandleFunc("/api/transactions/", s.requireAuth(s.handleTransactionsSubtree))',
    'mux.HandleFunc("/api/alerts/queue", s.requireAuth(s.handleAlertsQueue))',
    'mux.HandleFunc("/api/alerts/", s.requireAuth(s.handleAlertsSubtree))',
    'mux.HandleFunc("/api/cases/", s.requireAuth(s.handleCasesSubtree))',
]
REQUIRED_SERVER_MARKERS = [
    "WithEDDRepository",
    "EDDRepository interface",
    "CreateEDDRequest",
    "UpdateEDDRequest",
    "EDDOwnerView",
    "handleCustomerEDD",
    'parts[1] == "edd"',
    "eddOwnerView(record)",
    "duplicate_edd_record",
    "edd.ErrInvalidInput",
    "edd.ErrEDDRecordNotFound",
]
REQUIRED_EDD_REPOSITORY_MARKERS = [
    "Create(ctx context.Context, params CreateParams)",
    "GetByOwnerCustomer(ctx context.Context, ownerUserID, customerID int64)",
    "UpdateByOwnerCustomer(ctx context.Context, params UpdateParams)",
    "JOIN customers c ON c.id = er.customer_id",
    "c.owner_user_id = $1",
    "ErrDuplicate",
    "ErrEDDRecordNotFound",
]
EXPECTED_WAVE_REPORTS = [
    "docs/wave_reports/wave_05_W05-T01_handoff.md",
    "docs/wave_reports/wave_05_W05-T02_handoff.md",
    "docs/wave_reports/wave_05_W05-T03_handoff.md",
    "docs/wave_reports/wave_05_W05-T04_handoff.md",
    "docs/wave_reports/wave_05_validation_summary.md",
]
FORBIDDEN_TABLES = {
    "audit_events",
    "related_entities",
    "exports",
    "network_rooms",
    "network_room_members",
    "flag_stores",
    "worker_jobs",
    "risk_jobs",
    "queues",
}
FORBIDDEN_ROUTE_PREFIXES = (
    "/api/aml",
    "/api/edd",
    "/api/graph",
    "/api/export",
    "/api/exports",
    "/api/network",
    "/api/entities",
    "/api/checker",
    "/api/public",
    "/api/debug",
    "/api/admin",
)
FORBIDDEN_CODE_MARKERS = (
    "handleDedup",
    "handleAudit",
    "handleGraph",
    "handleExport",
    "handleNetwork",
    "handleChecker",
    "public attack",
    "attack-data",
    "merge-preview",
    "network-room",
)
FORBIDDEN_RESPONSE_MARKERS = (
    'json:"owner_user_id',
    'json:"password_hash',
    'json:"token_hash',
    'json:"raw_db_row',
    'json:"flag' + '_value',
    'json:"secret' + '_for_checker',
)
ALLOWED_CONFIDENTIAL_DTO_STRUCTS = {"CreateEDDRequest", "UpdateEDDRequest", "EDDOwnerView"}
FORBIDDEN_LOG_FIELDS = ("password", "password_hash", "token", "token_hash", "authorization", "body", "confidential_comment")
FORBIDDEN_EXPLOIT_NAMES = [
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
]


def validate_wave05_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_migrations(repo_root))
    checks.extend(check_routes(repo_root))
    checks.extend(check_repositories(repo_root))
    checks.extend(check_response_visibility(repo_root))
    checks.extend(check_case_note_body_containment(repo_root))
    checks.extend(check_edd_confidential_visibility(repo_root))
    checks.extend(check_logs(repo_root))
    checks.extend(check_no_exploit_scripts(repo_root))
    checks.extend(check_live_gate(repo_root))
    checks.extend(check_wave_reports(repo_root))
    checks.extend(check_docs_status(repo_root))
    checks.extend(check_external_validator(repo_root, "docs-tree", "scripts/check_docs_tree.py", "validate_docs_tree"))
    checks.extend(check_external_validator(repo_root, "forcad-config", "scripts/validate_forcad_config.py", "validate_config"))
    return {"status": aggregate_status(checks), "checks": checks}


def check_migrations(repo_root: Path) -> list[dict[str, Any]]:
    migrations_dir = repo_root / "migrations"
    if not migrations_dir.is_dir():
        return [{"name": "wave05-migrations-present-ordered", "path": "migrations", "status": "fail", "message": "migrations directory is missing"}]

    names = sorted(path.name for path in migrations_dir.glob("*.sql") if path.is_file())
    migration_text = "\n".join((migrations_dir / name).read_text(encoding="utf-8") for name in names)
    tables = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\b", migration_text))
    forbidden = sorted(tables & FORBIDDEN_TABLES)
    required_snippets = [
        "CREATE TABLE edd_records",
        "customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE RESTRICT",
        "analyst_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT",
        "source_of_funds text NOT NULL",
        "risk_rationale text NOT NULL",
        "confidential_comment text NOT NULL",
        "review_status text NOT NULL DEFAULT 'DRAFT'",
        "UNIQUE (customer_id)",
        "CHECK (review_status IN ('DRAFT', 'IN_REVIEW', 'APPROVED', 'REJECTED'))",
        "CREATE INDEX edd_records_customer_id_idx",
        "CREATE INDEX edd_records_analyst_user_id_idx",
        "CREATE INDEX edd_records_review_status_idx",
    ]
    missing = [snippet for snippet in required_snippets if snippet not in migration_text]

    return [
        {
            "name": "wave05-migrations-present-ordered",
            "path": "migrations",
            "status": "pass" if names == EXPECTED_MIGRATIONS and has_ordered_numeric_prefixes(names) else "fail",
            "message": "" if names == EXPECTED_MIGRATIONS else f"expected {EXPECTED_MIGRATIONS}, got {names}",
        },
        {
            "name": "wave05-tables-in-scope",
            "path": "migrations",
            "status": "pass" if tables == EXPECTED_TABLES and not forbidden else "fail",
            "message": "" if tables == EXPECTED_TABLES and not forbidden else f"tables={sorted(tables)} forbidden={forbidden}",
        },
        {
            "name": "wave05-edd-schema-contracts",
            "path": "migrations/000004_create_edd_records.sql",
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
        return [{"name": "wave05-routes-present", "path": "internal/httpapi/server.go", "status": "fail", "message": "server.go is missing"}]

    text = server_path.read_text(encoding="utf-8")
    routes = set(re.findall(r'mux\.HandleFunc\("([^"]+)"', text))
    missing_routes = sorted(EXPECTED_ROUTES - routes)
    extra_routes = sorted(routes - EXPECTED_ROUTES)
    missing_protection = [line for line in REQUIRED_ROUTE_LINES if line not in text]
    missing_markers = [marker for marker in REQUIRED_SERVER_MARKERS if marker not in text]
    forbidden_routes = sorted(
        route
        for route in routes
        if route not in EXPECTED_ROUTES and (route in {"/debug", "/admin"} or any(route.startswith(prefix) for prefix in FORBIDDEN_ROUTE_PREFIXES))
    )
    forbidden_code = sorted(marker for marker in FORBIDDEN_CODE_MARKERS if marker in text)

    return [
        {
            "name": "wave05-routes-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_routes and not extra_routes else "fail",
            "message": "" if not missing_routes and not extra_routes else f"missing={missing_routes} extra={extra_routes}",
        },
        {
            "name": "wave05-routes-require-auth",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_protection else "fail",
            "message": "" if not missing_protection else f"missing protected routes: {', '.join(missing_protection)}",
        },
        {
            "name": "wave05-edd-route-handlers-and-dtos-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_markers else "fail",
            "message": "" if not missing_markers else f"missing markers: {', '.join(missing_markers)}",
        },
        {
            "name": "no-out-of-scope-routes-or-handlers",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not forbidden_routes and not forbidden_code else "fail",
            "message": "" if not forbidden_routes and not forbidden_code else f"routes={forbidden_routes} code={forbidden_code}",
        },
    ]


def check_repositories(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "internal" / "edd" / "repository.go"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    missing = [marker for marker in REQUIRED_EDD_REPOSITORY_MARKERS if marker not in text]
    return [
        {
            "name": "wave05-edd-repository-owner-scope",
            "path": "internal/edd/repository.go",
            "status": "pass" if path.is_file() and not missing else "fail",
            "message": "" if path.is_file() and not missing else f"missing markers: {', '.join(missing)}",
        }
    ]


def check_response_visibility(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    leaked = sorted(marker for marker in FORBIDDEN_RESPONSE_MARKERS if marker in text)
    serializes_db_model = bool(
        re.search(r"json\.NewEncoder\([^)]*\)\.Encode\(\s*(?:customer|account|transaction|alert|investigationCase|note|record|user|session|result)\s*\)", text)
    )
    return [
        {
            "name": "wave05-dtos-avoid-internal-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked and not serializes_db_model else "fail",
            "message": "" if not leaked and not serializes_db_model else f"leaked={leaked} serializes_db_model={serializes_db_model}",
        }
    ]


def check_case_note_body_containment(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    body_structs = structs_with_json_field(text, "body")
    unexpected = sorted(body_structs - {"CreateCaseNoteRequest", "CaseNoteResponse"})
    return [
        {
            "name": "case-note-body-remains-owner-view-only",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not unexpected and {"CreateCaseNoteRequest", "CaseNoteResponse"} <= body_structs else "fail",
            "message": "" if not unexpected and {"CreateCaseNoteRequest", "CaseNoteResponse"} <= body_structs else f"body_structs={sorted(body_structs)} unexpected={unexpected}",
        }
    ]


def check_edd_confidential_visibility(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    unit_tests_path = repo_root / "internal" / "httpapi" / "domain_server_test.go"
    live_tests_path = repo_root / "internal" / "httpapi" / "live_postgres_integration_test.go"
    docs_path = repo_root / "docs" / "06_visibility_and_projections.md"
    server_text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    tests_text = "\n".join(path.read_text(encoding="utf-8") for path in (unit_tests_path, live_tests_path) if path.is_file())
    docs_text = docs_path.read_text(encoding="utf-8") if docs_path.is_file() else ""

    confidential_structs = structs_with_json_field(server_text, "confidential_comment")
    unexpected_structs = sorted(confidential_structs - ALLOWED_CONFIDENTIAL_DTO_STRUCTS)
    required_tests = [
        "EDD owner-only confidential comment",
        "non-EDD endpoint %s leaked EDD confidential comment",
        "cross-owner EDD response leaked",
        "TestLivePostgresWave05EDDAPIIntegration",
        "non-EDD or side-view path %s leaked EDD confidential comment",
        '"/api/customers/%d/edd/public"',
        '"/api/customers/%d/edd/audit"',
    ]
    missing_tests = [marker for marker in required_tests if marker not in tests_text]
    required_docs = [
        "Visibility matrix for `confidential_comment`",
        "Owner EDD create/get/patch response | visible",
        "Public attack-data or checker-only path | absent",
        "Worker, export, graph, audit, network-room, or side-view projection | absent",
    ]
    missing_docs = [marker for marker in required_docs if marker not in docs_text]
    return [
        {
            "name": "edd-confidential-comment-owner-dto-only",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not unexpected_structs and confidential_structs == ALLOWED_CONFIDENTIAL_DTO_STRUCTS else "fail",
            "message": "" if not unexpected_structs and confidential_structs == ALLOWED_CONFIDENTIAL_DTO_STRUCTS else f"structs={sorted(confidential_structs)} unexpected={unexpected_structs}",
        },
        {
            "name": "edd-confidential-comment-regression-tests",
            "path": "internal/httpapi/domain_server_test.go internal/httpapi/live_postgres_integration_test.go",
            "status": "pass" if not missing_tests else "fail",
            "message": "" if not missing_tests else f"missing markers: {', '.join(missing_tests)}",
        },
        {
            "name": "edd-visibility-doc-matrix",
            "path": "docs/06_visibility_and_projections.md",
            "status": "pass" if not missing_docs else "fail",
            "message": "" if not missing_docs else f"missing markers: {', '.join(missing_docs)}",
        },
    ]


def structs_with_json_field(text: str, field_name: str) -> set[str]:
    structs: set[str] = set()
    pattern = re.compile(r"type\s+([A-Za-z0-9_]+)\s+struct\s*{(?P<body>.*?)}", re.S)
    marker = f'json:"{field_name}'
    for match in pattern.finditer(text):
        if marker in match.group("body"):
            structs.add(match.group(1))
    return structs


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
            "name": "logs-avoid-secrets-note-and-edd-fields",
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
            "name": "no-wave05-exploit-scripts",
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
        "TestLivePostgresWave05EDDAPIIntegration",
        "SENTINEL_AML_INTEGRATION_DATABASE_URL",
        "ApplyMigrations",
        "WithEDDRepository",
        '"/api/customers/%d/edd"',
        "duplicate_edd_record",
        "cross-owner EDD",
        "non-EDD or side-view path %s leaked EDD confidential comment",
    ]
    missing_live = [marker for marker in required_live_markers if marker not in live_text]
    return [
        {
            "name": "wave05-live-edd-api-gate-present",
            "path": "internal/httpapi/live_postgres_integration_test.go",
            "status": "pass" if live_path.is_file() and not missing_live else "fail",
            "message": "" if live_path.is_file() and not missing_live else f"missing markers: {', '.join(missing_live)}",
        },
        {
            "name": "wave05-make-target-present",
            "path": "Makefile",
            "status": "pass" if "wave05-gate:" in makefile_text and "check_wave05_gate.py" in makefile_text else "fail",
            "message": "" if "wave05-gate:" in makefile_text and "check_wave05_gate.py" in makefile_text else "wave05-gate target missing",
        },
        {
            "name": "wave05-live-make-target-present",
            "path": "Makefile",
            "status": "pass" if "live-wave05-integration:" in makefile_text and "TestLivePostgresWave05EDDAPIIntegration" in makefile_text else "fail",
            "message": "" if "live-wave05-integration:" in makefile_text and "TestLivePostgresWave05EDDAPIIntegration" in makefile_text else "live Wave 05 integration target missing",
        },
    ]


def check_wave_reports(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path in EXPECTED_WAVE_REPORTS:
        full_path = repo_root / path
        checks.append(
            {
                "name": "wave05-report-present",
                "path": path,
                "status": "pass" if full_path.is_file() else "fail",
                "message": "" if full_path.is_file() else "required Wave 05 report is missing",
            }
        )
    return checks


def check_docs_status(repo_root: Path) -> list[dict[str, Any]]:
    paths = [
        repo_root / "README.md",
        repo_root / "docs" / "13_roadmap.md",
        repo_root / "docs" / "waves.md",
        repo_root / "docs" / "source_of_truth_map.md",
        repo_root / "docs" / "12_testing_strategy.md",
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.is_file())
    required = [
        "Wave 04 | complete",
        "Wave 05 | needs fixes",
        "W04 | Risk scoring, alerts, and owner case workflow | complete",
        "W05 | EDD workflow | needs fixes",
        "make wave05-gate",
        "live-wave05-integration",
        "EDDRecord.confidential_comment",
        "wave_05_validation_summary.md",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave05-doc-status-and-command-surface",
            "path": "README.md docs/12_testing_strategy.md docs/13_roadmap.md docs/waves.md docs/source_of_truth_map.md",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {', '.join(missing)}",
        }
    ]


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
    result = validate_wave05_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
