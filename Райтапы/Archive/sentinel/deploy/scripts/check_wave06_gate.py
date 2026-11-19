#!/usr/bin/env python3
"""Validate Wave 06 projection, visibility, authz, and release hygiene."""

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
FORBIDDEN_TABLES = {
    "dedup_candidates",
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
    "/api/graph",
    "/api/export",
    "/api/exports",
    "/api/network",
    "/api/entities",
    "/api/checker",
    "/api/attack-data",
    "/api/public",
    "/api/debug",
    "/api/admin",
    "/debug",
    "/admin",
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
    "audit timeline",
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
ALLOWED_HTTP_BODY_STRUCTS = {"CreateCaseNoteRequest", "CaseNoteResponse"}
ALLOWED_HTTP_CONFIDENTIAL_STRUCTS = {"CreateEDDRequest", "UpdateEDDRequest", "EDDOwnerView"}
ALLOWED_PROJECTION_BODY_STRUCTS = {"OwnerCaseNoteView"}
ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS = {"OwnerEDDView"}
FORBIDDEN_LOG_FIELDS = ("password", "password_hash", "token", "token_hash", "authorization", "body", "confidential_comment")
FORBIDDEN_EXPLOIT_NAMES = {
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
}
EXPECTED_WAVE_REPORTS = [
    "docs/wave_reports/wave_06_W06-T01_handoff.md",
    "docs/wave_reports/wave_06_W06-T02_handoff.md",
    "docs/wave_reports/wave_06_W06-T03_handoff.md",
    "docs/wave_reports/wave_06_W06-T04_handoff.md",
    "docs/wave_reports/wave_06_validation_summary.md",
]


def validate_wave06_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_migrations(repo_root))
    checks.extend(check_routes(repo_root))
    checks.extend(check_projection_contracts(repo_root))
    checks.extend(check_http_visibility_tests(repo_root))
    checks.extend(check_authz_matrix(repo_root))
    checks.extend(check_response_visibility(repo_root))
    checks.extend(check_logs(repo_root))
    checks.extend(check_no_exploit_or_fix_scripts(repo_root))
    checks.extend(check_wave_reports(repo_root))
    checks.extend(check_docs_status(repo_root))
    checks.extend(check_external_validator(repo_root, "docs-tree", "scripts/check_docs_tree.py", "validate_docs_tree"))
    checks.extend(check_external_validator(repo_root, "forcad-config", "scripts/validate_forcad_config.py", "validate_config"))
    return {"status": aggregate_status(checks), "checks": checks}


def check_migrations(repo_root: Path) -> list[dict[str, Any]]:
    migrations_dir = repo_root / "migrations"
    if not migrations_dir.is_dir():
        return [{"name": "wave06-migrations-retained", "path": "migrations", "status": "fail", "message": "migrations directory is missing"}]
    names = sorted(path.name for path in migrations_dir.glob("*.sql") if path.is_file())
    migration_text = "\n".join((migrations_dir / name).read_text(encoding="utf-8") for name in names)
    tables = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\b", migration_text))
    forbidden = sorted(tables & FORBIDDEN_TABLES)
    return [
        {
            "name": "wave06-migrations-retained",
            "path": "migrations",
            "status": "pass" if names == EXPECTED_MIGRATIONS else "fail",
            "message": "" if names == EXPECTED_MIGRATIONS else f"expected {EXPECTED_MIGRATIONS}, got {names}",
        },
        {
            "name": "wave06-no-out-of-scope-tables",
            "path": "migrations",
            "status": "pass" if tables == EXPECTED_TABLES and not forbidden else "fail",
            "message": "" if tables == EXPECTED_TABLES and not forbidden else f"tables={sorted(tables)} forbidden={forbidden}",
        },
    ]


def check_routes(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    routes = set(re.findall(r'mux\.HandleFunc\("([^"]+)"', text))
    missing = sorted(EXPECTED_ROUTES - routes)
    extra = sorted(routes - EXPECTED_ROUTES)
    forbidden_routes = sorted(route for route in routes if any(route.startswith(prefix) for prefix in FORBIDDEN_ROUTE_PREFIXES))
    forbidden_code = sorted(marker for marker in FORBIDDEN_CODE_MARKERS if marker in text)
    return [
        {
            "name": "wave06-route-surface-retained",
            "path": "internal/httpapi/server.go",
            "status": "pass" if server_path.is_file() and not missing and not extra else "fail",
            "message": "" if server_path.is_file() and not missing and not extra else f"missing={missing} extra={extra}",
        },
        {
            "name": "wave06-no-out-of-scope-routes-or-handlers",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not forbidden_routes and not forbidden_code else "fail",
            "message": "" if not forbidden_routes and not forbidden_code else f"routes={forbidden_routes} code={forbidden_code}",
        },
    ]


def check_projection_contracts(repo_root: Path) -> list[dict[str, Any]]:
    contracts_path = repo_root / "internal" / "projection" / "contracts.go"
    tests_path = repo_root / "internal" / "projection" / "contracts_test.go"
    text = contracts_path.read_text(encoding="utf-8") if contracts_path.is_file() else ""
    tests = tests_path.read_text(encoding="utf-8") if tests_path.is_file() else ""
    required_structs = [
        "OwnerCustomerView",
        "OwnerAccountView",
        "OwnerTransactionView",
        "OwnerAlertView",
        "OwnerCaseView",
        "OwnerCaseNoteView",
        "OwnerEDDView",
        "FuturePublicCaseShell",
        "FutureDuplicatePreview",
        "FutureAuditSummary",
        "FutureExportSummary",
        "FutureGraphSummary",
        "FutureNetworkSummary",
        "CurrentOwnerContracts",
        "FutureSafeContracts",
    ]
    missing_structs = [marker for marker in required_structs if marker not in text]
    body_structs = structs_with_json_field(text, "body")
    confidential_structs = structs_with_json_field(text, "confidential_comment")
    required_tests = [
        "TestProjectionContractsMatchStructJSONTags",
        "TestProjectionContractsExcludeSensitiveFieldsEverywhere",
        "TestOwnerOnlySensitiveFieldsAreNarrowlyContained",
        "TestFutureSafeProjectionContractsDenySensitiveFields",
        '"body"',
        '"confidential_comment"',
        '"password_hash"',
        '"token_hash"',
        '"checker_private"',
        '"owner_user_id"',
    ]
    missing_tests = [marker for marker in required_tests if marker not in tests]
    return [
        {
            "name": "wave06-projection-contracts-present",
            "path": "internal/projection/contracts.go",
            "status": "pass" if contracts_path.is_file() and not missing_structs else "fail",
            "message": "" if contracts_path.is_file() and not missing_structs else f"missing markers: {', '.join(missing_structs)}",
        },
        {
            "name": "wave06-projection-private-fields-owner-only",
            "path": "internal/projection/contracts.go",
            "status": "pass" if body_structs == ALLOWED_PROJECTION_BODY_STRUCTS and confidential_structs == ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS else "fail",
            "message": "" if body_structs == ALLOWED_PROJECTION_BODY_STRUCTS and confidential_structs == ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS else f"body={sorted(body_structs)} confidential_comment={sorted(confidential_structs)}",
        },
        {
            "name": "wave06-projection-allowlist-tests-present",
            "path": "internal/projection/contracts_test.go",
            "status": "pass" if tests_path.is_file() and not missing_tests else "fail",
            "message": "" if tests_path.is_file() and not missing_tests else f"missing markers: {', '.join(missing_tests)}",
        },
    ]


def check_http_visibility_tests(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "internal" / "httpapi" / "visibility_leak_test.go"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    required = [
        "TestVisibilitySentinelStringsStayOnOwnerOnlyEndpoints",
        "W06_NOTE_PRIVATE",
        "W06_EDD_CONFIDENTIAL",
        "GET /api/cases/{case_id}/notes owner",
        "GET /api/customers/{customer_id}/edd owner",
        "cross-owner note endpoint",
        "cross-owner EDD endpoint",
        "auth me",
        "customer profile unsupported",
        "customer risk unsupported",
        "graph route absent",
        "exports route absent",
        "network route absent",
        "entities route absent",
        "checker route absent",
        "attack data route absent",
        "case duplicates route absent",
        "case timeline route absent",
        "assertVisibilitySentinelsAbsent",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave06-http-leak-regression-tests-present",
            "path": "internal/httpapi/visibility_leak_test.go",
            "status": "pass" if path.is_file() and not missing else "fail",
            "message": "" if path.is_file() and not missing else f"missing markers: {', '.join(missing)}",
        }
    ]


def check_authz_matrix(repo_root: Path) -> list[dict[str, Any]]:
    contract_path = repo_root / "internal" / "authz" / "scope_contract.go"
    contract_tests_path = repo_root / "internal" / "authz" / "scope_contract_test.go"
    matrix_path = repo_root / "internal" / "httpapi" / "authz_matrix_test.go"
    contract_text = contract_path.read_text(encoding="utf-8") if contract_path.is_file() else ""
    contract_tests = contract_tests_path.read_text(encoding="utf-8") if contract_tests_path.is_file() else ""
    matrix_text = matrix_path.read_text(encoding="utf-8") if matrix_path.is_file() else ""
    required_contracts = ["OwnerScopeContract", "CurrentOwnerScopeContracts", "customer", "account", "transaction", "alert", "case", "case_note", "edd_record", "not_found"]
    required_matrix = [
        "TestCrossOwnerFailClosedAuthorizationMatrix",
        "TestAuthorizationBoundaryRejectsUnauthenticatedAndMalformedRequests",
        "customer get",
        "account get",
        "account list by customer",
        "account create under foreign customer",
        "transaction get",
        "transaction list by customer",
        "transaction create under foreign account",
        "alert detail",
        "alert claim",
        "alert triage",
        "case get",
        "case status",
        "case notes get",
        "case notes post",
        "EDD get",
        "EDD post",
        "EDD patch",
        "alert queue",
        "unauthenticated",
        "invalid_path",
        "assertFailClosedErrorBody",
        "assertVisibilitySentinelsAbsent",
    ]
    missing_contracts = [marker for marker in required_contracts if marker not in contract_text]
    missing_matrix = [marker for marker in required_matrix if marker not in matrix_text]
    return [
        {
            "name": "wave06-authz-contracts-present",
            "path": "internal/authz/scope_contract.go",
            "status": "pass" if contract_path.is_file() and not missing_contracts else "fail",
            "message": "" if contract_path.is_file() and not missing_contracts else f"missing markers: {', '.join(missing_contracts)}",
        },
        {
            "name": "wave06-authz-contract-tests-present",
            "path": "internal/authz/scope_contract_test.go",
            "status": "pass" if contract_tests_path.is_file() and "TestCurrentOwnerScopeContractsRemainFailClosed" in contract_tests else "fail",
            "message": "" if contract_tests_path.is_file() and "TestCurrentOwnerScopeContractsRemainFailClosed" in contract_tests else "owner scope contract test missing",
        },
        {
            "name": "wave06-cross-owner-matrix-tests-present",
            "path": "internal/httpapi/authz_matrix_test.go",
            "status": "pass" if matrix_path.is_file() and not missing_matrix else "fail",
            "message": "" if matrix_path.is_file() and not missing_matrix else f"missing markers: {', '.join(missing_matrix)}",
        },
    ]


def check_response_visibility(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    leaked = sorted(marker for marker in FORBIDDEN_RESPONSE_MARKERS if marker in text)
    body_structs = structs_with_json_field(text, "body")
    confidential_structs = structs_with_json_field(text, "confidential_comment")
    direct_model_encode = bool(
        re.search(r"json\.NewEncoder\([^)]*\)\.Encode\(\s*(?:customer|account|transaction|alert|investigationCase|note|record|user|session|result)\s*\)", text)
    )
    return [
        {
            "name": "wave06-http-dtos-avoid-internal-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked and not direct_model_encode else "fail",
            "message": "" if not leaked and not direct_model_encode else f"leaked={leaked} direct_model_encode={direct_model_encode}",
        },
        {
            "name": "wave06-http-body-owner-note-only",
            "path": "internal/httpapi/server.go",
            "status": "pass" if body_structs == ALLOWED_HTTP_BODY_STRUCTS else "fail",
            "message": "" if body_structs == ALLOWED_HTTP_BODY_STRUCTS else f"body_structs={sorted(body_structs)}",
        },
        {
            "name": "wave06-http-confidential-comment-owner-edd-only",
            "path": "internal/httpapi/server.go",
            "status": "pass" if confidential_structs == ALLOWED_HTTP_CONFIDENTIAL_STRUCTS else "fail",
            "message": "" if confidential_structs == ALLOWED_HTTP_CONFIDENTIAL_STRUCTS else f"confidential_structs={sorted(confidential_structs)}",
        },
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
            "name": "wave06-logs-avoid-sensitive-fields",
            "path": "cmd-and-internal",
            "status": "pass" if not hits else "fail",
            "message": "" if not hits else f"sensitive log markers found in: {', '.join(sorted(hits))}",
        }
    ]


def check_no_exploit_or_fix_scripts(repo_root: Path) -> list[dict[str, Any]]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    scripts = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    planned = sorted(name for name in scripts if name in FORBIDDEN_EXPLOIT_NAMES)
    fix_scripts = sorted(path.name for path in repo_root.rglob("*fix*.py") if "vendor" not in path.parts and "archive" not in path.parts)
    return [
        {
            "name": "wave06-no-exploit-or-fix-scripts",
            "path": "sploits/sentinel_aml",
            "status": "pass" if not scripts and not planned and not fix_scripts else "fail",
            "message": "" if not scripts and not planned and not fix_scripts else f"exploit_scripts={scripts} planned={planned} fix_scripts={fix_scripts}",
        }
    ]


def check_wave_reports(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path in EXPECTED_WAVE_REPORTS:
        full_path = repo_root / path
        checks.append(
            {
                "name": "wave06-report-present",
                "path": path,
                "status": "pass" if full_path.is_file() else "fail",
                "message": "" if full_path.is_file() else "required Wave 06 report is missing",
            }
        )
    return checks


def check_docs_status(repo_root: Path) -> list[dict[str, Any]]:
    paths = [
        repo_root / "README.md",
        repo_root / "docs" / "03_api_contract.md",
        repo_root / "docs" / "05_authentication_authorization.md",
        repo_root / "docs" / "06_visibility_and_projections.md",
        repo_root / "docs" / "12_testing_strategy.md",
        repo_root / "docs" / "13_roadmap.md",
        repo_root / "docs" / "waves.md",
        repo_root / "docs" / "source_of_truth_map.md",
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.is_file())
    required = [
        "Wave 05 | complete",
        "Wave 06 | needs fixes",
        "W05 | EDD workflow | complete",
        "W06 | Visibility and projection hardening | needs fixes",
        "scripts/check_wave06_gate.py",
        "make wave06-gate",
        "wave_06_validation_summary.md",
        "internal/projection",
        "Cross-Owner Authorization Matrix",
        "HTTP Leak Regression",
        "CaseNote.body",
        "EDDRecord.confidential_comment",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave06-doc-status-and-authority",
            "path": "README.md docs/03_api_contract.md docs/05_authentication_authorization.md docs/06_visibility_and_projections.md docs/12_testing_strategy.md docs/13_roadmap.md docs/waves.md docs/source_of_truth_map.md",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {', '.join(missing)}",
        }
    ]


def structs_with_json_field(text: str, field_name: str) -> set[str]:
    structs: set[str] = set()
    pattern = re.compile(r"type\s+([A-Za-z0-9_]+)\s+struct\s*{(?P<body>.*?)}", re.S)
    marker = f'json:"{field_name}'
    for match in pattern.finditer(text):
        if marker in match.group("body"):
            structs.add(match.group(1))
    return structs


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
        return [{"name": name, "path": script_path, "status": "pass" if not result else "fail", "message": "; ".join(result)}]
    return [{"name": name, "path": script_path, "status": result["status"], "message": "" if result["status"] == "pass" else json.dumps(result)}]


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave06_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
