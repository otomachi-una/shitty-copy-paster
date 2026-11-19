#!/usr/bin/env python3
"""Validate Wave 08 secure audit baseline and release hygiene."""

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
    "000005_add_case_dedup_hint.sql",
    "000006_create_audit_events.sql",
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
    "audit_events",
}
FORBIDDEN_TABLES = {
    "related_entities",
    "exports",
    "network_rooms",
    "network_room_members",
    "flag_stores",
    "worker_jobs",
    "risk_jobs",
    "queues",
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
    "handleGraph",
    "handleExport",
    "handleNetwork",
    "handleChecker",
    "handleAttackData",
    "public attack",
    "attack-data",
    "checker_private",
)
AUDIT_MIGRATION_SNIPPETS = [
    "CREATE TABLE audit_events",
    "actor_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT",
    "object_type text NOT NULL",
    "object_id bigint NOT NULL",
    "event_type text NOT NULL",
    "public_message text NOT NULL DEFAULT ''",
    "diff_json jsonb NOT NULL DEFAULT '[]'::jsonb",
    "created_at timestamptz NOT NULL DEFAULT now()",
    "visibility_scope text NOT NULL DEFAULT 'owner'",
    "CHECK (object_id > 0)",
    "CHECK (object_type IN ('customer', 'account', 'transaction', 'alert', 'case', 'case_note', 'edd_record'))",
    "CHECK (event_type IN ('created', 'updated', 'status_changed', 'claimed', 'triaged', 'reviewed'))",
    "CHECK (visibility_scope IN ('owner', 'internal', 'system'))",
    "CHECK (jsonb_typeof(diff_json) = 'array')",
    "CREATE INDEX audit_events_actor_user_id_idx",
    "CREATE INDEX audit_events_object_idx ON audit_events(object_type, object_id)",
    "CREATE INDEX audit_events_event_type_idx",
    "CREATE INDEX audit_events_visibility_created_idx",
    "CREATE INDEX audit_events_created_at_idx",
]
AUDIT_REPOSITORY_SNIPPETS = [
    "type Repository struct",
    "Create(ctx context.Context, params CreateParams)",
    "ListCaseTimelineByOwner(ctx context.Context, ownerUserID, caseID int64)",
    "RedactedDiffJSON",
    "IsRestrictedField",
    "HashValue",
    "case_note.body",
    "edd_record.confidential_comment",
    "JOIN cases c ON c.owner_user_id = $1 AND c.id = $2",
    "SELECT cn.id FROM case_notes cn WHERE cn.case_id = c.id",
]
AUDIT_SERVER_SNIPPETS = [
    "type AuditRepository interface",
    "WithAuditRepository",
    "CaseAuditChangeResponse",
    "CaseAuditView",
    "CaseTimelineResponse",
    'parts[1] == "timeline"',
    "handleCaseTimeline",
    "recordAudit",
    "caseAuditViews",
    "caseAuditChangeResponses",
    'field = "restricted_field"',
]
ANTI_AML2_TEST_SNIPPETS = [
    "TestAntiAML2AuditTimelineDoesNotExposePrivateStores",
    "AML2_WOULD_LEAK_CASE_NOTE_BODY",
    "AML2_WOULD_LEAK_EDD_INITIAL",
    "AML2_WOULD_LEAK_EDD_UPDATED",
    "assertAuditTimelineSafe",
    "TestAuditHTTPDTOAndPresenterRejectAML2RawExposure",
    "TestOwnerCaseAuditProjectionContractRejectsAML2Fields",
    "diff_json",
    "old_hash",
    "new_hash",
    "checker_private",
    "flag_value",
]
AUDIT_DTO_FIELDS = {
    "id",
    "object_type",
    "object_id",
    "event_type",
    "public_message",
    "changes",
    "created_at",
    "visibility_scope",
}
AUDIT_CHANGE_FIELDS = {"field", "old", "new", "redacted"}
FORBIDDEN_AUDIT_MARKERS = (
    '`json:"body',
    '`json:"confidential_comment',
    '`json:"diff_json',
    '`json:"old_hash',
    '`json:"new_hash',
    '`json:"password_hash',
    '`json:"token_hash',
    '`json:"session',
    '`json:"checker_private',
    '`json:"flag_value',
    '`json:"actor_user_id',
    '`json:"owner_user_id',
    '`json:"analyst_user_id',
    '`json:"author_user_id',
    ".ActorUserID",
    ".OldHash",
    ".NewHash",
    ".DiffJSON,",
    "writeJSON(w, http.StatusOK, event)",
    "writeJSON(w, http.StatusOK, events)",
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
    "docs/wave_reports/wave_08_W08-T01_handoff.md",
    "docs/wave_reports/wave_08_W08-T02_handoff.md",
    "docs/wave_reports/wave_08_W08-T03_handoff.md",
    "docs/wave_reports/wave_08_W08-T04_handoff.md",
    "docs/wave_reports/wave_08_validation_summary.md",
]


def validate_wave08_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_migrations(repo_root))
    checks.extend(check_audit_repository(repo_root))
    checks.extend(check_routes(repo_root))
    checks.extend(check_audit_presenters(repo_root))
    checks.extend(check_projection_contracts(repo_root))
    checks.extend(check_anti_aml2_tests(repo_root))
    checks.extend(check_response_visibility(repo_root))
    checks.extend(check_logs(repo_root))
    checks.extend(check_no_exploit_or_fix_scripts(repo_root))
    checks.extend(check_wave_reports(repo_root))
    checks.extend(check_docs_status(repo_root))
    checks.extend(check_makefile(repo_root))
    checks.extend(check_external_validator(repo_root, "docs-tree", "scripts/check_docs_tree.py", "validate_docs_tree"))
    checks.extend(check_external_validator(repo_root, "forcad-config", "scripts/validate_forcad_config.py", "validate_config"))
    return {"status": aggregate_status(checks), "checks": checks}


def check_migrations(repo_root: Path) -> list[dict[str, Any]]:
    migrations_dir = repo_root / "migrations"
    if not migrations_dir.is_dir():
        return [{"name": "wave08-migrations-present-ordered", "path": "migrations", "status": "fail", "message": "migrations directory is missing"}]
    names = sorted(path.name for path in migrations_dir.glob("*.sql") if path.is_file())
    migration_text = "\n".join((migrations_dir / name).read_text(encoding="utf-8") for name in names)
    tables = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\b", migration_text))
    forbidden = sorted(tables & FORBIDDEN_TABLES)
    audit_path = migrations_dir / "000006_create_audit_events.sql"
    audit_text = audit_path.read_text(encoding="utf-8") if audit_path.is_file() else ""
    missing_audit = [snippet for snippet in AUDIT_MIGRATION_SNIPPETS if snippet not in audit_text]
    return [
        {
            "name": "wave08-migrations-present-ordered",
            "path": "migrations",
            "status": "pass" if names == EXPECTED_MIGRATIONS and has_ordered_numeric_prefixes(names) else "fail",
            "message": "" if names == EXPECTED_MIGRATIONS else f"expected {EXPECTED_MIGRATIONS}, got {names}",
        },
        {
            "name": "wave08-tables-in-scope",
            "path": "migrations",
            "status": "pass" if tables == EXPECTED_TABLES and not forbidden else "fail",
            "message": "" if tables == EXPECTED_TABLES and not forbidden else f"tables={sorted(tables)} forbidden={forbidden}",
        },
        {
            "name": "wave08-audit-migration-contract",
            "path": "migrations/000006_create_audit_events.sql",
            "status": "pass" if audit_path.is_file() and not missing_audit else "fail",
            "message": "" if audit_path.is_file() and not missing_audit else f"missing snippets: {', '.join(missing_audit)}",
        },
    ]


def check_audit_repository(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "internal" / "audit" / "repository.go"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    missing = [snippet for snippet in AUDIT_REPOSITORY_SNIPPETS if snippet not in text]
    forbidden_public_params = "DiffJSON" in source_section(text, "type CreateParams struct", "type FieldChange struct")
    return [
        {
            "name": "wave08-audit-repository-present",
            "path": "internal/audit/repository.go",
            "status": "pass" if path.is_file() and not missing and not forbidden_public_params else "fail",
            "message": "" if path.is_file() and not missing and not forbidden_public_params else f"missing={missing} raw_diff_param={forbidden_public_params}",
        }
    ]


def check_routes(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    routes = set(re.findall(r'mux\.HandleFunc\("([^"]+)"', text))
    missing = sorted(EXPECTED_ROUTES - routes)
    extra = sorted(routes - EXPECTED_ROUTES)
    forbidden_routes = sorted(route for route in routes if any(route.startswith(prefix) for prefix in FORBIDDEN_ROUTE_PREFIXES))
    forbidden_code = sorted(marker for marker in FORBIDDEN_CODE_MARKERS if marker in text)
    missing_audit = [marker for marker in AUDIT_SERVER_SNIPPETS if marker not in text]
    absent_activity = [
        marker
        for marker in ("handleCustomerActivity", "handleEntityActivity", "handleRawAudit", "handleAuditExport")
        if marker in text
    ]
    return [
        {
            "name": "wave08-route-surface-retained",
            "path": "internal/httpapi/server.go",
            "status": "pass" if server_path.is_file() and not missing and not extra else "fail",
            "message": "" if server_path.is_file() and not missing and not extra else f"missing={missing} extra={extra}",
        },
        {
            "name": "wave08-secure-audit-timeline-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_audit else "fail",
            "message": "" if not missing_audit else f"missing markers: {', '.join(missing_audit)}",
        },
        {
            "name": "wave08-no-out-of-scope-routes-or-handlers",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not forbidden_routes and not forbidden_code and not absent_activity else "fail",
            "message": "" if not forbidden_routes and not forbidden_code and not absent_activity else f"routes={forbidden_routes} code={forbidden_code} activity={absent_activity}",
        },
    ]


def check_audit_presenters(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "internal" / "httpapi" / "server.go"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    dto = source_section(text, "type CaseAuditChangeResponse struct", "type ErrorResponse struct")
    presenter = source_section(text, "func caseAuditViews", "func duplicatePreviewViews")
    audit_fields = json_fields_for_struct(text, "CaseAuditView")
    change_fields = json_fields_for_struct(text, "CaseAuditChangeResponse")
    leaked = sorted(marker for marker in FORBIDDEN_AUDIT_MARKERS if marker in dto or marker in presenter)
    missing_collapse = 'field = "restricted_field"' not in presenter
    return [
        {
            "name": "wave08-audit-dto-safe-shape",
            "path": "internal/httpapi/server.go",
            "status": "pass" if audit_fields == AUDIT_DTO_FIELDS and change_fields == AUDIT_CHANGE_FIELDS else "fail",
            "message": "" if audit_fields == AUDIT_DTO_FIELDS and change_fields == AUDIT_CHANGE_FIELDS else f"audit_fields={sorted(audit_fields)} change_fields={sorted(change_fields)}",
        },
        {
            "name": "wave08-audit-presenters-omit-private-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked and not missing_collapse else "fail",
            "message": "" if not leaked and not missing_collapse else f"leaked={leaked} missing_restricted_field_collapse={missing_collapse}",
        },
    ]


def check_projection_contracts(repo_root: Path) -> list[dict[str, Any]]:
    contracts_path = repo_root / "internal" / "projection" / "contracts.go"
    tests_path = repo_root / "internal" / "projection" / "contracts_test.go"
    text = contracts_path.read_text(encoding="utf-8") if contracts_path.is_file() else ""
    tests = tests_path.read_text(encoding="utf-8") if tests_path.is_file() else ""
    body_structs = structs_with_json_field(text, "body")
    confidential_structs = structs_with_json_field(text, "confidential_comment")
    audit_fields = json_fields_for_struct(text, "OwnerCaseAuditView")
    change_fields = json_fields_for_struct(text, "OwnerCaseAuditChangeView")
    required_tests = [
        "TestOwnerCaseAuditChangeContractIsRedactedOnly",
        "TestOwnerCaseAuditProjectionContractRejectsAML2Fields",
        "owner_case_audit",
        '"diff_json"',
        '"old_hash"',
        '"new_hash"',
        '"checker_private"',
        '"flag_value"',
    ]
    missing_tests = [marker for marker in required_tests if marker not in tests]
    return [
        {
            "name": "wave08-projection-private-fields-owner-only",
            "path": "internal/projection/contracts.go",
            "status": "pass" if body_structs == ALLOWED_PROJECTION_BODY_STRUCTS and confidential_structs == ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS else "fail",
            "message": "" if body_structs == ALLOWED_PROJECTION_BODY_STRUCTS and confidential_structs == ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS else f"body={sorted(body_structs)} confidential_comment={sorted(confidential_structs)}",
        },
        {
            "name": "wave08-projection-audit-contract-present",
            "path": "internal/projection/contracts.go",
            "status": "pass" if "owner_case_audit" in text and audit_fields == AUDIT_DTO_FIELDS and change_fields == AUDIT_CHANGE_FIELDS else "fail",
            "message": "" if "owner_case_audit" in text and audit_fields == AUDIT_DTO_FIELDS and change_fields == AUDIT_CHANGE_FIELDS else f"audit_fields={sorted(audit_fields)} change_fields={sorted(change_fields)}",
        },
        {
            "name": "wave08-projection-anti-aml2-tests-present",
            "path": "internal/projection/contracts_test.go",
            "status": "pass" if tests_path.is_file() and not missing_tests else "fail",
            "message": "" if tests_path.is_file() and not missing_tests else f"missing markers: {', '.join(missing_tests)}",
        },
    ]


def check_anti_aml2_tests(repo_root: Path) -> list[dict[str, Any]]:
    http_test_path = repo_root / "internal" / "httpapi" / "audit_timeline_test.go"
    visibility_path = repo_root / "internal" / "httpapi" / "visibility_leak_test.go"
    source_test_path = repo_root / "tests" / "projection_visibility_test.go"
    projection_test_path = repo_root / "internal" / "projection" / "contracts_test.go"
    http_tests = http_test_path.read_text(encoding="utf-8") if http_test_path.is_file() else ""
    visibility_tests = visibility_path.read_text(encoding="utf-8") if visibility_path.is_file() else ""
    source_tests = source_test_path.read_text(encoding="utf-8") if source_test_path.is_file() else ""
    projection_tests = projection_test_path.read_text(encoding="utf-8") if projection_test_path.is_file() else ""
    missing_http = [marker for marker in ANTI_AML2_TEST_SNIPPETS if marker not in (http_tests + source_tests + projection_tests)]
    required_visibility = [
        "case timeline owner response",
        "cross-owner case timeline endpoint",
        "assertVisibilitySentinelsAbsent",
    ]
    missing_visibility = [marker for marker in required_visibility if marker not in visibility_tests]
    return [
        {
            "name": "wave08-anti-aml2-tests-present",
            "path": "internal/httpapi/audit_timeline_test.go internal/projection/contracts_test.go tests/projection_visibility_test.go",
            "status": "pass" if not missing_http else "fail",
            "message": "" if not missing_http else f"missing markers: {', '.join(missing_http)}",
        },
        {
            "name": "wave08-visibility-regression-covers-timeline",
            "path": "internal/httpapi/visibility_leak_test.go",
            "status": "pass" if not missing_visibility else "fail",
            "message": "" if not missing_visibility else f"missing markers: {', '.join(missing_visibility)}",
        },
    ]


def check_response_visibility(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    leaked = sorted(marker for marker in FORBIDDEN_RESPONSE_MARKERS if marker in text)
    body_structs = structs_with_json_field(text, "body")
    confidential_structs = structs_with_json_field(text, "confidential_comment")
    direct_model_encode = bool(
        re.search(r"json\.NewEncoder\([^)]*\)\.Encode\(\s*(?:customer|account|transaction|alert|investigationCase|note|record|user|session|event|events)\s*\)", text)
    )
    return [
        {
            "name": "wave08-http-dtos-avoid-internal-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked and not direct_model_encode else "fail",
            "message": "" if not leaked and not direct_model_encode else f"leaked={leaked} direct_model_encode={direct_model_encode}",
        },
        {
            "name": "wave08-http-body-owner-note-only",
            "path": "internal/httpapi/server.go",
            "status": "pass" if body_structs == ALLOWED_HTTP_BODY_STRUCTS else "fail",
            "message": "" if body_structs == ALLOWED_HTTP_BODY_STRUCTS else f"body_structs={sorted(body_structs)}",
        },
        {
            "name": "wave08-http-confidential-comment-owner-edd-only",
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
            "name": "wave08-logs-avoid-sensitive-fields",
            "path": "cmd-and-internal",
            "status": "pass" if not hits else "fail",
            "message": "" if not hits else f"sensitive log markers found in: {', '.join(sorted(hits))}",
        }
    ]


def check_no_exploit_or_fix_scripts(repo_root: Path) -> list[dict[str, Any]]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    scripts = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    planned = sorted(name for name in scripts if name in FORBIDDEN_EXPLOIT_NAMES)
    fix_scripts = sorted(
        str(path.relative_to(repo_root)).replace(os.sep, "/")
        for path in repo_root.rglob("*fix*.py")
        if "vendor" not in path.parts and "archive" not in path.parts
    )
    return [
        {
            "name": "wave08-no-exploit-or-fix-scripts",
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
                "name": "wave08-report-present",
                "path": path,
                "status": "pass" if full_path.is_file() else "fail",
                "message": "" if full_path.is_file() else "required Wave 08 report is missing",
            }
        )
    return checks


def check_docs_status(repo_root: Path) -> list[dict[str, Any]]:
    paths = [
        repo_root / "README.md",
        repo_root / "docs" / "03_api_contract.md",
        repo_root / "docs" / "04_database_model.md",
        repo_root / "docs" / "06_visibility_and_projections.md",
        repo_root / "docs" / "09_vulnerability_matrix.md",
        repo_root / "docs" / "12_testing_strategy.md",
        repo_root / "docs" / "13_roadmap.md",
        repo_root / "docs" / "waves.md",
        repo_root / "docs" / "source_of_truth_map.md",
        repo_root / "docs" / "wave_reports" / "wave_08_validation_summary.md",
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.is_file())
    required = [
        "Wave 07 | complete",
        "Wave 08 | needs fixes",
        "W07 | Dedup preview secure baseline | complete",
        "W08 | Audit timeline secure baseline | needs fixes",
        "scripts/check_wave08_gate.py",
        "make wave08-gate",
        "wave_08_validation_summary.md",
        "000006_create_audit_events.sql",
        "GET /api/cases/{case_id}/timeline",
        "owner_case_audit",
        "Anti-AML-2",
        "AML-2 remains future-only",
        "Wave 15",
        "CaseNote.body",
        "EDDRecord.confidential_comment",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave08-doc-status-and-authority",
            "path": "README.md docs/03_api_contract.md docs/04_database_model.md docs/06_visibility_and_projections.md docs/09_vulnerability_matrix.md docs/12_testing_strategy.md docs/13_roadmap.md docs/waves.md docs/source_of_truth_map.md docs/wave_reports/wave_08_validation_summary.md",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {', '.join(missing)}",
        }
    ]


def check_makefile(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "Makefile"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    required = [
        "wave08-gate",
        "scripts/check_wave08_gate.py",
        "GOFLAGS=-mod=vendor",
        "go test ./...",
        "go vet ./...",
        "scripts/check_docs_tree.py",
        "scripts/validate_forcad_config.py",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave08-make-target-present",
            "path": "Makefile",
            "status": "pass" if path.is_file() and not missing else "fail",
            "message": "" if path.is_file() and not missing else f"missing markers: {', '.join(missing)}",
        }
    ]


def has_ordered_numeric_prefixes(names: list[str]) -> bool:
    prefixes: list[int] = []
    for name in names:
        match = re.match(r"^(\d+)_", name)
        if not match:
            return False
        prefixes.append(int(match.group(1)))
    return prefixes == sorted(prefixes)


def source_section(source: str, start_marker: str, end_marker: str) -> str:
    start = source.find(start_marker)
    if start < 0:
        return ""
    end = source.find(end_marker, start)
    if end < 0:
        return ""
    return source[start:end]


def structs_with_json_field(text: str, field_name: str) -> set[str]:
    structs: set[str] = set()
    pattern = re.compile(r"type\s+([A-Za-z0-9_]+)\s+struct\s*{(?P<body>.*?)}", re.S)
    marker = f'json:"{field_name}'
    for match in pattern.finditer(text):
        if marker in match.group("body"):
            structs.add(match.group(1))
    return structs


def json_fields_for_struct(text: str, struct_name: str) -> set[str]:
    match = re.search(rf"type\s+{re.escape(struct_name)}\s+struct\s*{{(?P<body>.*?)}}", text, re.S)
    if not match:
        return set()
    return set(re.findall(r'json:"([^",]+)', match.group("body")))


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
    result = validate_wave08_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
