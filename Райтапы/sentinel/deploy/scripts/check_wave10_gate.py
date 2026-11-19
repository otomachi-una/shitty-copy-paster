#!/usr/bin/env python3
"""Validate Wave 10 secure export/network-room baseline and release hygiene."""

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
    "000007_create_entity_graph.sql",
    "000008_create_exports_disputes.sql",
    "000009_create_network_rooms.sql",
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
    "entity_graph_nodes",
    "entity_graph_edges",
    "disputes",
    "exports",
    "export_items",
    "network_rooms",
    "network_room_cases",
    "network_room_participants",
}
FORBIDDEN_TABLES = {
    "flag_stores",
    "checker_state",
    "checker_private",
    "worker_jobs",
    "risk_jobs",
    "queues",
    "public_attack_data",
    "network_room_private_blobs",
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
    "/api/graph/entities/",
    "/api/exports",
    "/api/exports/",
    "/api/disputes",
    "/api/disputes/",
    "/api/network/rooms",
    "/api/network/rooms/",
}
FORBIDDEN_ROUTE_PREFIXES = (
    "/api/aml",
    "/api/checker",
    "/api/attack-data",
    "/api/public",
    "/api/debug",
    "/api/admin",
    "/debug",
    "/admin",
)
FORBIDDEN_ROUTE_EXACT = {
    "/api/graph",
    "/api/graph/",
    "/api/network",
    "/api/network/",
    "/api/entities",
    "/api/entities/",
}
EXPORT_MIGRATION_SNIPPETS = [
    "CREATE TABLE disputes",
    "CREATE TABLE exports",
    "CREATE TABLE export_items",
    "owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE",
    "root_case_id bigint NOT NULL REFERENCES cases(id) ON DELETE RESTRICT",
    "bundle_json jsonb NOT NULL DEFAULT '{}'::jsonb",
    "redaction_policy text NOT NULL DEFAULT 'public_redacted'",
    "CHECK (redaction_policy IN ('public_redacted'))",
    "CHECK (jsonb_typeof(bundle_json) = 'object')",
    "CREATE INDEX exports_owner_status_idx",
    "CREATE INDEX export_items_export_id_idx",
]
NETWORK_MIGRATION_SNIPPETS = [
    "CREATE TABLE network_rooms",
    "CREATE TABLE network_room_cases",
    "CREATE TABLE network_room_participants",
    "room_key text NOT NULL",
    "entity_hint text NOT NULL",
    "public_risk_tags text[] NOT NULL DEFAULT '{}'::text[]",
    "case_id bigint NOT NULL REFERENCES cases(id) ON DELETE CASCADE",
    "UNIQUE (room_id, case_id)",
    "UNIQUE (room_id, user_id)",
    "CHECK (participant_role IN ('analyst', 'observer'))",
    "CREATE INDEX network_room_participants_user_id_idx",
]
EXPORT_DTO_FIELDS = {
    "ExportBundleView": {"purpose", "redaction_policy", "generated_at", "root_case", "linked_cases", "audit_summaries", "edd_summaries", "items"},
    "ExportCaseShellView": {"case_id", "customer_id", "status", "public_summary", "risk_score", "typology_hint", "created_at", "updated_at"},
    "ExportAuditSummaryView": {"event_id", "object_type", "object_id", "event_type", "public_message", "changed_fields", "created_at"},
    "ExportEDDSummaryView": {"record_id", "customer_id", "review_status", "risk_tags", "created_at", "updated_at"},
    "ExportItemMetadataView": {"item_type", "object_type", "object_id", "relation", "redaction_policy"},
}
NETWORK_DTO_FIELDS = {
    "NetworkRoomSummaryView": {"id", "room_key", "entity_hint", "typology_hint", "status", "public_summary", "public_risk_tags", "case_count", "participant_count", "created_at", "updated_at"},
    "NetworkRoomParticipantView": {"id", "room_id", "user_id", "participant_role", "joined_at"},
    "NetworkRoomCaseView": {"case_id", "customer_id", "owned_by_requester", "status", "public_summary", "risk_score", "typology_hint", "public_risk_tags", "private_data_omitted", "created_at", "updated_at"},
    "NetworkRoomDossierView": {"room", "cases", "redaction_policy", "private_data_policy"},
}
FORBIDDEN_SIDE_VIEW_JSON_FIELDS = {
    "body",
    "confidential_comment",
    "source_of_funds",
    "risk_rationale",
    "diff_json",
    "old_hash",
    "new_hash",
    "value_hash",
    "password_hash",
    "token_hash",
    "session",
    "owner_user_id",
    "analyst_user_id",
    "author_user_id",
    "assigned_user_id",
    "counterparty_fingerprint",
    "trace_id",
    "checker_private",
    "flag_value",
    "secret_for_checker",
    "raw_db_row",
}
FORBIDDEN_EXPORT_BUILDER_MARKERS = (
    ".Body",
    ".ConfidentialComment",
    ".SourceOfFunds",
    ".RiskRationale",
    ".DiffJSON",
    ".OldHash",
    ".NewHash",
)
FORBIDDEN_NETWORK_QUERY_MARKERS = (
    "case_notes",
    "edd_records",
    "audit_events",
    "body",
    "confidential_comment",
    "source_of_funds",
    "risk_rationale",
    "diff_json",
    "value_hash",
)
FORBIDDEN_RESPONSE_MARKERS = (
    'json:"owner_user_id',
    'json:"password_hash',
    'json:"token_hash',
    'json:"raw_db_row',
    'json:"flag' + '_value',
    'json:"secret' + '_for_checker',
)
FORBIDDEN_LOG_FIELDS = ("password", "password_hash", "token", "token_hash", "authorization", "body", "confidential_comment", "diff_json")
FORBIDDEN_EXPLOIT_NAMES = {
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
}
EXPECTED_WAVE_REPORTS = [
    "docs/wave_reports/wave_10_W10-T01_handoff.md",
    "docs/wave_reports/wave_10_W10-T02_handoff.md",
    "docs/wave_reports/wave_10_W10-T03_handoff.md",
    "docs/wave_reports/wave_10_W10-T04_handoff.md",
    "docs/wave_reports/wave_10_W10-T05_handoff.md",
    "docs/wave_reports/wave_10_validation_summary.md",
]


def validate_wave10_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_migrations(repo_root))
    checks.extend(check_export_repository(repo_root))
    checks.extend(check_network_repository(repo_root))
    checks.extend(check_routes(repo_root))
    checks.extend(check_export_network_presenters(repo_root))
    checks.extend(check_projection_contracts(repo_root))
    checks.extend(check_anti_aml4_aml5_tests(repo_root))
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
        return [{"name": "wave10-migrations-present-ordered", "path": "migrations", "status": "fail", "message": "migrations directory is missing"}]
    names = sorted(path.name for path in migrations_dir.glob("*.sql") if path.is_file())
    migration_text = "\n".join((migrations_dir / name).read_text(encoding="utf-8") for name in names)
    tables = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\b", migration_text))
    forbidden = sorted(tables & FORBIDDEN_TABLES)
    export_text = (migrations_dir / "000008_create_exports_disputes.sql").read_text(encoding="utf-8") if (migrations_dir / "000008_create_exports_disputes.sql").is_file() else ""
    network_text = (migrations_dir / "000009_create_network_rooms.sql").read_text(encoding="utf-8") if (migrations_dir / "000009_create_network_rooms.sql").is_file() else ""
    missing_export = [snippet for snippet in EXPORT_MIGRATION_SNIPPETS if snippet not in export_text]
    missing_network = [snippet for snippet in NETWORK_MIGRATION_SNIPPETS if snippet not in network_text]
    private_markers = [marker for marker in ("body", "confidential_comment", "source_of_funds", "risk_rationale", "diff_json", "password_hash", "token_hash", "checker_private", "flag_value") if marker in export_text or marker in network_text]
    return [
        {
            "name": "wave10-migrations-present-ordered",
            "path": "migrations",
            "status": "pass" if names == EXPECTED_MIGRATIONS and has_ordered_numeric_prefixes(names) else "fail",
            "message": "" if names == EXPECTED_MIGRATIONS else f"expected {EXPECTED_MIGRATIONS}, got {names}",
        },
        {
            "name": "wave10-tables-in-scope",
            "path": "migrations",
            "status": "pass" if tables == EXPECTED_TABLES and not forbidden else "fail",
            "message": "" if tables == EXPECTED_TABLES and not forbidden else f"tables={sorted(tables)} forbidden={forbidden}",
        },
        {
            "name": "wave10-export-migration-contract",
            "path": "migrations/000008_create_exports_disputes.sql",
            "status": "pass" if not missing_export and not private_markers else "fail",
            "message": "" if not missing_export and not private_markers else f"missing={missing_export} private_markers={private_markers}",
        },
        {
            "name": "wave10-network-migration-contract",
            "path": "migrations/000009_create_network_rooms.sql",
            "status": "pass" if not missing_network and not private_markers else "fail",
            "message": "" if not missing_network and not private_markers else f"missing={missing_network} private_markers={private_markers}",
        },
    ]


def check_export_repository(repo_root: Path) -> list[dict[str, Any]]:
    redaction_path = repo_root / "internal" / "exporting" / "redaction.go"
    repo_test_path = repo_root / "internal" / "exporting" / "repository_test.go"
    text = redaction_path.read_text(encoding="utf-8") if redaction_path.is_file() else ""
    tests = repo_test_path.read_text(encoding="utf-8") if repo_test_path.is_file() else ""
    required = [
        "type ExportContext struct",
        "func BuildBundle",
        "RedactionPolicyPublic",
        "flattenLinkedCases(root.LinkedCases, visited)",
        "appendSafeCaseData(&bundle, linked, scopes, \"linked\")",
        "safeCaseShell",
        "safeAuditSummary",
        "safeEDDSummary",
    ]
    missing = [marker for marker in required if marker not in text]
    outputs = source_section(text, "type ExportBundle struct", "func BuildBundle")
    builders = source_section(text, "func BuildBundle", "func validateExportContext")
    output_fields = json_fields_in_source(outputs)
    forbidden_output = sorted(output_fields & FORBIDDEN_SIDE_VIEW_JSON_FIELDS)
    forbidden_builder = sorted(marker for marker in FORBIDDEN_EXPORT_BUILDER_MARKERS if marker in builders)
    required_tests = [
        "ROOT_PRIVATE_NOTE_SENTINEL",
        "ROOT_EDD_CONFIDENTIAL_SENTINEL",
        "LINKED_PRIVATE_NOTE_SENTINEL",
        "LINKED_EDD_CONFIDENTIAL_SENTINEL",
        "NESTED_PRIVATE_NOTE_SENTINEL",
        "sha256:private",
    ]
    missing_tests = [marker for marker in required_tests if marker not in tests]
    return [
        {
            "name": "wave10-export-redaction-primitives-present",
            "path": "internal/exporting/redaction.go",
            "status": "pass" if redaction_path.is_file() and not missing else "fail",
            "message": "" if redaction_path.is_file() and not missing else f"missing markers: {', '.join(missing)}",
        },
        {
            "name": "wave10-export-output-omits-private-fields",
            "path": "internal/exporting/redaction.go",
            "status": "pass" if not forbidden_output and not forbidden_builder else "fail",
            "message": "" if not forbidden_output and not forbidden_builder else f"forbidden_output={forbidden_output} forbidden_builder={forbidden_builder}",
        },
        {
            "name": "wave10-export-recursive-redaction-tests-present",
            "path": "internal/exporting/repository_test.go",
            "status": "pass" if repo_test_path.is_file() and not missing_tests else "fail",
            "message": "" if repo_test_path.is_file() and not missing_tests else f"missing markers: {', '.join(missing_tests)}",
        },
    ]


def check_network_repository(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "internal" / "networkroom" / "repository.go"
    tests_path = repo_root / "internal" / "networkroom" / "repository_test.go"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    tests = tests_path.read_text(encoding="utf-8") if tests_path.is_file() else ""
    required = [
        "type RoomSummary struct",
        "type CaseDossierInput struct",
        "type SafeDossier struct",
        "CreateOrFindRoom(ctx context.Context",
        "AttachCase(ctx context.Context",
        "JoinRoom(ctx context.Context",
        "ListRoomsForUser(ctx context.Context",
        "GetRoomForUser(ctx context.Context",
        "ListDossierCases(ctx context.Context",
        "JOIN network_room_participants owned",
        "BuildSafeDossier",
        "PrivateDataOmitted: true",
        "PrivateDataPolicy: \"omitted\"",
    ]
    missing = [marker for marker in required if marker not in text]
    query_section = source_section(text, "func (r *Repository) ListDossierCases", "func (r *Repository) ListRoomsForUser")
    dossier_section = source_section(text, "func BuildSafeDossier", "func deterministicRoomKey")
    query_leaks = sorted(marker for marker in FORBIDDEN_NETWORK_QUERY_MARKERS if marker in query_section)
    dossier_fields = json_fields_in_source(dossier_section)
    forbidden_dossier_fields = sorted(dossier_fields & FORBIDDEN_SIDE_VIEW_JSON_FIELDS)
    required_tests = [
        "TestGetRoomAndDossierCasesUseParticipantScopeAndSafeFields",
        "TestBuildSafeDossierOmitsPrivateValues",
        "Owned public shell",
        "Foreign public shell",
        "PRIVATE_NOTE_SENTINEL",
        "EDD_CONFIDENTIAL_SENTINEL",
        "AUDIT_DIFF_SENTINEL",
        "value_hash",
    ]
    missing_tests = [marker for marker in required_tests if marker not in tests]
    return [
        {
            "name": "wave10-network-repository-primitives-present",
            "path": "internal/networkroom/repository.go",
            "status": "pass" if path.is_file() and not missing else "fail",
            "message": "" if path.is_file() and not missing else f"missing markers: {', '.join(missing)}",
        },
        {
            "name": "wave10-network-dossier-references-only",
            "path": "internal/networkroom/repository.go",
            "status": "pass" if not query_leaks and not forbidden_dossier_fields else "fail",
            "message": "" if not query_leaks and not forbidden_dossier_fields else f"query_leaks={query_leaks} forbidden_dossier_fields={forbidden_dossier_fields}",
        },
        {
            "name": "wave10-network-private-data-tests-present",
            "path": "internal/networkroom/repository_test.go",
            "status": "pass" if tests_path.is_file() and not missing_tests else "fail",
            "message": "" if tests_path.is_file() and not missing_tests else f"missing markers: {', '.join(missing_tests)}",
        },
    ]


def check_routes(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    routes = set(re.findall(r'mux\.HandleFunc\("([^"]+)"', text))
    missing = sorted(EXPECTED_ROUTES - routes)
    extra = sorted(routes - EXPECTED_ROUTES)
    forbidden_routes = sorted(
        route
        for route in routes
        if route in FORBIDDEN_ROUTE_EXACT or any(route.startswith(prefix) for prefix in FORBIDDEN_ROUTE_PREFIXES)
    )
    required_export = [
        "WithExportRepository",
        "handleExportsRoot",
        "handleExportsSubtree",
        "handleDisputesRoot",
        "handleDisputesSubtree",
        "s.requireAuth(s.handleExportsRoot)",
        "s.requireAuth(s.handleDisputesRoot)",
    ]
    required_network = [
        "WithNetworkRoomRepository",
        "handleNetworkRoomsRoot",
        "handleNetworkRoomsSubtree",
        "s.requireAuth(s.handleNetworkRoomsRoot)",
        "s.requireAuth(s.handleNetworkRoomsSubtree)",
    ]
    missing_export = [marker for marker in required_export if marker not in text]
    missing_network = [marker for marker in required_network if marker not in text]
    return [
        {
            "name": "wave10-route-surface-retained",
            "path": "internal/httpapi/server.go",
            "status": "pass" if server_path.is_file() and not missing and not extra else "fail",
            "message": "" if server_path.is_file() and not missing and not extra else f"missing={missing} extra={extra}",
        },
        {
            "name": "wave10-secure-export-routes-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_export else "fail",
            "message": "" if not missing_export else f"missing markers: {', '.join(missing_export)}",
        },
        {
            "name": "wave10-secure-network-routes-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_network else "fail",
            "message": "" if not missing_network else f"missing markers: {', '.join(missing_network)}",
        },
        {
            "name": "wave10-no-out-of-scope-routes",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not forbidden_routes else "fail",
            "message": "" if not forbidden_routes else f"forbidden routes: {forbidden_routes}",
        },
    ]


def check_export_network_presenters(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "internal" / "httpapi" / "server.go"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    shape_failures: list[str] = []
    for struct_name, expected_fields in (EXPORT_DTO_FIELDS | NETWORK_DTO_FIELDS).items():
        fields = json_fields_for_struct(text, struct_name)
        if fields != expected_fields:
            shape_failures.append(f"{struct_name}: got={sorted(fields)} expected={sorted(expected_fields)}")
    export_dto = source_section(text, "type ExportBundleView struct", "type NetworkRoomsResponse struct")
    network_dto = source_section(text, "type NetworkRoomsResponse struct", "type ErrorResponse struct")
    export_presenters = source_section(text, "func exportResponse", "func disputeResponse")
    network_presenters = source_section(text, "func networkRoomSummaryViews", "func writeDomainError")
    dto_fields = json_fields_in_source(export_dto + "\n" + network_dto)
    forbidden_dto_fields = sorted(dto_fields & FORBIDDEN_SIDE_VIEW_JSON_FIELDS)
    forbidden_presenter_markers = sorted(
        marker
        for marker in (
            ".Body",
            ".ConfidentialComment",
            ".SourceOfFunds",
            ".RiskRationale",
            ".DiffJSON",
            ".OldHash",
            ".NewHash",
            ".ValueHash",
            ".PasswordHash",
            ".TokenHash",
            ".CounterpartyFingerprint",
            ".TraceID",
        )
        if marker in export_presenters or marker in network_presenters
    )
    return [
        {
            "name": "wave10-export-network-dto-safe-shape",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not shape_failures else "fail",
            "message": "" if not shape_failures else "; ".join(shape_failures),
        },
        {
            "name": "wave10-export-network-presenters-omit-private-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not forbidden_dto_fields and not forbidden_presenter_markers else "fail",
            "message": "" if not forbidden_dto_fields and not forbidden_presenter_markers else f"dto_fields={forbidden_dto_fields} presenter_markers={forbidden_presenter_markers}",
        },
    ]


def check_projection_contracts(repo_root: Path) -> list[dict[str, Any]]:
    contracts_path = repo_root / "internal" / "projection" / "contracts.go"
    tests_path = repo_root / "internal" / "projection" / "contracts_test.go"
    text = contracts_path.read_text(encoding="utf-8") if contracts_path.is_file() else ""
    tests = tests_path.read_text(encoding="utf-8") if tests_path.is_file() else ""
    side_view_section = source_section(text, "func CurrentSideViewContracts", "func FutureSafeContracts")
    shape_failures: list[str] = []
    projection_fields = EXPORT_DTO_FIELDS | {
        name: fields for name, fields in NETWORK_DTO_FIELDS.items() if name != "NetworkRoomParticipantView"
    }
    for struct_name, expected_fields in projection_fields.items():
        fields = json_fields_for_struct(text, struct_name)
        if fields != expected_fields:
            shape_failures.append(f"{struct_name}: got={sorted(fields)} expected={sorted(expected_fields)}")
        contract_name = snake_contract_name(struct_name)
        if contract_name not in side_view_section:
            shape_failures.append(f"{contract_name} missing from CurrentSideViewContracts")
    required_tests = [
        "TestExportProjectionContractsDenyAML4PrivateFields",
        "TestNetworkRoomProjectionContractsDenyAML5PrivateFields",
        "export_bundle",
        "export_case_shell",
        "network_room_summary",
        "network_room_case",
        "network_room_dossier",
        '"confidential_comment"',
        '"diff_json"',
        '"value_hash"',
        '"checker_private"',
        '"flag_value"',
    ]
    missing_tests = [marker for marker in required_tests if marker not in tests]
    return [
        {
            "name": "wave10-projection-export-network-contracts-present",
            "path": "internal/projection/contracts.go",
            "status": "pass" if not shape_failures else "fail",
            "message": "" if not shape_failures else "; ".join(shape_failures),
        },
        {
            "name": "wave10-projection-anti-aml4-aml5-tests-present",
            "path": "internal/projection/contracts_test.go",
            "status": "pass" if tests_path.is_file() and not missing_tests else "fail",
            "message": "" if tests_path.is_file() and not missing_tests else f"missing markers: {', '.join(missing_tests)}",
        },
    ]


def check_anti_aml4_aml5_tests(repo_root: Path) -> list[dict[str, Any]]:
    export_test_path = repo_root / "internal" / "httpapi" / "export_server_test.go"
    network_test_path = repo_root / "internal" / "httpapi" / "network_room_server_test.go"
    source_test_path = repo_root / "tests" / "projection_visibility_test.go"
    export_tests = export_test_path.read_text(encoding="utf-8") if export_test_path.is_file() else ""
    network_tests = network_test_path.read_text(encoding="utf-8") if network_test_path.is_file() else ""
    source_tests = source_test_path.read_text(encoding="utf-8") if source_test_path.is_file() else ""
    required_export = [
        "TestRootCaseExportCreateRetrieveAndCrossOwnerDenial",
        "EXPORT_ROOT_PRIVATE_NOTE",
        "EXPORT_ROOT_EDD_CONFIDENTIAL",
        "EXPORT_LINKED_PRIVATE_NOTE",
        "EXPORT_LINKED_EDD_CONFIDENTIAL",
        "assertExportResponsePublicOnly",
        '"private_notes"',
    ]
    required_network = [
        "TestNetworkRoomAPIsRequireAuthentication",
        "TestNetworkRoomJoinListDetailAndDossier",
        "NETWORK_OWNER_PRIVATE_NOTE",
        "NETWORK_FOREIGN_PRIVATE_NOTE",
        "NETWORK_OWNER_EDD_CONFIDENTIAL",
        "NETWORK_FOREIGN_EDD_CONFIDENTIAL",
        "assertNetworkResponsePublicOnly",
        "private_data_omitted",
    ]
    required_source = [
        "TestExportingRedactionOutputStaysPublicOnly",
        "type ExportBundle struct",
        "func BuildBundle",
        ".ConfidentialComment",
        ".DiffJSON",
    ]
    missing_export = [marker for marker in required_export if marker not in export_tests]
    missing_network = [marker for marker in required_network if marker not in network_tests]
    missing_source = [marker for marker in required_source if marker not in source_tests]
    return [
        {
            "name": "wave10-anti-aml4-http-tests-present",
            "path": "internal/httpapi/export_server_test.go",
            "status": "pass" if not missing_export else "fail",
            "message": "" if not missing_export else f"missing markers: {', '.join(missing_export)}",
        },
        {
            "name": "wave10-anti-aml5-http-tests-present",
            "path": "internal/httpapi/network_room_server_test.go",
            "status": "pass" if not missing_network else "fail",
            "message": "" if not missing_network else f"missing markers: {', '.join(missing_network)}",
        },
        {
            "name": "wave10-export-source-guard-tests-present",
            "path": "tests/projection_visibility_test.go",
            "status": "pass" if not missing_source else "fail",
            "message": "" if not missing_source else f"missing markers: {', '.join(missing_source)}",
        },
    ]


def check_response_visibility(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    leaked = sorted(marker for marker in FORBIDDEN_RESPONSE_MARKERS if marker in text)
    direct_model_encode = bool(re.search(r"json\.NewEncoder\([^)]*\)\.Encode\(\s*(?:customer|account|transaction|alert|investigationCase|note|record|user|session|event|events|room|rooms|participant|dossier)\s*\)", text))
    return [
        {
            "name": "wave10-http-dtos-avoid-internal-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked and not direct_model_encode else "fail",
            "message": "" if not leaked and not direct_model_encode else f"leaked={leaked} direct_model_encode={direct_model_encode}",
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
            "name": "wave10-logs-avoid-sensitive-fields",
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
            "name": "wave10-no-exploit-or-fix-scripts",
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
                "name": "wave10-report-present",
                "path": path,
                "status": "pass" if full_path.is_file() else "fail",
                "message": "" if full_path.is_file() else "required Wave 10 report is missing",
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
        repo_root / "docs" / "wave_reports" / "wave_10_validation_summary.md",
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.is_file())
    required = [
        "Wave 09 | complete",
        "Wave 10 | needs fixes",
        "W09 | Related graph secure baseline | complete",
        "W10 | Export redaction and network-room secure baselines | needs fixes",
        "scripts/check_wave10_gate.py",
        "make wave10-gate",
        "wave_10_validation_summary.md",
        "000008_create_exports_disputes.sql",
        "000009_create_network_rooms.sql",
        "GET /api/network/rooms",
        "GET /api/network/rooms/{room_id}/dossier",
        "POST /api/cases/{case_id}/exports",
        "GET /api/exports/{export_id}",
        "ExportBundleView",
        "NetworkRoomDossierView",
        "AML-4 remains future-only",
        "AML-5 remains future-only",
        "Wave 17",
        "Wave 18",
        "CaseNote.body",
        "EDDRecord.confidential_comment",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave10-doc-status-and-authority",
            "path": "README.md docs/03_api_contract.md docs/05_authentication_authorization.md docs/06_visibility_and_projections.md docs/12_testing_strategy.md docs/13_roadmap.md docs/waves.md docs/source_of_truth_map.md docs/wave_reports/wave_10_validation_summary.md",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {', '.join(missing)}",
        }
    ]


def check_makefile(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "Makefile"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    required = [
        "wave10-gate",
        "scripts/check_wave10_gate.py",
        "GOFLAGS=-mod=vendor",
        "go test ./...",
        "go vet ./...",
        "scripts/check_docs_tree.py",
        "scripts/validate_forcad_config.py",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave10-make-target-present",
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


def json_fields_for_struct(text: str, struct_name: str) -> set[str]:
    match = re.search(rf"type\s+{re.escape(struct_name)}\s+struct\s*{{(?P<body>.*?)}}", text, re.S)
    if not match:
        return set()
    return set(re.findall(r'json:"([^",]+)', match.group("body")))


def json_fields_in_source(text: str) -> set[str]:
    return set(re.findall(r'json:"([^",]+)', text))


def snake_contract_name(struct_name: str) -> str:
    replacements = {
        "ExportBundleView": "export_bundle",
        "ExportCaseShellView": "export_case_shell",
        "ExportAuditSummaryView": "export_audit_summary",
        "ExportEDDSummaryView": "export_edd_summary",
        "ExportItemMetadataView": "export_item_metadata",
        "NetworkRoomSummaryView": "network_room_summary",
        "NetworkRoomParticipantView": "network_room_participant",
        "NetworkRoomCaseView": "network_room_case",
        "NetworkRoomDossierView": "network_room_dossier",
    }
    return replacements.get(struct_name, re.sub(r"(?<!^)(?=[A-Z])", "_", re.sub(r"View$", "", struct_name)).lower())


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
    result = validate_wave10_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
