#!/usr/bin/env python3
"""Validate Wave 09 secure related-graph baseline and release hygiene."""

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
}
FORBIDDEN_TABLES = {
    "exports",
    "network_rooms",
    "network_room_members",
    "flag_stores",
    "worker_jobs",
    "risk_jobs",
    "queues",
    "public_attack_data",
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
}
FORBIDDEN_ROUTE_PREFIXES = (
    "/api/aml",
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
FORBIDDEN_GRAPH_ROUTE_MARKERS = (
    "handleExport",
    "handleNetwork",
    "handleChecker",
    "handleAttackData",
    "public attack",
    "attack-data",
    "checker_private",
)
GRAPH_MIGRATION_SNIPPETS = [
    "CREATE TABLE entity_graph_nodes",
    "entity_hint text NOT NULL",
    "node_type text NOT NULL",
    "public_risk_tags text[] NOT NULL DEFAULT '{}'::text[]",
    "UNIQUE (entity_hint, node_type)",
    "CHECK (btrim(entity_hint) <> '')",
    "CHECK (node_type IN ('customer_entity', 'counterparty', 'case_cluster', 'edd_status'))",
    "CREATE TABLE entity_graph_edges",
    "source_node_id bigint NOT NULL REFERENCES entity_graph_nodes(id) ON DELETE CASCADE",
    "target_node_id bigint NOT NULL REFERENCES entity_graph_nodes(id) ON DELETE CASCADE",
    "relation_type text NOT NULL",
    "CHECK (source_node_id <> target_node_id)",
    "CHECK (relation_type IN ('shared_entity_hint', 'shared_counterparty', 'same_case_cluster', 'edd_status_overlap'))",
    "CHECK (strength >= 0 AND strength <= 100)",
    "CREATE INDEX entity_graph_nodes_entity_hint_idx",
    "CREATE INDEX entity_graph_edges_source_node_id_idx",
    "CREATE INDEX entity_graph_edges_target_node_id_idx",
    "CREATE INDEX entity_graph_edges_relation_type_idx",
]
GRAPH_REPOSITORY_SNIPPETS = [
    "type EntitySummary struct",
    "type RelatedCaseSummary struct",
    "type EDDSummary struct",
    "HasEntityAccess(ctx context.Context, ownerUserID int64, entityHint string)",
    "GetEntitySummary(ctx context.Context, ownerUserID int64, entityHint string)",
    "ListRelatedCases(ctx context.Context, ownerUserID int64, entityHint string)",
    "ListEDDSummaries(ctx context.Context, ownerUserID int64, entityHint string)",
    "WHERE owner_user_id = $1 AND lower(btrim(entity_hint)) = $2",
    "EXISTS (",
]
GRAPH_SERVER_SNIPPETS = [
    "type GraphRepository interface",
    "WithGraphRepository",
    "graphReady",
    'mux.HandleFunc("/api/graph/entities/", s.requireAuth(s.handleGraphEntitiesSubtree))',
    "handleGraphEntitiesSubtree",
    "HasEntityAccess(ctx, user.ID, entityHint)",
    "handleGraphEntity",
    "handleGraphRelatedCases",
    "handleGraphEDDSummaries",
    "GraphEntityView",
    "GraphRelatedCaseView",
    "EDDGraphSummaryView",
    "graphEntityView(summary)",
    "graphRelatedCaseViews(cases)",
    "eddGraphSummaryViews(summaries)",
]
GRAPH_DTO_FIELDS = {
    "GraphEntityView": {"entity_hint", "relation_type", "customer_count", "case_count", "highest_risk", "risk_tags", "updated_at"},
    "GraphRelatedCaseView": {"case_id", "customer_id", "entity_hint", "display_name", "country", "status", "public_summary", "risk_score", "typology_hint", "created_at", "updated_at"},
    "EDDGraphSummaryView": {"customer_id", "entity_hint", "review_status", "risk_tags", "created_at", "updated_at"},
}
FORBIDDEN_GRAPH_MARKERS = (
    "CaseNote",
    "case_notes",
    "`json:\"body",
    ".Body",
    "confidential_comment",
    "ConfidentialComment",
    "source_of_funds",
    "SourceOfFunds",
    "risk_rationale",
    "RiskRationale",
    "`json:\"diff_json",
    ".DiffJSON",
    "password_hash",
    "token_hash",
    "`json:\"session",
    "checker_private",
    "flag_value",
    "raw_db_row",
    "`json:\"owner_user_id",
    ".OwnerUserID",
    "`json:\"analyst_user_id",
    ".AnalystUserID",
    "`json:\"author_user_id",
    ".AuthorUserID",
    "`json:\"assigned_user_id",
    "`json:\"counterparty_fingerprint",
    "`json:\"trace_id",
)
ALLOWED_HTTP_BODY_STRUCTS = {"CreateCaseNoteRequest", "CaseNoteResponse"}
ALLOWED_HTTP_CONFIDENTIAL_STRUCTS = {"CreateEDDRequest", "UpdateEDDRequest", "EDDOwnerView"}
ALLOWED_PROJECTION_BODY_STRUCTS = {"OwnerCaseNoteView"}
ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS = {"OwnerEDDView"}
FORBIDDEN_RESPONSE_MARKERS = (
    'json:"owner_user_id',
    'json:"password_hash',
    'json:"token_hash',
    'json:"raw_db_row',
    'json:"flag' + '_value',
    'json:"secret' + '_for_checker',
)
FORBIDDEN_LOG_FIELDS = ("password", "password_hash", "token", "token_hash", "authorization", "body", "confidential_comment")
FORBIDDEN_EXPLOIT_NAMES = {
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
}
EXPECTED_WAVE_REPORTS = [
    "docs/wave_reports/wave_09_W09-T01_handoff.md",
    "docs/wave_reports/wave_09_W09-T02_handoff.md",
    "docs/wave_reports/wave_09_W09-T03_handoff.md",
    "docs/wave_reports/wave_09_W09-T04_handoff.md",
    "docs/wave_reports/wave_09_validation_summary.md",
]


def validate_wave09_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_migrations(repo_root))
    checks.extend(check_graph_repository(repo_root))
    checks.extend(check_routes(repo_root))
    checks.extend(check_graph_presenters(repo_root))
    checks.extend(check_projection_contracts(repo_root))
    checks.extend(check_anti_aml3_tests(repo_root))
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
        return [{"name": "wave09-migrations-present-ordered", "path": "migrations", "status": "fail", "message": "migrations directory is missing"}]
    names = sorted(path.name for path in migrations_dir.glob("*.sql") if path.is_file())
    migration_text = "\n".join((migrations_dir / name).read_text(encoding="utf-8") for name in names)
    tables = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\b", migration_text))
    forbidden = sorted(tables & FORBIDDEN_TABLES)
    graph_path = migrations_dir / "000007_create_entity_graph.sql"
    graph_text = graph_path.read_text(encoding="utf-8") if graph_path.is_file() else ""
    missing_graph = [snippet for snippet in GRAPH_MIGRATION_SNIPPETS if snippet not in graph_text]
    private_markers = [marker for marker in ("body", "confidential_comment", "source_of_funds", "risk_rationale", "diff_json", "password_hash", "token_hash", "checker_private", "flag_value") if marker in graph_text]
    return [
        {
            "name": "wave09-migrations-present-ordered",
            "path": "migrations",
            "status": "pass" if names == EXPECTED_MIGRATIONS and has_ordered_numeric_prefixes(names) else "fail",
            "message": "" if names == EXPECTED_MIGRATIONS else f"expected {EXPECTED_MIGRATIONS}, got {names}",
        },
        {
            "name": "wave09-tables-in-scope",
            "path": "migrations",
            "status": "pass" if tables == EXPECTED_TABLES and not forbidden else "fail",
            "message": "" if tables == EXPECTED_TABLES and not forbidden else f"tables={sorted(tables)} forbidden={forbidden}",
        },
        {
            "name": "wave09-graph-migration-contract",
            "path": "migrations/000007_create_entity_graph.sql",
            "status": "pass" if graph_path.is_file() and not missing_graph and not private_markers else "fail",
            "message": "" if graph_path.is_file() and not missing_graph and not private_markers else f"missing={missing_graph} private_markers={private_markers}",
        },
    ]


def check_graph_repository(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "internal" / "graph" / "repository.go"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    missing = [snippet for snippet in GRAPH_REPOSITORY_SNIPPETS if snippet not in text]
    structs = source_section(text, "type EntitySummary struct", "func NewRepository")
    queries = source_section(text, "func (r *Repository) HasEntityAccess", "func normalizeEntityHint")
    leaked = sorted(marker for marker in FORBIDDEN_GRAPH_MARKERS if marker in structs or marker in queries)
    return [
        {
            "name": "wave09-graph-repository-secure-shape",
            "path": "internal/graph/repository.go",
            "status": "pass" if path.is_file() and not missing and not leaked else "fail",
            "message": "" if path.is_file() and not missing and not leaked else f"missing={missing} leaked={leaked}",
        }
    ]


def check_routes(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    routes = set(re.findall(r'mux\.HandleFunc\("([^"]+)"', text))
    missing = sorted(EXPECTED_ROUTES - routes)
    extra = sorted(routes - EXPECTED_ROUTES)
    forbidden_routes = sorted(route for route in routes if route != "/api/graph/entities/" and any(route.startswith(prefix) for prefix in FORBIDDEN_ROUTE_PREFIXES))
    graph_root = sorted(route for route in routes if route in {"/api/graph", "/api/graph/"} or (route.startswith("/api/graph/") and route != "/api/graph/entities/"))
    forbidden_code = sorted(marker for marker in FORBIDDEN_GRAPH_ROUTE_MARKERS if marker in text)
    missing_graph = [marker for marker in GRAPH_SERVER_SNIPPETS if marker not in text]
    return [
        {
            "name": "wave09-route-surface-retained",
            "path": "internal/httpapi/server.go",
            "status": "pass" if server_path.is_file() and not missing and not extra else "fail",
            "message": "" if server_path.is_file() and not missing and not extra else f"missing={missing} extra={extra}",
        },
        {
            "name": "wave09-secure-graph-routes-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_graph else "fail",
            "message": "" if not missing_graph else f"missing markers: {', '.join(missing_graph)}",
        },
        {
            "name": "wave09-no-out-of-scope-routes-or-handlers",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not forbidden_routes and not graph_root and not forbidden_code else "fail",
            "message": "" if not forbidden_routes and not graph_root and not forbidden_code else f"routes={forbidden_routes} graph_root={graph_root} code={forbidden_code}",
        },
    ]


def check_graph_presenters(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "internal" / "httpapi" / "server.go"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    dto = source_section(text, "type GraphEntityView struct", "type ErrorResponse struct")
    presenter = source_section(text, "func graphEntityView", "func eddOwnerView")
    shape_failures: list[str] = []
    for struct_name, expected_fields in GRAPH_DTO_FIELDS.items():
        fields = json_fields_for_struct(text, struct_name)
        if fields != expected_fields:
            shape_failures.append(f"{struct_name}: got={sorted(fields)} expected={sorted(expected_fields)}")
    leaked = sorted(marker for marker in FORBIDDEN_GRAPH_MARKERS if marker in dto or marker in presenter)
    return [
        {
            "name": "wave09-graph-dto-safe-shape",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not shape_failures else "fail",
            "message": "" if not shape_failures else "; ".join(shape_failures),
        },
        {
            "name": "wave09-graph-presenters-omit-private-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked else "fail",
            "message": "" if not leaked else f"private markers in graph DTO/presenter: {', '.join(leaked)}",
        },
    ]


def check_projection_contracts(repo_root: Path) -> list[dict[str, Any]]:
    contracts_path = repo_root / "internal" / "projection" / "contracts.go"
    tests_path = repo_root / "internal" / "projection" / "contracts_test.go"
    text = contracts_path.read_text(encoding="utf-8") if contracts_path.is_file() else ""
    tests = tests_path.read_text(encoding="utf-8") if tests_path.is_file() else ""
    side_view_section = source_section(text, "func CurrentSideViewContracts", "func FutureSafeContracts")
    body_structs = structs_with_json_field(text, "body")
    confidential_structs = structs_with_json_field(text, "confidential_comment")
    shape_failures: list[str] = []
    for struct_name, expected_fields in GRAPH_DTO_FIELDS.items():
        fields = json_fields_for_struct(text, struct_name)
        if fields != expected_fields:
            shape_failures.append(f"{struct_name}: got={sorted(fields)} expected={sorted(expected_fields)}")
        if snake_contract_name(struct_name) not in side_view_section:
            shape_failures.append(f"{snake_contract_name(struct_name)} missing from CurrentSideViewContracts")
    required_tests = [
        "TestAntiAML3GraphProjectionContractsDenyPrivateFields",
        "graph_entity",
        "graph_related_case",
        "edd_graph_summary",
        '"confidential_comment"',
        '"diff_json"',
        '"counterparty_fingerprint"',
        '"trace_id"',
        '"checker_private"',
        '"flag_value"',
    ]
    missing_tests = [marker for marker in required_tests if marker not in tests]
    return [
        {
            "name": "wave09-projection-graph-contracts-present",
            "path": "internal/projection/contracts.go",
            "status": "pass" if not shape_failures else "fail",
            "message": "" if not shape_failures else "; ".join(shape_failures),
        },
        {
            "name": "wave09-projection-private-fields-owner-only",
            "path": "internal/projection/contracts.go",
            "status": "pass" if body_structs == ALLOWED_PROJECTION_BODY_STRUCTS and confidential_structs == ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS else "fail",
            "message": "" if body_structs == ALLOWED_PROJECTION_BODY_STRUCTS and confidential_structs == ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS else f"body={sorted(body_structs)} confidential_comment={sorted(confidential_structs)}",
        },
        {
            "name": "wave09-projection-anti-aml3-tests-present",
            "path": "internal/projection/contracts_test.go",
            "status": "pass" if tests_path.is_file() and not missing_tests else "fail",
            "message": "" if tests_path.is_file() and not missing_tests else f"missing markers: {', '.join(missing_tests)}",
        },
    ]


def check_anti_aml3_tests(repo_root: Path) -> list[dict[str, Any]]:
    graph_test_path = repo_root / "internal" / "httpapi" / "graph_server_test.go"
    visibility_test_path = repo_root / "internal" / "httpapi" / "visibility_leak_test.go"
    source_test_path = repo_root / "tests" / "projection_visibility_test.go"
    graph_tests = graph_test_path.read_text(encoding="utf-8") if graph_test_path.is_file() else ""
    visibility_tests = visibility_test_path.read_text(encoding="utf-8") if visibility_test_path.is_file() else ""
    source_tests = source_test_path.read_text(encoding="utf-8") if source_test_path.is_file() else ""
    required_graph = [
        "TestAntiAML3RelatedGraphDoesNotExposePrivateStores",
        "ANTI_AML3_VICTIM_NOTE",
        "ANTI_AML3_VICTIM_EDD",
        "aml3-second-analyst",
        "aml3-shared-entity",
        "assertGraphResponsePublicOnly",
        "/api/graph/entities/aml3-shared-entity",
        "/api/graph/entities/aml3-shared-entity/related-cases",
        "/api/graph/entities/aml3-shared-entity/edd-summaries",
    ]
    required_visibility = [
        "graph entity secure side-view",
        "graph related cases secure side-view",
        "graph EDD summaries secure side-view",
        "foreign graph hint fail closed",
        "assertVisibilitySentinelsAbsent",
    ]
    required_source = [
        "TestGraphHTTPDTOAndPresenterStayPublicOnly",
        "TestAntiAML3GraphRepositorySummariesStayMetadataOnly",
        "graph DTOs",
        "graph presenters",
        "graph repository summary structs",
        "graph repository query methods",
    ]
    missing_graph = [marker for marker in required_graph if marker not in graph_tests]
    missing_visibility = [marker for marker in required_visibility if marker not in visibility_tests]
    missing_source = [marker for marker in required_source if marker not in source_tests]
    return [
        {
            "name": "wave09-anti-aml3-http-tests-present",
            "path": "internal/httpapi/graph_server_test.go",
            "status": "pass" if not missing_graph else "fail",
            "message": "" if not missing_graph else f"missing markers: {', '.join(missing_graph)}",
        },
        {
            "name": "wave09-graph-leak-regression-tests-present",
            "path": "internal/httpapi/visibility_leak_test.go",
            "status": "pass" if not missing_visibility else "fail",
            "message": "" if not missing_visibility else f"missing markers: {', '.join(missing_visibility)}",
        },
        {
            "name": "wave09-graph-source-guard-tests-present",
            "path": "tests/projection_visibility_test.go",
            "status": "pass" if not missing_source else "fail",
            "message": "" if not missing_source else f"missing markers: {', '.join(missing_source)}",
        },
    ]


def check_response_visibility(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    leaked = sorted(marker for marker in FORBIDDEN_RESPONSE_MARKERS if marker in text)
    body_structs = structs_with_json_field(text, "body")
    confidential_structs = structs_with_json_field(text, "confidential_comment")
    direct_model_encode = bool(
        re.search(r"json\.NewEncoder\([^)]*\)\.Encode\(\s*(?:customer|account|transaction|alert|investigationCase|note|record|user|session|event|events|summary|cases|summaries)\s*\)", text)
    )
    return [
        {
            "name": "wave09-http-dtos-avoid-internal-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked and not direct_model_encode else "fail",
            "message": "" if not leaked and not direct_model_encode else f"leaked={leaked} direct_model_encode={direct_model_encode}",
        },
        {
            "name": "wave09-http-body-owner-note-only",
            "path": "internal/httpapi/server.go",
            "status": "pass" if body_structs == ALLOWED_HTTP_BODY_STRUCTS else "fail",
            "message": "" if body_structs == ALLOWED_HTTP_BODY_STRUCTS else f"body_structs={sorted(body_structs)}",
        },
        {
            "name": "wave09-http-confidential-comment-owner-edd-only",
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
            "name": "wave09-logs-avoid-sensitive-fields",
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
            "name": "wave09-no-exploit-or-fix-scripts",
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
                "name": "wave09-report-present",
                "path": path,
                "status": "pass" if full_path.is_file() else "fail",
                "message": "" if full_path.is_file() else "required Wave 09 report is missing",
            }
        )
    return checks


def check_docs_status(repo_root: Path) -> list[dict[str, Any]]:
    paths = [
        repo_root / "README.md",
        repo_root / "docs" / "03_api_contract.md",
        repo_root / "docs" / "04_database_model.md",
        repo_root / "docs" / "05_authentication_authorization.md",
        repo_root / "docs" / "06_visibility_and_projections.md",
        repo_root / "docs" / "09_vulnerability_matrix.md",
        repo_root / "docs" / "12_testing_strategy.md",
        repo_root / "docs" / "13_roadmap.md",
        repo_root / "docs" / "waves.md",
        repo_root / "docs" / "source_of_truth_map.md",
        repo_root / "docs" / "wave_reports" / "wave_09_validation_summary.md",
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.is_file())
    required = [
        "Wave 08 | complete",
        "Wave 09 | needs fixes",
        "W08 | Audit timeline secure baseline | complete",
        "W09 | Related graph secure baseline | needs fixes",
        "scripts/check_wave09_gate.py",
        "make wave09-gate",
        "wave_09_validation_summary.md",
        "000007_create_entity_graph.sql",
        "GET /api/graph/entities/{entity_hint}",
        "GET /api/graph/entities/{entity_hint}/related-cases",
        "GET /api/graph/entities/{entity_hint}/edd-summaries",
        "GraphEntityView",
        "GraphRelatedCaseView",
        "EDDGraphSummaryView",
        "Anti-AML-3",
        "AML-3 remains future-only",
        "Wave 16",
        "CaseNote.body",
        "EDDRecord.confidential_comment",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave09-doc-status-and-authority",
            "path": "README.md docs/03_api_contract.md docs/04_database_model.md docs/05_authentication_authorization.md docs/06_visibility_and_projections.md docs/09_vulnerability_matrix.md docs/12_testing_strategy.md docs/13_roadmap.md docs/waves.md docs/source_of_truth_map.md docs/wave_reports/wave_09_validation_summary.md",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {', '.join(missing)}",
        }
    ]


def check_makefile(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "Makefile"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    required = [
        "wave09-gate",
        "scripts/check_wave09_gate.py",
        "GOFLAGS=-mod=vendor",
        "go test ./...",
        "go vet ./...",
        "scripts/check_docs_tree.py",
        "scripts/validate_forcad_config.py",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave09-make-target-present",
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


def snake_contract_name(struct_name: str) -> str:
    if struct_name == "EDDGraphSummaryView":
        return "edd_graph_summary"
    value = re.sub(r"View$", "", struct_name)
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()


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
    result = validate_wave09_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
