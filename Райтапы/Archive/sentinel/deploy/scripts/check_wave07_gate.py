#!/usr/bin/env python3
"""Validate Wave 07 secure dedup baseline and release hygiene."""

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
    "handleAudit",
    "handleGraph",
    "handleExport",
    "handleNetwork",
    "handleChecker",
    "public attack",
    "attack-data",
    "audit timeline",
    "network-room",
)
DEDUP_SERVER_MARKERS = [
    "CaseDuplicatePreviewView",
    "CaseDuplicateCandidatesResponse",
    "CaseDuplicateMergePreviewResponse",
    'parts[1] == "duplicates"',
    'parts[3] == "merge-preview"',
    "handleCaseDuplicateCandidates",
    "handleCaseDuplicateMergePreview",
    "FindDuplicateCandidatesByOwner",
    "duplicatePreviewView(candidate)",
    "shared_dedup_hint",
]
DEDUP_DTO_FIELDS = {
    "case_id",
    "public_summary",
    "risk_tags",
    "overlap_score",
    "match_explanation",
}
FORBIDDEN_DEDUP_MARKERS = (
    "body",
    "Body",
    "CaseNote",
    "case_notes",
    "confidential_comment",
    "ConfidentialComment",
    "EDDRecord",
    "source_of_funds",
    "SourceOfFunds",
    "risk_rationale",
    "RiskRationale",
    "private_notes",
    "audit",
    "diff",
    "password_hash",
    "token_hash",
    "session",
    "checker_private",
    "flag_value",
    "owner_user_id",
    "analyst_user_id",
    "author_user_id",
    "assigned_user_id",
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
    "docs/wave_reports/wave_07_W07-T01_handoff.md",
    "docs/wave_reports/wave_07_W07-T02_handoff.md",
    "docs/wave_reports/wave_07_W07-T03_handoff.md",
    "docs/wave_reports/wave_07_W07-T04_handoff.md",
    "docs/wave_reports/wave_07_validation_summary.md",
]


def validate_wave07_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_migrations(repo_root))
    checks.extend(check_routes(repo_root))
    checks.extend(check_repositories(repo_root))
    checks.extend(check_projection_contracts(repo_root))
    checks.extend(check_dedup_presenters(repo_root))
    checks.extend(check_anti_aml1_tests(repo_root))
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
        return [{"name": "wave07-migrations-present-ordered", "path": "migrations", "status": "fail", "message": "migrations directory is missing"}]
    names = sorted(path.name for path in migrations_dir.glob("*.sql") if path.is_file())
    migration_text = "\n".join((migrations_dir / name).read_text(encoding="utf-8") for name in names)
    tables = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\b", migration_text))
    forbidden = sorted(tables & FORBIDDEN_TABLES)
    dedup_path = migrations_dir / "000005_add_case_dedup_hint.sql"
    dedup_text = dedup_path.read_text(encoding="utf-8") if dedup_path.is_file() else ""
    required_dedup = [
        "ALTER TABLE cases",
        "ADD COLUMN dedup_hint text NOT NULL DEFAULT ''",
        "cases_dedup_hint_not_blank_when_set",
        "CHECK (dedup_hint = '' OR btrim(dedup_hint) <> '')",
        "CREATE INDEX cases_dedup_hint_idx",
        "CREATE INDEX cases_owner_dedup_hint_idx",
    ]
    missing_dedup = [snippet for snippet in required_dedup if snippet not in dedup_text]
    return [
        {
            "name": "wave07-migrations-present-ordered",
            "path": "migrations",
            "status": "pass" if names == EXPECTED_MIGRATIONS and has_ordered_numeric_prefixes(names) else "fail",
            "message": "" if names == EXPECTED_MIGRATIONS else f"expected {EXPECTED_MIGRATIONS}, got {names}",
        },
        {
            "name": "wave07-tables-in-scope",
            "path": "migrations",
            "status": "pass" if tables == EXPECTED_TABLES and not forbidden else "fail",
            "message": "" if tables == EXPECTED_TABLES and not forbidden else f"tables={sorted(tables)} forbidden={forbidden}",
        },
        {
            "name": "wave07-dedup-metadata-contract",
            "path": "migrations/000005_add_case_dedup_hint.sql",
            "status": "pass" if dedup_path.is_file() and not missing_dedup else "fail",
            "message": "" if dedup_path.is_file() and not missing_dedup else f"missing snippets: {', '.join(missing_dedup)}",
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
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    routes = set(re.findall(r'mux\.HandleFunc\("([^"]+)"', text))
    missing = sorted(EXPECTED_ROUTES - routes)
    extra = sorted(routes - EXPECTED_ROUTES)
    forbidden_routes = sorted(route for route in routes if any(route.startswith(prefix) for prefix in FORBIDDEN_ROUTE_PREFIXES))
    forbidden_code = sorted(marker for marker in FORBIDDEN_CODE_MARKERS if marker in text)
    missing_dedup = [marker for marker in DEDUP_SERVER_MARKERS if marker not in text]
    return [
        {
            "name": "wave07-route-surface-retained",
            "path": "internal/httpapi/server.go",
            "status": "pass" if server_path.is_file() and not missing and not extra else "fail",
            "message": "" if server_path.is_file() and not missing and not extra else f"missing={missing} extra={extra}",
        },
        {
            "name": "wave07-secure-dedup-routes-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_dedup else "fail",
            "message": "" if not missing_dedup else f"missing markers: {', '.join(missing_dedup)}",
        },
        {
            "name": "wave07-no-out-of-scope-routes-or-handlers",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not forbidden_routes and not forbidden_code else "fail",
            "message": "" if not forbidden_routes and not forbidden_code else f"routes={forbidden_routes} code={forbidden_code}",
        },
    ]


def check_repositories(repo_root: Path) -> list[dict[str, Any]]:
	path = repo_root / "internal" / "casework" / "repository.go"
	text = path.read_text(encoding="utf-8") if path.is_file() else ""
	dedup_section = source_section(text, "func (r *Repository) FindDuplicateCandidatesByOwner", "func (r *Repository) CreateNote")
	required = [
		"DedupHint",
		"DuplicateCandidate",
        "FindDuplicateCandidatesByOwner(ctx context.Context, ownerUserID, sourceCaseID int64)",
        "WHERE owner_user_id = $1 AND id = $2",
        "c.dedup_hint = $1",
        "c.id <> $2",
        "JOIN customers cust ON cust.id = c.customer_id",
		"ORDER BY c.id",
	]
	missing = [marker for marker in required if marker not in text]
	forbidden = [marker for marker in ("JOIN case_notes", "JOIN edd_records", "confidential_comment", "cn.body") if marker in dedup_section]
	return [
        {
            "name": "wave07-dedup-repository-secure-shape",
            "path": "internal/casework/repository.go",
            "status": "pass" if path.is_file() and not missing and not forbidden else "fail",
            "message": "" if path.is_file() and not missing and not forbidden else f"missing={missing} forbidden={forbidden}",
        }
    ]


def check_projection_contracts(repo_root: Path) -> list[dict[str, Any]]:
    contracts_path = repo_root / "internal" / "projection" / "contracts.go"
    tests_path = repo_root / "internal" / "projection" / "contracts_test.go"
    text = contracts_path.read_text(encoding="utf-8") if contracts_path.is_file() else ""
    tests = tests_path.read_text(encoding="utf-8") if tests_path.is_file() else ""
    side_view_section = source_section(text, "func CurrentSideViewContracts", "func FutureSafeContracts")
    body_structs = structs_with_json_field(text, "body")
    confidential_structs = structs_with_json_field(text, "confidential_comment")
    fields = json_fields_for_struct(text, "CaseDuplicatePreviewView")
    missing_fields = sorted(DEDUP_DTO_FIELDS - fields)
    extra_fields = sorted(fields - DEDUP_DTO_FIELDS)
    required_tests = [
        "TestCurrentSideViewProjectionContractsDenyPrivateFields",
        "forbiddenCurrentSideView",
        '"body"',
        '"confidential_comment"',
        '"private_notes"',
        '"audit"',
        '"diff"',
        '"session"',
        '"checker_private"',
    ]
    missing_tests = [marker for marker in required_tests if marker not in tests]
    return [
        {
            "name": "wave07-projection-dedup-contract-present",
            "path": "internal/projection/contracts.go",
            "status": "pass" if "CaseDuplicatePreviewView" in text and "case_duplicate_preview" in side_view_section and not missing_fields and not extra_fields else "fail",
            "message": "" if "CaseDuplicatePreviewView" in text and "case_duplicate_preview" in side_view_section and not missing_fields and not extra_fields else f"missing_fields={missing_fields} extra_fields={extra_fields}",
        },
        {
            "name": "wave07-projection-private-fields-owner-only",
            "path": "internal/projection/contracts.go",
            "status": "pass" if body_structs == ALLOWED_PROJECTION_BODY_STRUCTS and confidential_structs == ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS else "fail",
            "message": "" if body_structs == ALLOWED_PROJECTION_BODY_STRUCTS and confidential_structs == ALLOWED_PROJECTION_CONFIDENTIAL_STRUCTS else f"body={sorted(body_structs)} confidential_comment={sorted(confidential_structs)}",
        },
        {
            "name": "wave07-projection-side-view-private-field-tests",
            "path": "internal/projection/contracts_test.go",
            "status": "pass" if tests_path.is_file() and not missing_tests else "fail",
            "message": "" if tests_path.is_file() and not missing_tests else f"missing markers: {', '.join(missing_tests)}",
        },
    ]


def check_dedup_presenters(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "internal" / "httpapi" / "server.go"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    dto = source_section(text, "type CaseDuplicatePreviewView struct", "type CaseDuplicateCandidatesResponse struct")
    presenter = source_section(text, "func duplicatePreviewViews", "func eddOwnerView")
    fields = json_fields_for_struct(text, "CaseDuplicatePreviewView")
    missing_fields = sorted(DEDUP_DTO_FIELDS - fields)
    extra_fields = sorted(fields - DEDUP_DTO_FIELDS)
    leaked = sorted(marker for marker in FORBIDDEN_DEDUP_MARKERS if marker in dto or marker in presenter)
    return [
        {
            "name": "wave07-dedup-dto-public-shape",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_fields and not extra_fields else "fail",
            "message": "" if not missing_fields and not extra_fields else f"missing_fields={missing_fields} extra_fields={extra_fields}",
        },
        {
            "name": "wave07-dedup-presenters-omit-private-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked else "fail",
            "message": "" if not leaked else f"private markers in dedup DTO/presenter: {', '.join(leaked)}",
        },
    ]


def check_anti_aml1_tests(repo_root: Path) -> list[dict[str, Any]]:
    http_test_path = repo_root / "internal" / "httpapi" / "domain_server_test.go"
    visibility_test_path = repo_root / "internal" / "httpapi" / "visibility_leak_test.go"
    projection_test_path = repo_root / "tests" / "projection_visibility_test.go"
    http_tests = http_test_path.read_text(encoding="utf-8") if http_test_path.is_file() else ""
    visibility_tests = visibility_test_path.read_text(encoding="utf-8") if visibility_test_path.is_file() else ""
    projection_tests = projection_test_path.read_text(encoding="utf-8") if projection_test_path.is_file() else ""
    required_http = [
        "TestSecureDedupEndpointsExposeOnlyPublicOverlap",
        "TestAntiAML1DedupMergePreviewDoesNotLeakCandidatePrivateData",
        "TestCaseDuplicatePreviewResponseShapeIsStable",
        "AML1_WOULD_LEAK_NOTE_BODY",
        "AML1_WOULD_LEAK_EDD_COMMENT",
        "assertDedupResponsePublicOnly",
        '"body"',
        '"confidential_comment"',
        '"private_notes"',
        '"audit"',
        '"diff"',
        '"session"',
        '"checker_private"',
        '"flag_value"',
        '"case_id", "public_summary", "risk_tags", "overlap_score", "match_explanation"',
    ]
    required_visibility = [
        "case duplicates secure side-view",
        "case merge preview secure side-view",
        "cross-owner duplicates endpoint",
        "assertVisibilitySentinelsAbsent",
    ]
    required_source = [
        "TestDedupHTTPDTOAndPresenterStayPublicOnly",
        "CaseDuplicatePreviewView DTO",
        "dedup presenter",
        "sourceSection",
        "CaseNote",
        "confidential_comment",
        "EDDRecord",
    ]
    missing_http = [marker for marker in required_http if marker not in http_tests]
    missing_visibility = [marker for marker in required_visibility if marker not in visibility_tests]
    missing_source = [marker for marker in required_source if marker not in projection_tests]
    return [
        {
            "name": "wave07-anti-aml1-http-tests-present",
            "path": "internal/httpapi/domain_server_test.go",
            "status": "pass" if not missing_http else "fail",
            "message": "" if not missing_http else f"missing markers: {', '.join(missing_http)}",
        },
        {
            "name": "wave07-dedup-leak-regression-tests-present",
            "path": "internal/httpapi/visibility_leak_test.go",
            "status": "pass" if not missing_visibility else "fail",
            "message": "" if not missing_visibility else f"missing markers: {', '.join(missing_visibility)}",
        },
        {
            "name": "wave07-dedup-source-guard-tests-present",
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
        re.search(r"json\.NewEncoder\([^)]*\)\.Encode\(\s*(?:customer|account|transaction|alert|investigationCase|note|record|user|session|result)\s*\)", text)
    )
    return [
        {
            "name": "wave07-http-dtos-avoid-internal-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked and not direct_model_encode else "fail",
            "message": "" if not leaked and not direct_model_encode else f"leaked={leaked} direct_model_encode={direct_model_encode}",
        },
        {
            "name": "wave07-http-body-owner-note-only",
            "path": "internal/httpapi/server.go",
            "status": "pass" if body_structs == ALLOWED_HTTP_BODY_STRUCTS else "fail",
            "message": "" if body_structs == ALLOWED_HTTP_BODY_STRUCTS else f"body_structs={sorted(body_structs)}",
        },
        {
            "name": "wave07-http-confidential-comment-owner-edd-only",
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
            "name": "wave07-logs-avoid-sensitive-fields",
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
            "name": "wave07-no-exploit-or-fix-scripts",
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
                "name": "wave07-report-present",
                "path": path,
                "status": "pass" if full_path.is_file() else "fail",
                "message": "" if full_path.is_file() else "required Wave 07 report is missing",
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
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.is_file())
    required = [
        "Wave 06 | complete",
        "Wave 07 | needs fixes",
        "W06 | Visibility and projection hardening | complete",
        "W07 | Dedup preview secure baseline | needs fixes",
        "scripts/check_wave07_gate.py",
        "make wave07-gate",
        "wave_07_validation_summary.md",
        "000005_add_case_dedup_hint.sql",
        "GET /api/cases/{case_id}/duplicates",
        "GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview",
        "CaseDuplicatePreviewView",
        "AML-1 remains future-only",
        "Anti-AML-1",
        "CaseNote.body",
        "EDDRecord.confidential_comment",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave07-doc-status-and-authority",
            "path": "README.md docs/03_api_contract.md docs/04_database_model.md docs/05_authentication_authorization.md docs/06_visibility_and_projections.md docs/09_vulnerability_matrix.md docs/12_testing_strategy.md docs/13_roadmap.md docs/waves.md docs/source_of_truth_map.md",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {', '.join(missing)}",
        }
    ]


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
    result = validate_wave07_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
