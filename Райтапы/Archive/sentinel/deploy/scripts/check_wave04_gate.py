#!/usr/bin/env python3
"""Validate Wave 04 risk/alert/case/note integration and visibility guardrails."""

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
]
EXPECTED_TABLES = {"users", "sessions", "customers", "accounts", "transactions", "alerts", "cases", "case_notes"}
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
    "WithInvestigationRepositories",
    "AlertResponse",
    "CaseResponse",
    "CaseNoteResponse",
    "TriageAlertRequest",
    "CreateCaseRequest",
    "UpdateCaseStatusRequest",
    "CreateCaseNoteRequest",
    "handleAlertsQueue",
    "handleClaimAlert",
    "handleTriageAlert",
    "handleCreateCaseFromAlert",
    "handleCaseNotes",
    "handleUpdateCaseStatus",
    "invalid_transition",
    "duplicate_case",
]
REQUIRED_REPOSITORY_MARKERS = {
    "internal/alert/repository.go": [
        "ListByOwner",
        "GetByOwner",
        "Claim",
        "Triage",
        "JOIN customers c",
        "c.owner_user_id = $1",
        "ErrInvalidTransition",
    ],
    "internal/casework/repository.go": [
        "CreateFromAlert",
        "GetByOwner",
        "UpdateStatus",
        "CreateNote",
        "ListNotesByOwner",
        "owner_user_id = $1",
        "ErrInvalidTransition",
    ],
    "internal/risk/scoring.go": [
        "ScoreTransaction",
        "RuleDeterministicThreshold",
        "SuspiciousThreshold",
        "UpdateRiskScoreByOwner",
        "alertrepo.ErrDuplicate",
    ],
}
EXPECTED_WAVE_REPORTS = [
    "docs/wave_reports/wave_04_W04-T01_handoff.md",
    "docs/wave_reports/wave_04_W04-T02_handoff.md",
    "docs/wave_reports/wave_04_W04-T03_handoff.md",
    "docs/wave_reports/wave_04_W04-T04_handoff.md",
    "docs/wave_reports/wave_04_validation_summary.md",
]
FORBIDDEN_TABLES = {
    "edd_records",
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
    "handleEDD",
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
FORBIDDEN_LOG_FIELDS = ("password", "password_hash", "token", "token_hash", "authorization", "body")
FORBIDDEN_EXPLOIT_NAMES = [
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
]
EXPECTED_WAVE03_EXPANSION_FAILURES = {
    "wave03-migrations-present-ordered",
    "wave03-tables-only",
    "wave03-routes-present",
    "no-side-view-or-later-routes",
}


def validate_wave04_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_migrations(repo_root))
    checks.extend(check_routes(repo_root))
    checks.extend(check_repositories(repo_root))
    checks.extend(check_response_visibility(repo_root))
    checks.extend(check_note_body_containment(repo_root))
    checks.extend(check_logs(repo_root))
    checks.extend(check_no_exploit_scripts(repo_root))
    checks.extend(check_live_gate(repo_root))
    checks.extend(check_wave_reports(repo_root))
    checks.extend(check_docs_status(repo_root))
    checks.extend(check_external_validator(repo_root, "docs-tree", "scripts/check_docs_tree.py", "validate_docs_tree"))
    checks.extend(check_external_validator(repo_root, "forcad-config", "scripts/validate_forcad_config.py", "validate_config"))
    checks.extend(check_external_validator(repo_root, "wave01-scope", "scripts/check_wave01_scope.py", "validate_wave01_scope"))
    checks.extend(check_wave03_invariants(repo_root))
    return {"status": aggregate_status(checks), "checks": checks}


def check_migrations(repo_root: Path) -> list[dict[str, Any]]:
    migrations_dir = repo_root / "migrations"
    if not migrations_dir.is_dir():
        return [{"name": "wave04-migrations-present-ordered", "path": "migrations", "status": "fail", "message": "migrations directory is missing"}]

    names = sorted(path.name for path in migrations_dir.glob("*.sql") if path.is_file())
    migration_text = "\n".join((migrations_dir / name).read_text(encoding="utf-8") for name in names)
    tables = set(re.findall(r"(?im)^\s*CREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\b", migration_text))
    forbidden = sorted(tables & FORBIDDEN_TABLES)
    required_snippets = [
        "CREATE TABLE alerts",
        "CREATE TABLE cases",
        "CREATE TABLE case_notes",
        "transaction_id bigint NOT NULL REFERENCES transactions(id) ON DELETE CASCADE",
        "customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE",
        "owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE",
        "case_id bigint NOT NULL REFERENCES cases(id) ON DELETE CASCADE",
        "body text NOT NULL",
        "UNIQUE (transaction_id, rule_code)",
        "UNIQUE (alert_id)",
        "CHECK (visibility IN ('private', 'internal'))",
        "CREATE INDEX alerts_customer_status_idx",
        "CREATE INDEX cases_owner_status_idx",
        "CREATE INDEX case_notes_case_id_idx",
    ]
    missing = [snippet for snippet in required_snippets if snippet not in migration_text]

    return [
        {
            "name": "wave04-migrations-present-ordered",
            "path": "migrations",
            "status": "pass" if names == EXPECTED_MIGRATIONS and has_ordered_numeric_prefixes(names) else "fail",
            "message": "" if names == EXPECTED_MIGRATIONS else f"expected {EXPECTED_MIGRATIONS}, got {names}",
        },
        {
            "name": "wave04-tables-in-scope",
            "path": "migrations",
            "status": "pass" if tables == EXPECTED_TABLES and not forbidden else "fail",
            "message": "" if tables == EXPECTED_TABLES and not forbidden else f"tables={sorted(tables)} forbidden={forbidden}",
        },
        {
            "name": "wave04-investigation-schema-contracts",
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
        return [{"name": "wave04-routes-present", "path": "internal/httpapi/server.go", "status": "fail", "message": "server.go is missing"}]

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
            "name": "wave04-routes-present",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_routes and not extra_routes else "fail",
            "message": "" if not missing_routes and not extra_routes else f"missing={missing_routes} extra={extra_routes}",
        },
        {
            "name": "wave04-routes-require-auth",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not missing_protection else "fail",
            "message": "" if not missing_protection else f"missing protected routes: {', '.join(missing_protection)}",
        },
        {
            "name": "wave04-route-handlers-and-dtos-present",
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
    checks: list[dict[str, Any]] = []
    for relative, markers in REQUIRED_REPOSITORY_MARKERS.items():
        path = repo_root / relative
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        missing = [marker for marker in markers if marker not in text]
        checks.append(
            {
                "name": "wave04-repository-owner-and-risk-scope",
                "path": relative,
                "status": "pass" if path.is_file() and not missing else "fail",
                "message": "" if path.is_file() and not missing else f"missing markers: {', '.join(missing)}",
            }
        )
    return checks


def check_response_visibility(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    leaked = sorted(marker for marker in FORBIDDEN_RESPONSE_MARKERS if marker in text)
    serializes_db_model = bool(
        re.search(r"json\.NewEncoder\([^)]*\)\.Encode\(\s*(?:customer|account|transaction|alert|investigationCase|note|user|session|result)\s*\)", text)
    )
    return [
        {
            "name": "wave04-dtos-avoid-internal-fields",
            "path": "internal/httpapi/server.go",
            "status": "pass" if not leaked and not serializes_db_model else "fail",
            "message": "" if not leaked and not serializes_db_model else f"leaked={leaked} serializes_db_model={serializes_db_model}",
        }
    ]


def check_note_body_containment(repo_root: Path) -> list[dict[str, Any]]:
    server_path = repo_root / "internal" / "httpapi" / "server.go"
    tests_path = repo_root / "internal" / "httpapi" / "domain_server_test.go"
    live_path = repo_root / "internal" / "httpapi" / "live_postgres_integration_test.go"
    server_text = server_path.read_text(encoding="utf-8") if server_path.is_file() else ""
    tests_text = tests_path.read_text(encoding="utf-8") if tests_path.is_file() else ""
    live_text = live_path.read_text(encoding="utf-8") if live_path.is_file() else ""

    body_json_count = server_text.count('json:"body"')
    note_request_has_body = "type CreateCaseNoteRequest struct" in server_text and 'Body       string `json:"body"`' in server_text
    note_response_has_body = "type CaseNoteResponse struct" in server_text and 'Body         string    `json:"body"`' in server_text
    alert_case_body_leak = bool(re.search(r"type\s+(?:AlertResponse|CaseResponse)\s+struct\s*{[^}]*json:\"body", server_text, re.S))
    note_handlers_present = "handleCaseNotes" in server_text and "caseNoteResponse(note)" in server_text and "caseNoteResponses(notes)" in server_text
    required_test_markers = [
        "Private owner-only note",
        "cross-owner response leaked note body",
        "/api/cases/%d/notes/public",
        "TestLivePostgresWave04InvestigationAPIIntegration",
        "Live private owner note",
    ]
    combined_tests = tests_text + "\n" + live_text
    missing_tests = [marker for marker in required_test_markers if marker not in combined_tests]

    return [
        {
            "name": "case-note-body-owner-view-only",
            "path": "internal/httpapi/server.go",
            "status": "pass" if body_json_count == 2 and note_request_has_body and note_response_has_body and not alert_case_body_leak and note_handlers_present else "fail",
            "message": ""
            if body_json_count == 2 and note_request_has_body and note_response_has_body and not alert_case_body_leak and note_handlers_present
            else f"body_json_count={body_json_count} note_request_has_body={note_request_has_body} note_response_has_body={note_response_has_body} alert_case_body_leak={alert_case_body_leak} note_handlers_present={note_handlers_present}",
        },
        {
            "name": "case-note-body-non-owner-regression-tests",
            "path": "internal/httpapi/domain_server_test.go internal/httpapi/live_postgres_integration_test.go",
            "status": "pass" if not missing_tests else "fail",
            "message": "" if not missing_tests else f"missing markers: {', '.join(missing_tests)}",
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
            "name": "logs-avoid-secrets-and-note-bodies",
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
            "name": "no-wave04-exploit-scripts",
            "path": "sploits/sentinel_aml",
            "status": "pass" if not files and not planned else "fail",
            "message": "" if not files and not planned else f"unexpected exploit scripts: {', '.join(files)}",
        }
    ]


def check_live_gate(repo_root: Path) -> list[dict[str, Any]]:
    live_path = repo_root / "internal" / "httpapi" / "live_postgres_integration_test.go"
    tests_live_path = repo_root / "tests" / "wave03_live_postgres_test.go"
    makefile_path = repo_root / "Makefile"
    live_text = live_path.read_text(encoding="utf-8") if live_path.is_file() else ""
    tests_live_text = tests_live_path.read_text(encoding="utf-8") if tests_live_path.is_file() else ""
    makefile_text = makefile_path.read_text(encoding="utf-8") if makefile_path.is_file() else ""
    required_live_markers = [
        "TestLivePostgresWave04InvestigationAPIIntegration",
        "SENTINEL_AML_INTEGRATION_DATABASE_URL",
        "ApplyMigrations",
        "WithInvestigationRepositories",
        "WithTransactionRiskService",
        '"/api/alerts/queue"',
        '"/api/cases/%d/notes"',
        "http.StatusNotFound",
        "assertIntegrationResponseClean",
    ]
    required_risk_markers = ["TestWave04LivePostgresRiskAlertGeneration", "risk.NewService", "alertRepo.ListByOwner"]
    missing_live = [marker for marker in required_live_markers if marker not in live_text]
    missing_risk = [marker for marker in required_risk_markers if marker not in tests_live_text]
    return [
        {
            "name": "wave04-live-owner-api-gate-present",
            "path": "internal/httpapi/live_postgres_integration_test.go",
            "status": "pass" if live_path.is_file() and not missing_live else "fail",
            "message": "" if live_path.is_file() and not missing_live else f"missing markers: {', '.join(missing_live)}",
        },
        {
            "name": "wave04-live-risk-alert-gate-present",
            "path": "tests/wave03_live_postgres_test.go",
            "status": "pass" if tests_live_path.is_file() and not missing_risk else "fail",
            "message": "" if tests_live_path.is_file() and not missing_risk else f"missing markers: {', '.join(missing_risk)}",
        },
        {
            "name": "wave04-make-target-present",
            "path": "Makefile",
            "status": "pass" if "wave04-gate:" in makefile_text and "check_wave04_gate.py" in makefile_text else "fail",
            "message": "" if "wave04-gate:" in makefile_text and "check_wave04_gate.py" in makefile_text else "wave04-gate target missing",
        },
        {
            "name": "wave04-live-make-target-present",
            "path": "Makefile",
            "status": "pass" if "live-wave04-integration:" in makefile_text and "TestLivePostgresWave04InvestigationAPIIntegration" in makefile_text else "fail",
            "message": "" if "live-wave04-integration:" in makefile_text and "TestLivePostgresWave04InvestigationAPIIntegration" in makefile_text else "live Wave 04 integration target missing",
        },
    ]


def check_wave_reports(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path in EXPECTED_WAVE_REPORTS:
        full_path = repo_root / path
        checks.append(
            {
                "name": "wave04-report-present",
                "path": path,
                "status": "pass" if full_path.is_file() else "fail",
                "message": "" if full_path.is_file() else "required Wave 04 report is missing",
            }
        )
    return checks


def check_docs_status(repo_root: Path) -> list[dict[str, Any]]:
    roadmap = repo_root / "docs" / "13_roadmap.md"
    waves = repo_root / "docs" / "waves.md"
    readme = repo_root / "README.md"
    text = "\n".join(path.read_text(encoding="utf-8") for path in (roadmap, waves, readme) if path.is_file())
    required = [
        "Wave 04 | needs fixes",
        "W04 | Risk scoring, alerts, and owner case workflow | needs fixes",
        "make wave04-gate",
        "live-wave04-integration",
        "CaseNote.body",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave04-doc-status-and-command-surface",
            "path": "README.md docs/13_roadmap.md docs/waves.md",
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


def check_wave03_invariants(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "scripts" / "check_wave03_gate.py"
    spec = importlib.util.spec_from_file_location("check_wave03_gate", path)
    if spec is None or spec.loader is None:
        return [{"name": "wave03-invariants", "path": "scripts/check_wave03_gate.py", "status": "fail", "message": "Wave 03 gate unavailable"}]

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.validate_wave03_gate(repo_root)
    failures = [check for check in result["checks"] if check["status"] == "fail"]
    failure_names = {check["name"] for check in failures}
    unexpected = sorted(failure_names - EXPECTED_WAVE03_EXPANSION_FAILURES)
    missing_expected = sorted(EXPECTED_WAVE03_EXPANSION_FAILURES - failure_names)
    status = "pass" if not unexpected and not missing_expected else "fail"
    message = ""
    if unexpected or missing_expected:
        message = f"unexpected={unexpected} missing_expected={missing_expected} failures={failures}"
    return [
        {
            "name": "wave03-invariants-retained-with-wave04-expansion",
            "path": "scripts/check_wave03_gate.py",
            "status": status,
            "message": message,
        }
    ]


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave04_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
