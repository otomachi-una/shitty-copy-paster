#!/usr/bin/env python3
"""Validate Wave 16 AML-3 vulnerable graph profile and guardrails."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


SECURE_PROFILE = "internal/httpapi/graph_profile_secure.go"
VULNERABLE_PROFILE = "internal/httpapi/graph_profile_aml3_vulnerable.go"
VULNERABLE_REPOSITORY = "internal/graph/repository_aml3_vulnerable.go"
HTTP_SERVER = "internal/httpapi/server.go"
VULNERABLE_TEST = "internal/httpapi/aml3_vulnerable_graph_test.go"
SECURE_TEST = "internal/httpapi/graph_profile_secure_test.go"
GRAPH_SERVER_TEST = "internal/httpapi/graph_server_test.go"
HANDOFF_REPORT = "docs/wave_reports/wave_16_W16-T01_handoff.md"
ADR_0003 = "docs/decisions/ADR-0003-historical-vs-current-branch-gates.md"
SPLOIT_DIR = "sploits/sentinel_aml"
FIX_DIR = "fixes/sentinel_aml"
ALLOWED_PLACEHOLDER_FILES = {"README.md"}
PRODUCTION_SCAN_DIRS = ("cmd", "internal", "checkers")
PRODUCTION_SCAN_FILES = ("config.yml", "docker-compose.yml", "Makefile")
PRODUCTION_SCAN_SUFFIXES = {".go", ".py", ".yml", ".yaml", ".toml", ".sh", ".ps1"}
FORBIDDEN_DEBUG_ADMIN_ENDPOINTS = ("/api/debug", "/api/admin", "/debug", "/admin")
FORBIDDEN_DEBUG_ADMIN_TOGGLE_RE = re.compile(
    r"(?i)(debug|admin).{0,48}(variant|toggle|profile|mode|enable|enabled|flag)"
    r"|"
    r"(variant|toggle|profile|mode|enable|enabled|flag).{0,48}(debug|admin)"
)
FORBIDDEN_FUTURE_AML_MARKERS = (
    "aml4_vulnerable",
    "aml5_vulnerable",
    "aml_4",
    "aml_5",
    "AML-4",
    "AML-5",
)
AML3_FORBIDDEN_EARLY_FILES = (
    "sploits/sentinel_aml/aml_related_graph.py",
    "fixes/sentinel_aml/aml_related_graph.patch",
    "fixes/sentinel_aml/aml_related_graph.diff",
)


def validate_wave16_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_profile_split(repo_root),
        check_graph_handler_uses_profile(repo_root),
        check_vulnerable_repository_scope(repo_root),
        check_vulnerability_tests(repo_root),
        check_no_reference_exploit_or_fix(repo_root),
        check_no_debug_admin_toggles(repo_root),
        check_no_direct_db_checker_path(repo_root),
        check_no_future_aml_activation(repo_root),
        check_makefile_wave16_gate(repo_root),
        check_handoff_report(repo_root),
        check_status_ledger_reconciled(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_profile_split(repo_root: Path) -> dict[str, Any]:
    secure = read(repo_root, SECURE_PROFILE)
    vulnerable = read(repo_root, VULNERABLE_PROFILE)
    required_secure = [
        "//go:build !aml3_vulnerable",
        "aml3VulnerableProfileEnabled() bool",
        "return false",
        "EDDGraphSummariesResponse",
        "eddGraphSummaryViews(summaries)",
    ]
    required_vulnerable = [
        "//go:build aml3_vulnerable",
        "aml3VulnerableProfileEnabled() bool",
        "return true",
        "confidential_comment",
        "ListVulnerableEDDSummaries",
        "aml3VulnerableEDDGraphSummariesResponse",
    ]
    forbidden_vulnerable = [
        "source_of_funds",
        "risk_rationale",
        "case_note",
        "private_notes",
        "diff_json",
        "password_hash",
        "token_hash",
        "raw_db_row",
    ]
    missing = missing_markers(secure, required_secure) + missing_markers(vulnerable, required_vulnerable)
    forbidden = [marker for marker in forbidden_vulnerable if marker in vulnerable]
    return {
        "name": "wave16-aml3-profile-split",
        "path": f"{SECURE_PROFILE} {VULNERABLE_PROFILE}",
        "status": "pass" if not missing and not forbidden else "fail",
        "message": "" if not missing and not forbidden else f"missing={missing} forbidden={forbidden}",
    }


def check_graph_handler_uses_profile(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, HTTP_SERVER)
    section = source_section(text, "func (s *Server) handleGraphEDDSummaries", "func (s *Server) handleNetworkRoomsRoot")
    required = [
        "s.graph.ListEDDSummaries(ctx, user.ID, entityHint)",
        "s.graphEDDSummariesResponseForProfile(ctx, user.ID, entityHint, summaries)",
    ]
    forbidden = ["confidential_comment", "source_of_funds", "risk_rationale", "debug", "admin"]
    missing = missing_markers(section, required)
    present_forbidden = [marker for marker in forbidden if marker in section]
    return {
        "name": "wave16-graph-edd-summary-profile-hook",
        "path": HTTP_SERVER,
        "status": "pass" if section and not missing and not present_forbidden else "fail",
        "message": "" if section and not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def check_vulnerable_repository_scope(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, VULNERABLE_REPOSITORY)
    required = [
        "//go:build aml3_vulnerable",
        "type VulnerableEDDSummary struct",
        "ConfidentialComment string",
        "er.confidential_comment",
        "FROM edd_records er",
        "JOIN customers c ON c.id = er.customer_id",
        "owned.owner_user_id = $1",
        "lower(btrim(owned.entity_hint)) = $2",
    ]
    forbidden = [
        "case_notes",
        "source_of_funds",
        "risk_rationale",
        "audit_events",
        "diff_json",
        "password_hash",
        "token_hash",
        "sessions",
    ]
    missing = missing_markers(text, required)
    present_forbidden = [marker for marker in forbidden if marker in text]
    return {
        "name": "wave16-aml3-targeted-edd-comment-lookup",
        "path": VULNERABLE_REPOSITORY,
        "status": "pass" if not missing and not present_forbidden else "fail",
        "message": "" if not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def check_vulnerability_tests(repo_root: Path) -> dict[str, Any]:
    vulnerable = read(repo_root, VULNERABLE_TEST)
    secure = read(repo_root, SECURE_TEST)
    graph_server = read(repo_root, GRAPH_SERVER_TEST)
    required_vulnerable = [
        "//go:build aml3_vulnerable",
        "TestAML3VulnerableGraphEDDSummariesExposeOnlyConfidentialComment",
        "AML3_EDD_CONFIDENTIAL_COMMENT_LEAK_TARGET",
        "assertAML3GraphEDDLeakIsBounded",
        "assertExportResponsePublicOnly",
        "assertNetworkResponsePublicOnly",
        "cross-owner EDD must fail closed",
    ]
    missing = missing_markers(vulnerable, required_vulnerable)
    if "TestAML3SecureProfileDisabledByDefault" not in secure:
        missing.append("default secure AML-3 profile test")
    if "TestAntiAML3RelatedGraphDoesNotExposePrivateStores" not in graph_server:
        missing.append("secure anti-AML-3 graph regression test")
    if "assertGraphResponsePublicOnly" not in graph_server:
        missing.append("secure graph public-only assertion")
    return {
        "name": "wave16-aml3-vulnerable-and-secure-tests",
        "path": f"{VULNERABLE_TEST} {SECURE_TEST} {GRAPH_SERVER_TEST}",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_no_reference_exploit_or_fix(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    for relative in AML3_FORBIDDEN_EARLY_FILES:
        if (repo_root / relative).exists():
            findings.append(relative)
    for relative in (SPLOIT_DIR, FIX_DIR):
        base = repo_root / relative
        if not base.is_dir():
            findings.append(f"{relative}: missing")
            continue
        unexpected = sorted(
            path.relative_to(base).as_posix()
            for path in base.rglob("*")
            if path.is_file() and path.name not in ALLOWED_PLACEHOLDER_FILES
        )
        if unexpected:
            findings.append(f"{relative}: {unexpected}")
    return {
        "name": "wave16-no-reference-exploit-or-fix",
        "path": f"{SPLOIT_DIR} {FIX_DIR}",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_no_debug_admin_toggles(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    for path in iter_scanned_files(repo_root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        endpoint_hits = [endpoint for endpoint in FORBIDDEN_DEBUG_ADMIN_ENDPOINTS if endpoint in lowered]
        toggle_hit = FORBIDDEN_DEBUG_ADMIN_TOGGLE_RE.search(text)
        if endpoint_hits or toggle_hit:
            detail = ",".join(endpoint_hits) if endpoint_hits else toggle_hit.group(0)
            findings.append(f"{path.relative_to(repo_root).as_posix()}: {detail}")
    return {
        "name": "wave16-no-debug-admin-profile-toggle",
        "path": "cmd internal checkers config.yml docker-compose.yml Makefile",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_no_direct_db_checker_path(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    checker_dir = repo_root / "checkers"
    if checker_dir.is_dir():
        for path in checker_dir.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            for marker in ("psycopg", "asyncpg", "sqlalchemy", "postgresql://", "database/sql", "internal/"):
                if marker in text:
                    findings.append(f"{path.relative_to(repo_root).as_posix()}: {marker}")
    return {
        "name": "wave16-no-direct-db-checker-path",
        "path": "checkers",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_no_future_aml_activation(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    for path in iter_scanned_files(repo_root):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        hits = [marker for marker in FORBIDDEN_FUTURE_AML_MARKERS if marker in text]
        if hits:
            findings.append(f"{path.relative_to(repo_root).as_posix()}: {sorted(hits)}")
    return {
        "name": "wave16-no-aml4-or-aml5-activation",
        "path": "cmd internal checkers config.yml docker-compose.yml Makefile",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_makefile_wave16_gate(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, "Makefile")
    target = makefile_target_section(text, "wave16-gate")
    required = [
        'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        'python -B -m unittest discover -s tests -p "test_wave16_gate.py"',
        "$(GO_OFFLINE_ENV) go test ./...",
        "$(GO_OFFLINE_ENV) go test -tags aml3_vulnerable ./...",
        "$(GO_OFFLINE_ENV) go vet ./...",
        "python -B scripts/check_docs_tree.py",
        "python -B scripts/check_wave16_gate.py",
        "python -B scripts/check_competition_matrix_gate.py",
        "python -B scripts/validate_forcad_config.py",
    ]
    missing = missing_markers(target, required)
    return {
        "name": "wave16-make-target-runs-full-gate",
        "path": "Makefile",
        "status": "pass" if target and not missing else "fail",
        "message": "" if target and not missing else f"wave16-gate missing or incomplete: {missing}",
    }


def check_handoff_report(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, HANDOFF_REPORT)
    required = [
        "Summary",
        "Tests Run",
        "CTF Invariants Checked",
        "Security Invariants Checked",
        "Ready for Orchestrator Review",
    ]
    missing = missing_markers(text, required)
    return {
        "name": "wave16-t01-handoff-present",
        "path": HANDOFF_REPORT,
        "status": "pass" if text and not missing else "fail",
        "message": "" if text and not missing else f"missing markers: {missing}",
    }


def check_status_ledger_reconciled(repo_root: Path) -> dict[str, Any]:
    roadmap = read(repo_root, "docs/13_roadmap.md")
    waves = read(repo_root, "docs/waves.md")
    source_map = read(repo_root, "docs/source_of_truth_map.md")
    adr = read(repo_root, ADR_0003)
    combined = "\n".join((roadmap, waves, source_map, adr))
    required = [
        "ADR-0003",
        "point-in-time historical wave gates",
        "current-branch aggregate gates",
        "orchestrator review host reported `make wave16-gate` exiting 0",
        "| Wave 13 | complete |",
        "| Wave 14 | complete |",
        "| Wave 15 | complete |",
        "| Wave 16 | complete |",
        "| Wave 17 | ready |",
        "| W13 | Checker integration and HAVOC | complete |",
        "| W14 | Vulnerability 1: dedup preview | complete |",
        "| W15 | Vulnerability 2: audit timeline | complete |",
        "| W16 | Vulnerability 3: related graph | complete |",
        "| W17 | Vulnerability 4: export redaction | ready |",
        "No standalone Wave 14 or Wave 15 accepted review artifact is fabricated",
        "Reference exploit waves remain locked",
    ]
    forbidden = [
        "| Wave 13 | needs fixes |",
        "| Wave 15 | needs fixes |",
        "| Wave 16 | under review |",
        "| Waves 17-30 | blocked |",
        "| W13 | Checker integration and HAVOC | needs fixes |",
        "| W15 | Vulnerability 2: audit timeline | needs fixes |",
        "| W16 | Vulnerability 3: related graph | under review |",
        "| W17 | Vulnerability 4: export redaction | blocked |",
        "Wave 16 execution-blocked",
        "Wave 16 remains under review",
        "Waves 17-30 blocked",
    ]
    missing = missing_markers(combined, required)
    present_forbidden = [marker for marker in forbidden if marker in combined]
    return {
        "name": "wave16-status-ledger-reconciled",
        "path": f"docs/13_roadmap.md docs/waves.md docs/source_of_truth_map.md {ADR_0003}",
        "status": "pass" if not missing and not present_forbidden else "fail",
        "message": "" if not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def iter_scanned_files(repo_root: Path):
    for dirname in PRODUCTION_SCAN_DIRS:
        base = repo_root / dirname
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in PRODUCTION_SCAN_SUFFIXES:
                yield path
    for relative in PRODUCTION_SCAN_FILES:
        path = repo_root / relative
        if path.is_file():
            yield path


def read(repo_root: Path, relative: str) -> str:
    path = repo_root / relative
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def missing_markers(text: str, markers: list[str]) -> list[str]:
    return [marker for marker in markers if marker not in text]


def source_section(text: str, start: str, end: str) -> str:
    start_index = text.find(start)
    if start_index == -1:
        return ""
    end_index = text.find(end, start_index + len(start))
    if end_index == -1:
        return text[start_index:]
    return text[start_index:end_index]


def makefile_target_section(text: str, target_name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target_name)}:\s*$", text)
    if not match:
        return ""
    next_target = re.search(r"(?m)^[A-Za-z0-9_.-]+:\s*(?:#.*)?$", text[match.end() :])
    if not next_target:
        return text[match.start() :]
    return text[match.start() : match.end() + next_target.start()]


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave16_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
