#!/usr/bin/env python3
"""Validate Wave 17 AML-4 vulnerable export profile and guardrails."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


EXPORT_SECURE_PROFILE = "internal/exporting/export_profile_secure.go"
EXPORT_VULNERABLE_PROFILE = "internal/exporting/export_profile_aml4_vulnerable.go"
HTTP_SECURE_PROFILE = "internal/httpapi/export_profile_secure.go"
HTTP_VULNERABLE_PROFILE = "internal/httpapi/export_profile_aml4_vulnerable.go"
EXPORT_REDACTION = "internal/exporting/redaction.go"
HTTP_SERVER = "internal/httpapi/server.go"
VULNERABLE_HTTP_TEST = "internal/httpapi/aml4_vulnerable_export_test.go"
SECURE_HTTP_TEST = "internal/httpapi/export_profile_secure_test.go"
VULNERABLE_EXPORT_TEST = "internal/exporting/export_profile_aml4_vulnerable_test.go"
HANDOFF_REPORT = "docs/wave_reports/wave_17_W17-T01_handoff.md"
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
    "aml5_vulnerable",
    "aml_5",
    "AML-5",
)
AML4_FORBIDDEN_EARLY_FILES = (
    "sploits/sentinel_aml/aml_export_redaction.py",
    "sploits/sentinel_aml/aml_regulatory_export.py",
    "fixes/sentinel_aml/aml_export_redaction.patch",
    "fixes/sentinel_aml/aml_export_redaction.diff",
    "fixes/sentinel_aml/aml_regulatory_export.patch",
    "fixes/sentinel_aml/aml_regulatory_export.diff",
)


def validate_wave17_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_profile_split(repo_root),
        check_export_bundle_profile_contract(repo_root),
        check_http_export_uses_profile(repo_root),
        check_vulnerability_tests(repo_root),
        check_no_reference_exploit_or_fix(repo_root),
        check_no_debug_admin_toggles(repo_root),
        check_no_future_aml_activation(repo_root),
        check_makefile_wave17_gate(repo_root),
        check_handoff_report(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_profile_split(repo_root: Path) -> dict[str, Any]:
    export_secure = read(repo_root, EXPORT_SECURE_PROFILE)
    export_vulnerable = read(repo_root, EXPORT_VULNERABLE_PROFILE)
    http_secure = read(repo_root, HTTP_SECURE_PROFILE)
    http_vulnerable = read(repo_root, HTTP_VULNERABLE_PROFILE)
    required = [
        (export_secure, "//go:build !aml4_vulnerable"),
        (export_secure, "aml4VulnerableProfileEnabled() bool"),
        (export_secure, "return false"),
        (export_secure, "appendExportProfileData"),
        (http_secure, "//go:build !aml4_vulnerable"),
        (http_secure, "populateExportLinkedCaseProfileData"),
        (export_vulnerable, "//go:build aml4_vulnerable"),
        (export_vulnerable, "aml4VulnerableProfileEnabled() bool"),
        (export_vulnerable, "return true"),
        (export_vulnerable, "ctx.DisputeID <= 0"),
        (export_vulnerable, 'scopes["linked_cases"]'),
        (export_vulnerable, "normalizeToken(note.Visibility) != \"private\""),
        (export_vulnerable, '"body"'),
        (http_vulnerable, "//go:build aml4_vulnerable"),
        (http_vulnerable, "FindDuplicatePrivateNotesForPreview"),
        (http_vulnerable, "populateExportLinkedCaseProfileData"),
        (http_vulnerable, "exportNoteSnapshot(note)"),
    ]
    forbidden_vulnerable = [
        "confidential_comment",
        "source_of_funds",
        "risk_rationale",
        "diff_json",
        "password_hash",
        "token_hash",
        "session",
        "network_room",
        "dossier",
    ]
    missing = [marker for text, marker in required if marker not in text]
    combined_vulnerable = "\n".join((export_vulnerable, http_vulnerable))
    forbidden = [marker for marker in forbidden_vulnerable if marker in combined_vulnerable]
    return {
        "name": "wave17-aml4-profile-split",
        "path": f"{EXPORT_SECURE_PROFILE} {EXPORT_VULNERABLE_PROFILE} {HTTP_SECURE_PROFILE} {HTTP_VULNERABLE_PROFILE}",
        "status": "pass" if not missing and not forbidden else "fail",
        "message": "" if not missing and not forbidden else f"missing={missing} forbidden={forbidden}",
    }


def check_export_bundle_profile_contract(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, EXPORT_REDACTION)
    context_section = source_section(text, "type ExportContext struct", "type CaseSnapshot")
    section = source_section(text, "type ExportBundle struct", "type ExportCaseShell struct")
    build_section = source_section(text, "func BuildBundle", "func flattenLinkedCases")
    required = [
        "DisputeID       int64",
        "LinkedPrivateNotes []map[string]any",
        'json:"linked_private_notes,omitempty"',
        "flattenLinkedCases(root.LinkedCases, visited)",
        "appendExportProfileData(&bundle, root, linkedCases, scopes, ctx)",
    ]
    forbidden = ['json:"body"', "ConfidentialComment string", "SourceOfFunds string", "RiskRationale string"]
    haystack = "\n".join((context_section, section, build_section))
    missing = missing_markers(haystack, required)
    present_forbidden = [marker for marker in forbidden if marker in haystack]
    return {
        "name": "wave17-export-bundle-profile-contract",
        "path": EXPORT_REDACTION,
        "status": "pass" if not missing and not present_forbidden else "fail",
        "message": "" if not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def check_http_export_uses_profile(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, HTTP_SERVER)
    handler_section = source_section(text, "func (s *Server) handleCreateCaseExport", "func (s *Server) handleExportsSubtree")
    builder_section = source_section(text, "func (s *Server) buildExportBundle", "func exportResponse")
    view_section = source_section(text, "func exportBundleView", "func exportCaseShellView")
    required = [
        "s.buildExportBundle(ctx, user.ID, caseID, disputeID, req)",
        "func (s *Server) buildExportBundle(ctx context.Context, ownerUserID, caseID, disputeID int64",
        "s.populateExportLinkedCaseProfileData(ctx, ownerUserID, caseID, &linkedSnapshot)",
        "DisputeID:       disputeID",
        "LinkedPrivateNotes: cloneExportProfileMaps(bundle.LinkedPrivateNotes)",
    ]
    forbidden = ["confidential_comment", "source_of_funds", "risk_rationale", "/api/debug", "/api/admin"]
    combined = "\n".join((handler_section, builder_section, view_section))
    missing = missing_markers(combined, required)
    present_forbidden = [marker for marker in forbidden if marker in combined]
    return {
        "name": "wave17-http-dispute-export-profile-hook",
        "path": HTTP_SERVER,
        "status": "pass" if handler_section and builder_section and not missing and not present_forbidden else "fail",
        "message": "" if handler_section and builder_section and not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def check_vulnerability_tests(repo_root: Path) -> dict[str, Any]:
    vulnerable_http = read(repo_root, VULNERABLE_HTTP_TEST)
    secure_http = read(repo_root, SECURE_HTTP_TEST)
    vulnerable_export = read(repo_root, VULNERABLE_EXPORT_TEST)
    required_vulnerable = [
        "//go:build aml4_vulnerable",
        "TestAML4VulnerableDisputeExportLeaksOnlyLinkedPrivateNote",
        "AML4_LINKED_PRIVATE_NOTE_LEAK_TARGET",
        "linked_private_notes",
        "assertAML4VulnerableExportLeakIsBounded",
        "confidential_comment",
        "cross-owner notes must fail closed",
        "cross-owner EDD must fail closed",
    ]
    required_export = [
        "//go:build aml4_vulnerable",
        "TestAML4VulnerableBuildBundleLeaksOnlyLinkedPrivateNotesForDisputeExport",
        "LINKED_PRIVATE_NOTE_SENTINEL",
        "NESTED_PRIVATE_NOTE_SENTINEL",
        "ROOT_PRIVATE_NOTE_SENTINEL",
        "ROOT_EDD_CONFIDENTIAL_SENTINEL",
    ]
    missing = missing_markers(vulnerable_http, required_vulnerable)
    missing += missing_markers(vulnerable_export, required_export)
    if "TestAML4SecureProfileDisputeExportRedactsLinkedPrivateNotes" not in secure_http:
        missing.append("default secure AML-4 export regression test")
    if "assertExportResponsePublicOnly" not in secure_http:
        missing.append("secure export public-only assertion")
    return {
        "name": "wave17-aml4-vulnerable-and-secure-tests",
        "path": f"{VULNERABLE_HTTP_TEST} {SECURE_HTTP_TEST} {VULNERABLE_EXPORT_TEST}",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_no_reference_exploit_or_fix(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    for relative in AML4_FORBIDDEN_EARLY_FILES:
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
        "name": "wave17-no-reference-exploit-or-fix",
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
        "name": "wave17-no-debug-admin-profile-toggle",
        "path": "cmd internal checkers config.yml docker-compose.yml Makefile",
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
        "name": "wave17-no-aml5-activation",
        "path": "cmd internal checkers config.yml docker-compose.yml Makefile",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_makefile_wave17_gate(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, "Makefile")
    target = makefile_target_section(text, "wave17-gate")
    required = [
        'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        'python -B -m unittest discover -s tests -p "test_wave17_gate.py"',
        "$(GO_OFFLINE_ENV) go test ./...",
        "$(GO_OFFLINE_ENV) go test -p 1 -tags aml4_vulnerable ./...",
        "$(GO_OFFLINE_ENV) go vet ./...",
        "python -B scripts/check_docs_tree.py",
        "python -B scripts/check_wave17_gate.py",
        "python -B scripts/check_competition_matrix_gate.py",
        "python -B scripts/validate_forcad_config.py",
    ]
    missing = missing_markers(target, required)
    return {
        "name": "wave17-make-target-runs-full-gate",
        "path": "Makefile",
        "status": "pass" if target and not missing else "fail",
        "message": "" if target and not missing else f"wave17-gate missing or incomplete: {missing}",
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
        "name": "wave17-t01-handoff-present",
        "path": HANDOFF_REPORT,
        "status": "pass" if text and not missing else "fail",
        "message": "" if text and not missing else f"missing markers: {missing}",
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
    result = validate_wave17_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
