#!/usr/bin/env python3
"""Validate Wave 14 AML-1 vulnerable dedup preview profile and guardrails."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


SECURE_PROFILE = "internal/httpapi/dedup_profile_secure.go"
VULNERABLE_PROFILE = "internal/httpapi/dedup_profile_aml1_vulnerable.go"
CASEWORK_REPOSITORY = "internal/casework/repository.go"
HTTP_SERVER = "internal/httpapi/server.go"
VULNERABLE_TEST = "internal/httpapi/aml1_vulnerable_dedup_test.go"
SECURE_TEST = "internal/httpapi/domain_server_test.go"
HANDOFF_REPORTS = (
    "docs/wave_reports/wave_14_W14-T01_handoff.md",
    "docs/wave_reports/wave_14_W14-T02_handoff.md",
    "docs/wave_reports/wave_14_W14-T03_handoff.md",
)
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
    "aml2_vulnerable",
    "aml3_vulnerable",
    "aml4_vulnerable",
    "aml5_vulnerable",
    "aml_2",
    "aml_3",
    "aml_4",
    "aml_5",
    "AML-2",
    "AML-3",
    "AML-4",
    "AML-5",
)


def validate_wave14_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_profile_split(repo_root),
        check_targeted_repository_lookup(repo_root),
        check_http_merge_preview_uses_profile(repo_root),
        check_vulnerability_tests(repo_root),
        check_no_reference_exploit_or_fix(repo_root),
        check_no_debug_admin_toggles(repo_root),
        check_no_future_aml_activation(repo_root),
        check_makefile_wave14_gate(repo_root),
        check_handoff_reports(repo_root),
        check_docs(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_profile_split(repo_root: Path) -> dict[str, Any]:
    secure = read(repo_root, SECURE_PROFILE)
    vulnerable = read(repo_root, VULNERABLE_PROFILE)
    required_secure = [
        "//go:build !aml1_vulnerable",
        "aml1VulnerableProfileEnabled() bool",
        "return false",
        "CaseDuplicateMergePreviewResponse",
        "duplicatePreviewView(candidate)",
    ]
    required_vulnerable = [
        "//go:build aml1_vulnerable",
        "aml1VulnerableProfileEnabled() bool",
        "return true",
        "private_notes",
        'json:"body"',
        "FindDuplicatePrivateNotesForPreview",
    ]
    missing = missing_markers(secure, required_secure) + missing_markers(vulnerable, required_vulnerable)
    return {
        "name": "wave14-aml1-profile-split",
        "path": f"{SECURE_PROFILE} {VULNERABLE_PROFILE}",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_targeted_repository_lookup(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, CASEWORK_REPOSITORY)
    section = source_section(text, "func (r *Repository) FindDuplicatePrivateNotesForPreview", "func (r *Repository) CreateNote")
    required = [
        "WHERE owner_user_id = $1 AND id = $2",
        "JOIN case_notes cn ON cn.case_id = c.id",
        "c.id = $1 AND c.dedup_hint = $2",
        "cn.visibility = 'private'",
        "cn.body",
    ]
    forbidden = ["edd_records", "confidential_comment", "audit_events", "password_hash", "token_hash", "sessions"]
    missing = missing_markers(section, required)
    present_forbidden = [marker for marker in forbidden if marker in section.lower()]
    return {
        "name": "wave14-aml1-targeted-note-lookup",
        "path": CASEWORK_REPOSITORY,
        "status": "pass" if section and not missing and not present_forbidden else "fail",
        "message": "" if section and not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def check_http_merge_preview_uses_profile(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, HTTP_SERVER)
    section = source_section(text, "func (s *Server) handleCaseDuplicateMergePreview", "func (s *Server) handleCaseNotes")
    required = [
        "FindDuplicateCandidatesByOwner",
        "candidate.CaseID == duplicateCaseID",
        "caseDuplicateMergePreviewResponse(ctx, user.ID, sourceCaseID, candidate)",
    ]
    forbidden = ["ListNotesByOwner", "confidential_comment", "debug", "admin"]
    missing = missing_markers(section, required)
    present_forbidden = [marker for marker in forbidden if marker in section]
    return {
        "name": "wave14-aml1-merge-preview-profile-hook",
        "path": HTTP_SERVER,
        "status": "pass" if section and not missing and not present_forbidden else "fail",
        "message": "" if section and not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def check_vulnerability_tests(repo_root: Path) -> dict[str, Any]:
    vulnerable = read(repo_root, VULNERABLE_TEST)
    secure = read(repo_root, SECURE_TEST)
    wave14 = read(repo_root, "tests/test_wave14_gate.py")
    required = [
        "//go:build aml1_vulnerable",
        "TestAML1VulnerableDedupMergePreviewExposesOnlyDuplicatePrivateNotes",
        "AML1_VICTIM_DUPLICATE_NOTE_BODY_LEAK",
        "assertDedupResponsePublicOnly",
        "confidential_comment",
        "source_of_funds",
        "risk_rationale",
        "private_state",
    ]
    missing = missing_markers(vulnerable, required)
    if "TestAntiAML1DedupMergePreviewDoesNotLeakCandidatePrivateData" not in secure:
        missing.append("secure anti-AML-1 regression test")
    if "aml1VulnerableProfileEnabled()" not in secure:
        missing.append("secure tests skip only under vulnerable profile")
    if "test_checker_unittest_discovery_returns_after_ok" not in wave14:
        missing.append("checker discovery subprocess liveness regression")
    return {
        "name": "wave14-aml1-vulnerable-and-secure-tests",
        "path": f"{VULNERABLE_TEST} {SECURE_TEST} tests/test_wave14_gate.py",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_no_reference_exploit_or_fix(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
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
        "name": "wave14-no-reference-exploit-or-fix",
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
        "name": "wave14-no-debug-admin-profile-toggle",
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
        "name": "wave14-no-aml2-through-aml5-activation",
        "path": "cmd internal checkers config.yml docker-compose.yml Makefile",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_makefile_wave14_gate(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, "Makefile")
    target = makefile_target_section(text, "wave14-gate")
    required = [
        'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        'python -B -m unittest discover -s tests -p "test_wave14_gate.py"',
        "$(GO_OFFLINE_ENV) go test ./...",
        "$(GO_OFFLINE_ENV) go test -tags aml1_vulnerable ./...",
        "$(GO_OFFLINE_ENV) go vet ./...",
        "python -B scripts/check_docs_tree.py",
        "python -B scripts/check_wave14_gate.py",
        "python -B scripts/check_competition_matrix_gate.py",
        "python -B scripts/validate_forcad_config.py",
    ]
    missing = missing_markers(target, required)
    return {
        "name": "wave14-make-target-runs-full-gate",
        "path": "Makefile",
        "status": "pass" if target and not missing else "fail",
        "message": "" if target and not missing else f"wave14-gate missing or incomplete: {missing}",
    }


def check_handoff_reports(repo_root: Path) -> dict[str, Any]:
    required_markers = [
        "Summary",
        "Tests Run",
        "CTF Invariants Checked",
        "Security Invariants Checked",
        "Ready for Orchestrator Review",
    ]
    findings: list[str] = []
    for relative in HANDOFF_REPORTS:
        text = read(repo_root, relative)
        if not text:
            findings.append(f"{relative}: missing")
            continue
        missing = [marker for marker in required_markers if marker not in text]
        if missing:
            findings.append(f"{relative}: missing markers {missing}")
    return {
        "name": "wave14-handoff-reports-present",
        "path": " ".join(HANDOFF_REPORTS),
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_docs(repo_root: Path) -> dict[str, Any]:
    docs = {
        "docs/09_vulnerability_matrix.md": read(repo_root, "docs/09_vulnerability_matrix.md"),
        "docs/06_visibility_and_projections.md": read(repo_root, "docs/06_visibility_and_projections.md"),
        "docs/12_testing_strategy.md": read(repo_root, "docs/12_testing_strategy.md"),
        "docs/15_risk_register.md": read(repo_root, "docs/15_risk_register.md"),
    }
    required = {
        "docs/09_vulnerability_matrix.md": ["AML-1", "aml1_vulnerable", "private_notes", "sploits/sentinel_aml/aml_dedup_preview.py", "Wave 19"],
        "docs/06_visibility_and_projections.md": ["AML-1", "aml1_vulnerable", "CaseNote.body", "EDDRecord.confidential_comment"],
        "docs/12_testing_strategy.md": ["Wave 14 AML-1", "make wave14-gate", "scripts/check_wave14_gate.py", "scripts/check_competition_matrix_gate.py", "aml1_vulnerable", "No reference exploit"],
        "docs/15_risk_register.md": ["AML-1 Dedup Preview Scope", "mitigated"],
    }
    missing: list[str] = []
    for path, markers in required.items():
        missing.extend(f"{path}: {marker}" for marker in markers if marker not in docs[path])
    return {
        "name": "wave14-aml1-docs",
        "path": "docs/09_vulnerability_matrix.md docs/06_visibility_and_projections.md docs/12_testing_strategy.md docs/15_risk_register.md",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
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
    result = validate_wave14_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
