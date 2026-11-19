#!/usr/bin/env python3
"""Validate Wave 15 AML-2 vulnerable audit timeline profile and guardrails."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


SECURE_PROFILE = "internal/httpapi/audit_profile_secure.go"
VULNERABLE_PROFILE = "internal/httpapi/audit_profile_aml2_vulnerable.go"
HTTP_SERVER = "internal/httpapi/server.go"
VULNERABLE_TEST = "internal/httpapi/aml2_vulnerable_audit_test.go"
SECURE_TEST = "internal/httpapi/audit_timeline_test.go"
VISIBILITY_TEST = "internal/httpapi/visibility_leak_test.go"
WAVE15_GATE_TEST = "tests/test_wave15_gate.py"
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
    "aml3_vulnerable",
    "aml4_vulnerable",
    "aml5_vulnerable",
    "aml_3",
    "aml_4",
    "aml_5",
    "AML-3",
    "AML-4",
    "AML-5",
)
AML2_FORBIDDEN_EARLY_FILES = (
    "sploits/sentinel_aml/aml_audit_timeline.py",
    "fixes/sentinel_aml/aml_audit_timeline.patch",
    "fixes/sentinel_aml/aml_audit_timeline.diff",
)


def validate_wave15_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_profile_split(repo_root),
        check_timeline_uses_profile(repo_root),
        check_vulnerability_tests(repo_root),
        check_no_reference_exploit_or_fix(repo_root),
        check_no_debug_admin_toggles(repo_root),
        check_no_future_aml_activation(repo_root),
        check_makefile_wave15_gate(repo_root),
        check_docs(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_profile_split(repo_root: Path) -> dict[str, Any]:
    secure = read(repo_root, SECURE_PROFILE)
    vulnerable = read(repo_root, VULNERABLE_PROFILE)
    required_secure = [
        "//go:build !aml2_vulnerable",
        "aml2VulnerableProfileEnabled() bool",
        "return false",
        "caseAuditViews(events)",
    ]
    required_vulnerable = [
        "//go:build aml2_vulnerable",
        "aml2VulnerableProfileEnabled() bool",
        "return true",
        "ListNotesByOwner",
        "case_note.body",
        "isAML2CaseNoteBodyField",
    ]
    forbidden_vulnerable = [
        "confidential_comment",
        "source_of_funds",
        "risk_rationale",
        "graph",
        "export",
        "network",
    ]
    missing = missing_markers(secure, required_secure) + missing_markers(vulnerable, required_vulnerable)
    forbidden = [marker for marker in forbidden_vulnerable if marker in vulnerable]
    return {
        "name": "wave15-aml2-profile-split",
        "path": f"{SECURE_PROFILE} {VULNERABLE_PROFILE}",
        "status": "pass" if not missing and not forbidden else "fail",
        "message": "" if not missing and not forbidden else f"missing={missing} forbidden={forbidden}",
    }


def check_timeline_uses_profile(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, HTTP_SERVER)
    section = source_section(text, "func (s *Server) handleCaseTimeline", "func (s *Server) handleCaseDuplicateCandidates")
    required = [
        "GetByOwner(ctx, user.ID, caseID)",
        "ListCaseTimelineByOwner(ctx, user.ID, caseID)",
        "caseAuditViewsForProfile(ctx, user.ID, caseID, events)",
    ]
    forbidden = ["ListNotesByOwner", "confidential_comment", "/api/debug", "/api/admin"]
    missing = missing_markers(section, required)
    present_forbidden = [marker for marker in forbidden if marker in section]
    return {
        "name": "wave15-audit-timeline-profile-hook",
        "path": HTTP_SERVER,
        "status": "pass" if section and not missing and not present_forbidden else "fail",
        "message": "" if section and not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def check_vulnerability_tests(repo_root: Path) -> dict[str, Any]:
    vulnerable = read(repo_root, VULNERABLE_TEST)
    secure = read(repo_root, SECURE_TEST)
    visibility = read(repo_root, VISIBILITY_TEST)
    gate_test = read(repo_root, WAVE15_GATE_TEST)
    required = [
        "//go:build aml2_vulnerable",
        "TestAML2VulnerableAuditTimelineExposesOnlyCaseNoteBody",
        "AML2_CASE_NOTE_BODY_LEAK_TARGET",
        "assertAML2TimelineLeakIsBounded",
        "assertExportResponsePublicOnly",
        "assertNetworkResponsePublicOnly",
        "TestAML2VulnerableProfileDoesNotBroadenGraphSideViews",
        "assertGraphResponsePublicOnly",
    ]
    missing = missing_markers(vulnerable, required)
    if "TestAntiAML2AuditTimelineDoesNotExposePrivateStores" not in secure:
        missing.append("secure anti-AML-2 regression test")
    if "aml2VulnerableProfileEnabled()" not in secure or "secure-profile-only anti-AML-2 projection test" not in secure:
        missing.append("secure audit tests skip only under AML-2 profile")
    if "aml2VulnerableProfileEnabled()" not in visibility:
        missing.append("secure visibility tests skip only under AML-2 profile")
    if "test_checker_unittest_discovery_returns_after_ok" not in gate_test:
        missing.append("checker unittest discovery subprocess liveness regression")
    return {
        "name": "wave15-aml2-vulnerable-and-secure-tests",
        "path": f"{VULNERABLE_TEST} {SECURE_TEST} {VISIBILITY_TEST} {WAVE15_GATE_TEST}",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_no_reference_exploit_or_fix(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    for relative in AML2_FORBIDDEN_EARLY_FILES:
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
        "name": "wave15-no-reference-exploit-or-fix",
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
        "name": "wave15-no-debug-admin-profile-toggle",
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
        "name": "wave15-no-aml3-through-aml5-activation",
        "path": "cmd internal checkers config.yml docker-compose.yml Makefile",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_makefile_wave15_gate(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, "Makefile")
    target = makefile_target_section(text, "wave15-gate")
    required = [
        'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        'python -B -m unittest discover -s tests -p "test_wave15_gate.py"',
        "$(GO_OFFLINE_ENV) go test ./...",
        "$(GO_OFFLINE_ENV) go test -tags aml2_vulnerable ./...",
        "$(GO_OFFLINE_ENV) go vet ./...",
        "python -B scripts/check_docs_tree.py",
        "python -B scripts/check_wave15_gate.py",
        "python -B scripts/check_competition_matrix_gate.py",
        "python -B scripts/validate_forcad_config.py",
    ]
    missing = missing_markers(target, required)
    return {
        "name": "wave15-make-target-runs-full-gate",
        "path": "Makefile",
        "status": "pass" if target and not missing else "fail",
        "message": "" if target and not missing else f"wave15-gate missing or incomplete: {missing}",
    }


def check_docs(repo_root: Path) -> dict[str, Any]:
    required = {
        "docs/09_vulnerability_matrix.md": ["AML-2", "aml2_vulnerable", "case_note.body", "sploits/sentinel_aml/aml_audit_timeline.py", "Wave 20"],
        "docs/06_visibility_and_projections.md": ["AML-2", "aml2_vulnerable", "CaseNote.body", "audit timeline"],
        "docs/audit_export_graph_invariants.md": ["Wave 15 AML-2", "aml2_vulnerable", "CaseNote.body", "EDDRecord.confidential_comment"],
        "docs/12_testing_strategy.md": ["Wave 15 AML-2", "make wave15-gate", "scripts/check_wave15_gate.py", "aml2_vulnerable", "No reference exploit"],
        "docs/15_risk_register.md": ["AML-2 Audit Timeline Scope", "open"],
    }
    missing: list[str] = []
    for path, markers in required.items():
        text = read(repo_root, path)
        missing.extend(f"{path}: {marker}" for marker in markers if marker not in text)
    return {
        "name": "wave15-aml2-docs",
        "path": " ".join(required),
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
    result = validate_wave15_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
