#!/usr/bin/env python3
"""Validate Wave 18 AML-5 vulnerable network-room profile and guardrails."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


HTTP_SECURE_PROFILE = "internal/httpapi/network_room_profile_secure.go"
HTTP_VULNERABLE_PROFILE = "internal/httpapi/network_room_profile_aml5_vulnerable.go"
NETWORK_REPOSITORY = "internal/networkroom/repository.go"
NETWORK_VULNERABLE_DOSSIER = "internal/networkroom/dossier_profile_aml5_vulnerable.go"
NETWORK_VULNERABLE_READER = "internal/networkroom/repository_aml5_vulnerable.go"
SECURE_HTTP_TEST = "internal/httpapi/network_room_server_test.go"
VULNERABLE_HTTP_TEST = "internal/httpapi/aml5_vulnerable_network_room_test.go"
VULNERABLE_REPOSITORY_TEST = "internal/networkroom/repository_aml5_vulnerable_test.go"
HANDOFF_REPORT = "docs/wave_reports/wave_18_W18-T01_handoff.md"
F01_HANDOFF_REPORT = "docs/wave_reports/wave_18_W18-F01_handoff.md"
F02_HANDOFF_REPORT = "docs/wave_reports/wave_18_W18-F02_handoff.md"
DETERMINISTIC_TAGGED_RUNNER = "scripts/run_aml5_tagged_tests.py"
ARCHIVE_HYGIENE_SCRIPT = "scripts/check_archive_hygiene.py"
ARCHIVE_HYGIENE_TEST = "tests/test_archive_hygiene.py"
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
AML5_FORBIDDEN_EARLY_FILES = (
    "sploits/sentinel_aml/aml_network_room.py",
    "fixes/sentinel_aml/aml_network_room.patch",
    "fixes/sentinel_aml/aml_network_room.diff",
)


def validate_wave18_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_profile_split(repo_root),
        check_vulnerability_tests(repo_root),
        check_secure_default_tests(repo_root),
        check_no_reference_exploit_or_fix(repo_root),
        check_no_debug_admin_toggles(repo_root),
        check_deterministic_tagged_runner(repo_root),
        check_archive_hygiene_policy(repo_root),
        check_makefile_wave18_gate(repo_root),
        check_handoff_report(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_profile_split(repo_root: Path) -> dict[str, Any]:
    secure = read(repo_root, HTTP_SECURE_PROFILE)
    vulnerable = read(repo_root, HTTP_VULNERABLE_PROFILE)
    repository = read(repo_root, NETWORK_REPOSITORY)
    vulnerable_dossier = read(repo_root, NETWORK_VULNERABLE_DOSSIER)
    reader = read(repo_root, NETWORK_VULNERABLE_READER)
    required = [
        (secure, "//go:build !aml5_vulnerable"),
        (secure, "aml5VulnerableProfileEnabled() bool"),
        (secure, "return false"),
        (secure, "BuildSafeDossier"),
        (vulnerable, "//go:build aml5_vulnerable"),
        (vulnerable, "aml5VulnerableProfileEnabled() bool"),
        (vulnerable, "return true"),
        (vulnerable, "ListVulnerableDossierCases"),
        (vulnerable, "BuildVulnerableDossier"),
        (vulnerable, "foreign_private_notes"),
        (vulnerable, "foreign_edd_comments"),
        (vulnerable_dossier, "//go:build aml5_vulnerable"),
        (vulnerable_dossier, "type VulnerableDossier struct"),
        (vulnerable_dossier, "BuildVulnerableDossier"),
        (vulnerable_dossier, "foreign_source_case_private_data"),
        (vulnerable_dossier, "!summary.OwnedByRequester"),
        (reader, "//go:build aml5_vulnerable"),
        (reader, "JOIN network_room_participants owned"),
        (reader, "JOIN case_notes cn"),
        (reader, "cn.visibility = 'private'"),
        (reader, "JOIN edd_records er"),
        (reader, "er.confidential_comment"),
    ]
    forbidden = [
        "source_of_funds",
        "risk_rationale",
        "diff_json",
        "password_hash",
        "token_hash",
        "checker_private",
        "raw_db_row",
        "EnableDebugAdmin",
        "/api/debug",
        "/api/admin",
        "linked_private_notes",
        "private_notes[].body",
        "case_note.body",
    ]
    combined = "\n".join((vulnerable, vulnerable_dossier, reader))
    missing = [marker for text, marker in required if marker not in text]
    present_forbidden = [marker for marker in forbidden if marker in combined]
    return {
        "name": "wave18-aml5-profile-split",
        "path": f"{HTTP_SECURE_PROFILE} {HTTP_VULNERABLE_PROFILE} {NETWORK_REPOSITORY} {NETWORK_VULNERABLE_DOSSIER} {NETWORK_VULNERABLE_READER}",
        "status": "pass" if not missing and not present_forbidden else "fail",
        "message": "" if not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def check_vulnerability_tests(repo_root: Path) -> dict[str, Any]:
    http_test = read(repo_root, VULNERABLE_HTTP_TEST)
    repository_test = read(repo_root, VULNERABLE_REPOSITORY_TEST)
    required = [
        (http_test, "//go:build aml5_vulnerable"),
        (http_test, "TestAML5VulnerableNetworkRoomDossierLeaksOnlyForeignSourcePrivateDataAfterJoin"),
        (http_test, "AML5_FOREIGN_NOTE_LEAK_TARGET"),
        (http_test, "AML5_FOREIGN_EDD_LEAK_TARGET"),
        (http_test, "beforeJoin.Code != http.StatusNotFound"),
        (http_test, "outsiderDossier.Code != http.StatusNotFound"),
        (http_test, "assertAML5VulnerableDossierBounded"),
        (repository_test, "//go:build aml5_vulnerable"),
        (repository_test, "TestAML5VulnerableDossierLeaksOnlyForeignSourcePrivateData"),
        (repository_test, "TestAML5VulnerableRepositoryReaderUsesParticipantScopeAndBoundedPrivateJoins"),
        (repository_test, "AML5_FOREIGN_NOTE_LEAK_TARGET"),
        (repository_test, "AML5_FOREIGN_EDD_LEAK_TARGET"),
    ]
    missing = [marker for text, marker in required if marker not in text]
    return {
        "name": "wave18-aml5-vulnerable-tests",
        "path": f"{VULNERABLE_HTTP_TEST} {VULNERABLE_REPOSITORY_TEST}",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_secure_default_tests(repo_root: Path) -> dict[str, Any]:
    secure_test = read(repo_root, SECURE_HTTP_TEST)
    repository_test = read(repo_root, "internal/networkroom/repository_test.go")
    required = [
        (secure_test, "//go:build !aml5_vulnerable"),
        (secure_test, "TestNetworkRoomJoinListDetailAndDossier"),
        (secure_test, "assertNetworkResponsePublicOnly"),
        (secure_test, "private_data_omitted"),
        (repository_test, "TestBuildSafeDossierOmitsPrivateValues"),
        (repository_test, "FOREIGN_PRIVATE_NOTE_SENTINEL"),
        (repository_test, "FOREIGN_EDD_CONFIDENTIAL_SENTINEL"),
    ]
    missing = [marker for text, marker in required if marker not in text]
    return {
        "name": "wave18-secure-default-dossier-tests",
        "path": f"{SECURE_HTTP_TEST} internal/networkroom/repository_test.go",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_no_reference_exploit_or_fix(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    for relative in AML5_FORBIDDEN_EARLY_FILES:
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
        "name": "wave18-no-reference-exploit-or-fix",
        "path": f"{SPLOIT_DIR} {FIX_DIR}",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_no_debug_admin_toggles(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    for path in iter_scanned_files(repo_root):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        endpoint_hits = [endpoint for endpoint in FORBIDDEN_DEBUG_ADMIN_ENDPOINTS if endpoint in lowered]
        toggle_hit = FORBIDDEN_DEBUG_ADMIN_TOGGLE_RE.search(text)
        if endpoint_hits or toggle_hit:
            detail = ",".join(endpoint_hits) if endpoint_hits else toggle_hit.group(0)
            findings.append(f"{path.relative_to(repo_root).as_posix()}: {detail}")
    return {
        "name": "wave18-no-debug-admin-profile-toggle",
        "path": "cmd internal checkers config.yml docker-compose.yml Makefile",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_makefile_wave18_gate(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, "Makefile")
    target = makefile_target_section(text, "wave18-gate")
    required = [
        'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        'python -B -m unittest discover -s tests -p "test_wave18_gate.py"',
        'python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"',
        "$(GO_RELEASE_ENV) go test ./...",
        "$(GO_RELEASE_ENV) python -B scripts/run_aml5_tagged_tests.py",
        "$(GO_RELEASE_ENV) go vet ./...",
        "python -B scripts/check_docs_tree.py",
        "python -B scripts/check_wave18_gate.py",
        "python -B scripts/check_competition_matrix_gate.py",
        "python -B scripts/validate_forcad_config.py",
        "python -B scripts/check_archive_hygiene.py",
    ]
    forbidden = [
        "$(GO_OFFLINE_ENV) go test -p 1 -tags aml5_vulnerable ./...",
        "$(GO_OFFLINE_ENV) go test -tags aml5_vulnerable ./...",
        "$(GO_OFFLINE_ENV) go test ./...",
        "$(GO_OFFLINE_ENV) python -B scripts/run_aml5_tagged_tests.py",
        "$(GO_OFFLINE_ENV) go vet ./...",
    ]
    missing = missing_markers(target, required)
    present_forbidden = [marker for marker in forbidden if marker in target]
    return {
        "name": "wave18-make-target-runs-full-gate",
        "path": "Makefile",
        "status": "pass" if target and not missing and not present_forbidden else "fail",
        "message": "" if target and not missing and not present_forbidden else f"wave18-gate missing or incomplete: missing={missing} forbidden={present_forbidden}",
    }


def check_archive_hygiene_policy(repo_root: Path) -> dict[str, Any]:
    gitignore = read(repo_root, ".gitignore")
    script = read(repo_root, ARCHIVE_HYGIENE_SCRIPT)
    test = read(repo_root, ARCHIVE_HYGIENE_TEST)
    required = [
        (gitignore, ".gocache*/"),
        (gitignore, ".appdata*/"),
        (gitignore, "__pycache__/"),
        (gitignore, ".pytest_cache/"),
        (gitignore, ".idea/"),
        (gitignore, ".vscode/"),
        (gitignore, "*.tar.gz"),
        (script, "FORBIDDEN_DIR_PREFIXES"),
        (script, '".gocache"'),
        (script, '".appdata"'),
        (script, "FORBIDDEN_FILE_SUFFIX_CHAINS"),
        (script, '".tar.gz"'),
        (test, "test_current_repository_tree_passes"),
        (test, "test_forbidden_cache_directory_prefixes_fail"),
        (test, "test_local_coverage_and_archive_files_fail"),
    ]
    missing = [marker for text, marker in required if marker not in text]
    return {
        "name": "wave18-archive-hygiene-policy",
        "path": f".gitignore {ARCHIVE_HYGIENE_SCRIPT} {ARCHIVE_HYGIENE_TEST}",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_deterministic_tagged_runner(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, DETERMINISTIC_TAGGED_RUNNER)
    required = [
        'TAG = "aml5_vulnerable"',
        '"go",',
        '"list",',
        '"-tags",',
        'TAG,',
        '"./..."',
        '"test",',
        '"-count=1"',
        '"-timeout"',
        "run_package(command, args.process_timeout_seconds)",
        "subprocess.TimeoutExpired",
        "package command timed out",
    ]
    forbidden = [
        '"go", "test", "-p", "1", "-tags", TAG, "./..."',
        "go test -p 1 -tags aml5_vulnerable ./...",
    ]
    missing = missing_markers(text, required)
    present_forbidden = [marker for marker in forbidden if marker in text]
    return {
        "name": "wave18-deterministic-aml5-tagged-runner",
        "path": DETERMINISTIC_TAGGED_RUNNER,
        "status": "pass" if text and not missing and not present_forbidden else "fail",
        "message": "" if text and not missing and not present_forbidden else f"missing={missing} forbidden={present_forbidden}",
    }


def check_handoff_report(repo_root: Path) -> dict[str, Any]:
    texts = [read(repo_root, HANDOFF_REPORT), read(repo_root, F01_HANDOFF_REPORT), read(repo_root, F02_HANDOFF_REPORT)]
    required = [
        "Summary",
        "Implementation Details",
        "Tests Run",
        "CTF Invariants Checked",
        "Security Invariants Checked",
        "Ready for Orchestrator Review",
    ]
    missing = []
    for path, text in ((HANDOFF_REPORT, texts[0]), (F01_HANDOFF_REPORT, texts[1]), (F02_HANDOFF_REPORT, texts[2])):
        missing.extend(f"{path}: {marker}" for marker in missing_markers(text, required))
    return {
        "name": "wave18-handoffs-present",
        "path": f"{HANDOFF_REPORT} {F01_HANDOFF_REPORT} {F02_HANDOFF_REPORT}",
        "status": "pass" if all(texts) and not missing else "fail",
        "message": "" if all(texts) and not missing else f"missing markers: {missing}",
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


def makefile_target_section(text: str, target_name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target_name)}:\s*$", text)
    if not match:
        return ""
    start = match.start()
    next_target = re.search(r"(?m)^[A-Za-z0-9_.-]+:.*$", text[match.end() :])
    if not next_target:
        return text[start:]
    return text[start : match.end() + next_target.start()]


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "pass" if all(check["status"] == "pass" for check in checks) else "fail"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave18_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
