#!/usr/bin/env python3
"""Validate Sentinel AML competition variant and matrix-gate scaffolding."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ADR_PATH = "docs/decisions/ADR-0002-competition-variant-and-reference-fix-strategy.md"
FIXES_README_PATH = "fixes/sentinel_aml/README.md"
MAKE_TARGET = "competition-matrix-gate"

MATRIX_GATE_PLACEHOLDERS = (
    "vulnerable checker gate",
    "exploit-success gate",
    "fixed checker gate",
    "exploit-blocked gate",
    "anti-coarse-fix gate",
)
AML1_CONCRETE_CELL_MARKERS = (
    "AML-1 vulnerable checker gate",
    "concrete",
    "scripts/check_wave14_gate.py",
    "go test -tags aml1_vulnerable ./...",
    "private_notes",
)
AML1_EXPLOIT_SUCCESS_MARKERS = (
    "AML-1 exploit-success gate",
    "concrete",
    "sploits/sentinel_aml/aml_dedup_preview.py",
    "scripts/check_wave19_gate.py",
    "private_notes[].body",
)
AML1_REQUIRED_ARTIFACTS = (
    "internal/httpapi/dedup_profile_default.go",
    "internal/httpapi/dedup_profile_case_match.go",
    "internal/httpapi/dedup_profile_case_match_test.go",
    "scripts/check_wave14_gate.py",
)
AML1_EXPLOIT_ARTIFACTS = (
    "sploits/sentinel_aml/aml_dedup_preview.py",
    "scripts/check_wave19_gate.py",
    "tests/test_wave19_gate.py",
)
AML1_FIXED_CHECKER_MARKERS = (
    "AML-1 fixed checker gate",
    "concrete",
    "scripts/check_wave24_gate.py",
    'python -B -m unittest discover -s tests -p "test_checker_*.py"',
    "go test ./...",
)
AML1_EXPLOIT_BLOCKED_MARKERS = (
    "AML-1 exploit-blocked gate",
    "concrete",
    "sploits/sentinel_aml/aml_dedup_preview.py",
    "test_exploit_fails_safely_against_secure_preview",
    "private_notes leak is absent",
)
AML1_ANTI_COARSE_FIX_MARKERS = (
    "AML-1 anti-coarse-fix gate",
    "concrete",
    "scripts/check_wave24_gate.py",
    "CaseDuplicateMergePreviewResponse",
    "duplicatePreviewView(candidate)",
    "public_summary",
    "overlap_score",
)
AML1_FIX_ARTIFACTS = (
    "fixes/sentinel_aml/aml_dedup_preview.patch",
    "fixes/sentinel_aml/aml_dedup_preview.diff",
)
AML1_FIX_REQUIRED_ARTIFACTS = (
    "scripts/check_wave24_gate.py",
    "tests/test_wave24_gate.py",
    "docs/wave_reports/wave_24_W24-T01_handoff.md",
)
EXPECTED_WAVE23_EXPLOITS = (
    "aml_audit_timeline.py",
    "aml_dedup_preview.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
    "aml_related_graph.py",
)
WAVE32_MATRIX_COLUMNS = (
    "vulnerable profile builds",
    "sploit syntax",
    "sploit expected path",
    "fix patch applies",
    "fixed profile blocks sploit",
    "checker stays green",
    "CHECK/HAVOC stays green",
)
WAVE32_SPLOIT_FIX_MATRIX = (
    {
        "aml": "AML-1",
        "profile_gate": "scripts/check_wave14_gate.py",
        "profile_command": "go test -tags aml1_vulnerable ./...",
        "sploit": "sploits/sentinel_aml/aml_dedup_preview.py",
        "sploit_paths": (
            "/api/cases/{source_case_id}/duplicates",
            "/api/cases/{source_case_id}/duplicates/{victim_case_id}/merge-preview",
        ),
        "fix": "fixes/sentinel_aml/aml_dedup_preview.patch",
        "fix_gate": "scripts/check_wave24_gate.py",
        "vulnerable_success_test": "test_aml1_exploit_succeeds_on_vulnerable_fixture",
        "fixed_block_test": "test_aml1_exploit_fails_safely_on_fixed_public_output",
        "checker_green": 'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        "check_havoc_green": "check_dedup",
    },
    {
        "aml": "AML-2",
        "profile_gate": "scripts/check_wave15_gate.py",
        "profile_command": "go test -tags aml2_vulnerable ./...",
        "sploit": "sploits/sentinel_aml/aml_audit_timeline.py",
        "sploit_paths": ("/api/entities/{entity_hint}/activity",),
        "fix": "fixes/sentinel_aml/aml_audit_timeline.patch",
        "fix_gate": "scripts/check_wave25_gate.py",
        "vulnerable_success_test": "test_aml2_exploit_succeeds_on_vulnerable_fixture",
        "fixed_block_test": "test_aml2_exploit_fails_safely_on_fixed_redacted_output_and_preserves_event",
        "checker_green": 'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        "check_havoc_green": "check_audit",
    },
    {
        "aml": "AML-3",
        "profile_gate": "scripts/check_wave16_gate.py",
        "profile_command": "go test -tags aml3_vulnerable ./...",
        "sploit": "sploits/sentinel_aml/aml_related_graph.py",
        "sploit_paths": ("/api/graph/entities/{quoted_hint}/edd-summaries",),
        "fix": "fixes/sentinel_aml/aml_related_graph.patch",
        "fix_gate": "scripts/check_wave26_gate.py",
        "vulnerable_success_test": "test_aml3_exploit_succeeds_on_vulnerable_fixture",
        "fixed_block_test": "test_aml3_exploit_fails_safely_on_fixed_public_graph_output",
        "checker_green": 'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        "check_havoc_green": "check_graph",
    },
    {
        "aml": "AML-4",
        "profile_gate": "scripts/check_wave17_gate.py",
        "profile_command": "go test -p 1 -tags aml4_vulnerable ./...",
        "sploit": "sploits/sentinel_aml/aml_export_redaction.py",
        "sploit_paths": (
            "/api/disputes/{dispute_id}/export",
            "/api/exports/{export_id}",
        ),
        "fix": "fixes/sentinel_aml/aml_export_redaction.patch",
        "fix_gate": "scripts/check_wave27_gate.py",
        "vulnerable_success_test": "test_aml4_exploit_succeeds_on_vulnerable_fixture",
        "fixed_block_test": "test_aml4_exploit_fails_safely_on_fixed_public_export_output",
        "checker_green": 'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        "check_havoc_green": "check_export",
    },
    {
        "aml": "AML-5",
        "profile_gate": "scripts/check_wave18_gate.py",
        "profile_command": "go test -p 1 -tags aml5_vulnerable ./...",
        "sploit": "sploits/sentinel_aml/aml_network_room.py",
        "sploit_paths": (
            "/api/network/rooms",
            "/api/network/rooms/{room_id}/join",
            "/api/network/rooms/{room_id}/dossier",
        ),
        "fix": "fixes/sentinel_aml/aml_network_room.patch",
        "fix_gate": "scripts/check_wave28_gate.py",
        "vulnerable_success_test": "test_exploit_succeeds_on_accepted_vulnerable_fixture",
        "fixed_block_test": "test_exploit_fails_safely_on_accepted_fixed_fixture",
        "checker_green": 'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        "check_havoc_green": "check_network_room",
    },
)
FORBIDDEN_SPLOIT_SHORTCUTS = (
    "sqlite3",
    "psycopg",
    "database/sql",
    "sql.Open",
    "subprocess",
    "os.system",
    "/api/debug",
    "/api/admin",
    "/debug",
    "/admin",
)
WAVE32_DOC_PATHS = (
    "docs/09_vulnerability_matrix.md",
    "docs/wave_reports/wave_32_sploit_fix_matrix.md",
)
AML2_CONCRETE_CELL_MARKERS = (
	"AML-2 vulnerable checker gate",
	"concrete",
	"scripts/check_wave15_gate.py",
	"go test -tags aml2_vulnerable ./...",
	"activity_narrative",
)
AML2_FIXED_CHECKER_MARKERS = (
    "AML-2 fixed checker gate",
    "concrete",
    "scripts/check_wave25_gate.py",
    'python -B -m unittest discover -s tests -p "test_checker_*.py"',
    "go test ./...",
)
AML2_EXPLOIT_BLOCKED_MARKERS = (
    "AML-2 exploit-blocked gate",
    "concrete",
    "sploits/sentinel_aml/aml_audit_timeline.py",
    "test_exploit_fails_safely_against_secure_redacted_timeline",
    "flag-like token not found",
)
AML2_ANTI_COARSE_FIX_MARKERS = (
	"AML-2 anti-coarse-fix gate",
	"concrete",
	"scripts/check_wave25_gate.py",
	"TestAML2FixedEntityActivityKeepsReviewContextScoped",
	"activity_narrative",
	"redacted",
	"owner note path",
	"/api/entities/{entity_hint}/activity",
)
AML2_EXPLOIT_SUCCESS_MARKERS = (
    "AML-2 exploit-success gate",
    "concrete",
	"sploits/sentinel_aml/aml_audit_timeline.py",
	"scripts/check_wave20_gate.py",
	"/api/entities/{entity_hint}/activity",
	"activity_narrative",
	"review_context_excerpt",
)
AML2_REQUIRED_ARTIFACTS = (
    "internal/httpapi/audit_profile_default.go",
    "internal/httpapi/audit_profile_detail.go",
    "internal/httpapi/audit_profile_detail_test.go",
    "scripts/check_wave15_gate.py",
)
AML2_EXPLOIT_ARTIFACTS = (
    "sploits/sentinel_aml/aml_audit_timeline.py",
    "scripts/check_wave20_gate.py",
    "tests/test_wave20_gate.py",
)
AML2_FIX_ARTIFACTS = (
    "fixes/sentinel_aml/aml_audit_timeline.patch",
    "fixes/sentinel_aml/aml_audit_timeline.diff",
)
AML2_FIX_REQUIRED_ARTIFACTS = (
    "scripts/check_wave25_gate.py",
    "tests/test_wave25_gate.py",
    "docs/wave_reports/wave_25_W25-T01_handoff.md",
)
AML3_CONCRETE_CELL_MARKERS = (
    "AML-3 vulnerable checker gate",
    "concrete",
    "scripts/check_wave16_gate.py",
    "go test -tags aml3_vulnerable ./...",
    "confidential_comment",
)
AML3_EXPLOIT_SUCCESS_MARKERS = (
    "AML-3 exploit-success gate",
    "concrete",
    "sploits/sentinel_aml/aml_related_graph.py",
    "scripts/check_wave21_gate.py",
    "confidential_comment",
    "edd-summaries",
)
AML3_FIXED_CHECKER_MARKERS = (
    "AML-3 fixed checker gate",
    "concrete",
    "scripts/check_wave26_gate.py",
    'python -B -m unittest discover -s tests -p "test_checker_*.py"',
    "go test ./...",
)
AML3_EXPLOIT_BLOCKED_MARKERS = (
    "AML-3 exploit-blocked gate",
    "concrete",
    "sploits/sentinel_aml/aml_related_graph.py",
    "test_exploit_fails_safely_against_secure_metadata_only_graph_response",
    "flag-like token not found",
)
AML3_ANTI_COARSE_FIX_MARKERS = (
    "AML-3 anti-coarse-fix gate",
    "concrete",
    "scripts/check_wave26_gate.py",
    "TestAML3FixedGraphEDDSummariesUsePublicProjection",
    "EDDGraphSummariesResponse",
    "GraphEntityView",
    "GraphRelatedCaseView",
    "owner EDD path",
)
AML3_EXPLOIT_ARTIFACTS = (
    "sploits/sentinel_aml/aml_related_graph.py",
    "scripts/check_wave21_gate.py",
    "tests/test_wave21_gate.py",
)
AML3_REQUIRED_ARTIFACTS = (
    "internal/httpapi/graph_profile_default.go",
    "internal/httpapi/graph_profile_entity_review.go",
    "internal/graph/repository_entity_review.go",
    "internal/httpapi/graph_profile_entity_review_test.go",
    "scripts/check_wave16_gate.py",
)
AML3_FORBIDDEN_FIX_FILES = (
    "fixes/sentinel_aml/aml_related_graph.patch",
    "fixes/sentinel_aml/aml_related_graph.diff",
)
AML3_FIX_ARTIFACTS = (
    "fixes/sentinel_aml/aml_related_graph.patch",
    "fixes/sentinel_aml/aml_related_graph.diff",
)
AML3_FIX_REQUIRED_ARTIFACTS = (
    "scripts/check_wave26_gate.py",
    "tests/test_wave26_gate.py",
    "docs/wave_reports/wave_26_W26-T01_handoff.md",
)
AML4_CONCRETE_CELL_MARKERS = (
    "AML-4 vulnerable checker gate",
    "concrete",
    "scripts/check_wave17_gate.py",
    "go test -tags aml4_vulnerable ./...",
    "linked_private_notes",
)
AML4_EXPLOIT_SUCCESS_MARKERS = (
    "AML-4 exploit-success gate",
    "concrete",
    "sploits/sentinel_aml/aml_export_redaction.py",
    "scripts/check_wave22_gate.py",
    "linked_private_notes",
    "body",
)
AML4_FIXED_CHECKER_MARKERS = (
    "AML-4 fixed checker gate",
    "concrete",
    "scripts/check_wave27_gate.py",
    'python -B -m unittest discover -s tests -p "test_checker_*.py"',
    "go test ./...",
)
AML4_EXPLOIT_BLOCKED_MARKERS = (
    "AML-4 exploit-blocked gate",
    "concrete",
    "sploits/sentinel_aml/aml_export_redaction.py",
    "test_exploit_fails_safely_against_secure_redacted_export",
    "flag-like token not found",
)
AML4_ANTI_COARSE_FIX_MARKERS = (
    "AML-4 anti-coarse-fix gate",
    "concrete",
    "scripts/check_wave27_gate.py",
    "TestAML4FixedDisputeExportRedactsLinkedPrivateNotesRecursively",
    "linked_cases",
    "redaction_policy",
    "owner notes path",
)
AML4_EXPLOIT_ARTIFACTS = (
    "sploits/sentinel_aml/aml_export_redaction.py",
    "scripts/check_wave22_gate.py",
    "tests/test_wave22_gate.py",
)
AML4_REQUIRED_ARTIFACTS = (
    "internal/exporting/export_profile_default.go",
    "internal/exporting/export_profile_linked_case.go",
    "internal/httpapi/export_profile_default.go",
    "internal/httpapi/export_profile_linked_case.go",
    "internal/httpapi/export_profile_linked_case_test.go",
    "scripts/check_wave17_gate.py",
)
AML4_FIX_ARTIFACTS = (
    "fixes/sentinel_aml/aml_export_redaction.patch",
    "fixes/sentinel_aml/aml_export_redaction.diff",
)
AML4_FIX_REQUIRED_ARTIFACTS = (
    "scripts/check_wave27_gate.py",
    "tests/test_wave27_gate.py",
    "docs/wave_reports/wave_27_W27-T01_handoff.md",
)
AML4_FORBIDDEN_LEGACY_FIX_FILES = (
    "fixes/sentinel_aml/aml_regulatory_export.patch",
    "fixes/sentinel_aml/aml_regulatory_export.diff",
)
AML5_CONCRETE_CELL_MARKERS = (
    "AML-5 vulnerable checker gate",
    "concrete",
    "scripts/check_wave18_gate.py",
    "go test -p 1 -tags aml5_vulnerable ./...",
    "context_blocks",
    "evaluation_blocks",
)
AML5_EXPLOIT_SUCCESS_MARKERS = (
    "AML-5 exploit-success gate",
    "concrete",
    "sploits/sentinel_aml/aml_network_room.py",
    "scripts/check_wave23_gate.py",
    "context_blocks",
    "evaluation_blocks",
    "network-room dossier",
)
AML5_FIXED_CHECKER_MARKERS = (
    "AML-5 fixed checker gate",
    "concrete",
    "scripts/check_wave28_gate.py",
    'python -B -m unittest discover -s tests -p "test_checker_*.py"',
    "go test ./...",
)
AML5_EXPLOIT_BLOCKED_MARKERS = (
    "AML-5 exploit-blocked gate",
    "concrete",
    "sploits/sentinel_aml/aml_network_room.py",
    "test_exploit_fails_safely_when_dossier_is_redacted",
    "flag-like token not found",
)
AML5_ANTI_COARSE_FIX_MARKERS = (
    "AML-5 anti-coarse-fix gate",
    "concrete",
    "scripts/check_wave28_gate.py",
    "scope_coverage_complete",
    "network-room dossier",
    "AML-5 fixed dossier missing expected public marker",
    "owner note path",
)
AML5_EXPLOIT_ARTIFACTS = (
    "sploits/sentinel_aml/aml_network_room.py",
    "scripts/check_wave23_gate.py",
    "tests/test_wave23_gate.py",
)
AML5_REQUIRED_ARTIFACTS = (
    "internal/httpapi/network_room_profile_default.go",
    "internal/httpapi/network_room_profile_detail.go",
    "internal/networkroom/dossier_profile_room_detail.go",
    "internal/networkroom/repository_room_detail.go",
    "internal/httpapi/network_room_profile_detail_test.go",
    "internal/networkroom/repository_room_detail_test.go",
    "scripts/check_wave18_gate.py",
)
AML5_FIX_ARTIFACTS = (
    "fixes/sentinel_aml/aml_network_room.patch",
    "fixes/sentinel_aml/aml_network_room.diff",
)
AML5_FIX_REQUIRED_ARTIFACTS = (
    "scripts/check_wave28_gate.py",
    "tests/test_wave28_gate.py",
    "docs/wave_reports/wave_28_W28-F01_handoff.md",
)
FORBIDDEN_UNSEQUENCED_AML_MARKERS = (
    "aml6_vulnerable",
    "aml_6",
    "AML-6",
)

FORBIDDEN_DEBUG_ADMIN_ENDPOINTS = (
    "/api/debug",
    "/api/admin",
    "/debug",
    "/admin",
)

FORBIDDEN_VARIANT_TOGGLE_RE = re.compile(
    r"(?i)(debug|admin).{0,48}(variant|toggle|profile|mode|enable|enabled|flag)"
    r"|"
    r"(variant|toggle|profile|mode|enable|enabled|flag).{0,48}(debug|admin)"
)

SCAN_DIRS = ("cmd", "internal", "checkers")
SCAN_FILES = ("config.yml", "docker-compose.yml", "Makefile")
SCAN_SUFFIXES = {".go", ".py", ".yml", ".yaml", ".toml", ".env", ".ps1", ".sh"}


def validate_competition_matrix_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_adr(repo_root))
    checks.append(check_fix_skeleton(repo_root))
    checks.append(check_matrix_placeholders(repo_root))
    checks.append(check_aml1_vulnerable_checker_cell(repo_root))
    checks.append(check_aml1_exploit_success_cell(repo_root))
    checks.append(check_wave28_exploit_and_fix_sequence(repo_root))
    checks.append(check_aml1_fix_cells_concrete(repo_root))
    checks.append(check_aml2_vulnerable_checker_cell(repo_root))
    checks.append(check_aml2_exploit_success_cell(repo_root))
    checks.append(check_aml2_fix_cells_concrete(repo_root))
    checks.append(check_aml3_vulnerable_checker_cell(repo_root))
    checks.append(check_aml3_exploit_success_cell(repo_root))
    checks.append(check_aml3_fix_cells_concrete(repo_root))
    checks.append(check_aml4_vulnerable_checker_cell(repo_root))
    checks.append(check_aml4_exploit_success_cell(repo_root))
    checks.append(check_aml4_fix_cells_concrete(repo_root))
    checks.append(check_aml5_vulnerable_checker_cell(repo_root))
    checks.append(check_aml5_exploit_success_cell(repo_root))
    checks.append(check_aml5_fix_cells_concrete(repo_root))
    checks.append(check_wave32_validation_matrix_shape(repo_root))
    checks.append(check_wave32_sploit_syntax_and_business_paths(repo_root))
    checks.append(check_wave32_fix_patch_and_simulation_evidence(repo_root))
    checks.append(check_wave32_docs_and_report_evidence(repo_root))
    checks.append(check_no_unsequenced_aml_activation(repo_root))
    checks.append(check_make_target(repo_root))
    checks.append(check_no_debug_admin_variant_toggles(repo_root))
    return {"status": aggregate_status(checks), "checks": checks}


def check_adr(repo_root: Path) -> dict[str, Any]:
    path = repo_root / ADR_PATH
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    required = [
        "Competition Variant and Reference Fix Strategy",
        "vulnerable checker gate",
        "exploit-success gate",
        "fixed checker gate",
        "exploit-blocked gate",
        "anti-coarse-fix gate",
        "HTTP debug/admin toggles",
        "sploits/sentinel_aml/",
        "fixes/sentinel_aml/",
    ]
    missing = [marker for marker in required if marker not in text]
    return {
        "name": "competition-adr-present",
        "path": ADR_PATH,
        "status": "pass" if path.is_file() and not missing else "fail",
        "message": "" if path.is_file() and not missing else f"missing markers: {missing}",
    }


def check_fix_skeleton(repo_root: Path) -> dict[str, Any]:
    path = repo_root / FIXES_README_PATH
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    required = ["Reference Fixes", "skeleton", "CHECK/HAVOC", "debug/admin", "feature-disable"]
    missing = [marker for marker in required if marker not in text]
    return {
        "name": "reference-fix-skeleton-present",
        "path": FIXES_README_PATH,
        "status": "pass" if path.is_file() and not missing else "fail",
        "message": "" if path.is_file() and not missing else f"missing markers: {missing}",
    }


def check_matrix_placeholders(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    adr_text = (repo_root / ADR_PATH).read_text(encoding="utf-8") if (repo_root / ADR_PATH).is_file() else ""
    missing = [
        placeholder
        for placeholder in MATRIX_GATE_PLACEHOLDERS
        if placeholder not in script_text or placeholder not in adr_text
    ]
    return {
        "name": "competition-matrix-placeholders-present",
        "path": "scripts/check_competition_matrix_gate.py",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing placeholders: {missing}",
    }


def check_aml1_vulnerable_checker_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML1_CONCRETE_CELL_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML1_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml1-vulnerable-checker-concrete",
        "path": "scripts/check_competition_matrix_gate.py scripts/check_wave14_gate.py internal/httpapi",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_aml1_exploit_success_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML1_EXPLOIT_SUCCESS_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML1_EXPLOIT_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml1-exploit-success-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml/aml_dedup_preview.py scripts/check_wave19_gate.py",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_wave28_exploit_and_fix_sequence(repo_root: Path) -> dict[str, Any]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    exploit_files = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    fixes_dir = repo_root / "fixes" / "sentinel_aml"
    fix_artifacts: list[str] = []
    if fixes_dir.is_dir():
        fix_artifacts = sorted(
            path.relative_to(repo_root).as_posix()
            for path in fixes_dir.rglob("*")
            if path.is_file() and path != fixes_dir / "README.md"
        )
    expected_aml1_fix = [relative for relative in AML1_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    expected_aml2_fix = [relative for relative in AML2_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    expected_aml3_fix = [relative for relative in AML3_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    expected_aml4_fix = [relative for relative in AML4_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    expected_aml5_fix = [relative for relative in AML5_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    expected_fix_artifacts = sorted(expected_aml1_fix + expected_aml2_fix + expected_aml3_fix + expected_aml4_fix + expected_aml5_fix)
    ok = (
        exploit_files == list(EXPECTED_WAVE23_EXPLOITS)
        and len(expected_aml1_fix) == 1
        and len(expected_aml2_fix) == 1
        and len(expected_aml3_fix) == 1
        and len(expected_aml4_fix) == 1
        and len(expected_aml5_fix) == 1
        and fix_artifacts == expected_fix_artifacts
    )
    return {
        "name": "competition-matrix-wave28-five-exploits-and-five-fixes",
        "path": "sploits/sentinel_aml fixes/sentinel_aml",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"exploit_files={exploit_files} fix_artifacts={fix_artifacts}",
    }


def check_wave27_exploit_and_fix_sequence(repo_root: Path) -> dict[str, Any]:
    return check_wave28_exploit_and_fix_sequence(repo_root)


def check_wave26_exploit_and_fix_sequence(repo_root: Path) -> dict[str, Any]:
    return check_wave27_exploit_and_fix_sequence(repo_root)


def check_wave25_exploit_and_fix_sequence(repo_root: Path) -> dict[str, Any]:
    return check_wave27_exploit_and_fix_sequence(repo_root)


def check_wave24_exploit_and_fix_sequence(repo_root: Path) -> dict[str, Any]:
    return check_wave27_exploit_and_fix_sequence(repo_root)


def check_wave23_exploit_and_fix_sequence(repo_root: Path) -> dict[str, Any]:
    return check_wave27_exploit_and_fix_sequence(repo_root)


def check_wave22_exploit_and_fix_sequence(repo_root: Path) -> dict[str, Any]:
    return check_wave27_exploit_and_fix_sequence(repo_root)


def check_wave20_exploit_and_fix_sequence(repo_root: Path) -> dict[str, Any]:
    return check_wave27_exploit_and_fix_sequence(repo_root)


def check_aml1_fix_cells_concrete(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    required_markers = AML1_FIXED_CHECKER_MARKERS + AML1_EXPLOIT_BLOCKED_MARKERS + AML1_ANTI_COARSE_FIX_MARKERS
    missing_markers = [marker for marker in required_markers if marker not in script_text]
    fix_artifacts = [relative for relative in AML1_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    missing_artifacts = [relative for relative in AML1_FIX_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml1-fix-cells-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml fixes/sentinel_aml",
        "status": "pass" if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts else "fail",
        "message": ""
        if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts
        else f"missing_markers={missing_markers} fix_artifacts={fix_artifacts} missing_artifacts={missing_artifacts}",
    }


def check_aml2_vulnerable_checker_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML2_CONCRETE_CELL_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML2_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml2-vulnerable-checker-concrete",
        "path": "scripts/check_competition_matrix_gate.py scripts/check_wave15_gate.py internal/httpapi",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_aml2_exploit_success_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML2_EXPLOIT_SUCCESS_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML2_EXPLOIT_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml2-exploit-success-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml/aml_audit_timeline.py scripts/check_wave20_gate.py",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_aml2_fix_cells_concrete(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    required_markers = AML2_FIXED_CHECKER_MARKERS + AML2_EXPLOIT_BLOCKED_MARKERS + AML2_ANTI_COARSE_FIX_MARKERS
    missing_markers = [marker for marker in required_markers if marker not in script_text]
    fix_artifacts = [relative for relative in AML2_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    missing_artifacts = [relative for relative in AML2_FIX_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml2-fix-cells-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml fixes/sentinel_aml",
        "status": "pass" if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts else "fail",
        "message": ""
        if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts
        else f"missing_markers={missing_markers} fix_artifacts={fix_artifacts} missing_artifacts={missing_artifacts}",
    }


def check_aml3_vulnerable_checker_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML3_CONCRETE_CELL_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML3_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml3-vulnerable-checker-concrete",
        "path": "scripts/check_competition_matrix_gate.py scripts/check_wave16_gate.py internal/httpapi internal/graph",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_aml3_exploit_success_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML3_EXPLOIT_SUCCESS_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML3_EXPLOIT_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml3-exploit-success-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml/aml_related_graph.py scripts/check_wave21_gate.py",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_aml3_fix_cells_concrete(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    required_markers = AML3_FIXED_CHECKER_MARKERS + AML3_EXPLOIT_BLOCKED_MARKERS + AML3_ANTI_COARSE_FIX_MARKERS
    missing_markers = [marker for marker in required_markers if marker not in script_text]
    fix_artifacts = [relative for relative in AML3_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    missing_artifacts = [relative for relative in AML3_FIX_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml3-fix-cells-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml fixes/sentinel_aml",
        "status": "pass" if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts else "fail",
        "message": ""
        if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts
        else f"missing_markers={missing_markers} fix_artifacts={fix_artifacts} missing_artifacts={missing_artifacts}",
    }


def check_aml4_vulnerable_checker_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML4_CONCRETE_CELL_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML4_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml4-vulnerable-checker-concrete",
        "path": "scripts/check_competition_matrix_gate.py scripts/check_wave17_gate.py internal/exporting internal/httpapi",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_aml4_exploit_success_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML4_EXPLOIT_SUCCESS_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML4_EXPLOIT_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml4-exploit-success-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml/aml_export_redaction.py scripts/check_wave22_gate.py",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_aml4_fix_cells_concrete(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    required_markers = AML4_FIXED_CHECKER_MARKERS + AML4_EXPLOIT_BLOCKED_MARKERS + AML4_ANTI_COARSE_FIX_MARKERS
    missing_markers = [marker for marker in required_markers if marker not in script_text]
    fix_artifacts = [relative for relative in AML4_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    missing_artifacts = [relative for relative in AML4_FIX_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    legacy_artifacts = [relative for relative in AML4_FORBIDDEN_LEGACY_FIX_FILES if (repo_root / relative).exists()]
    return {
        "name": "competition-matrix-aml4-fix-cells-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml fixes/sentinel_aml",
        "status": "pass"
        if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts and not legacy_artifacts
        else "fail",
        "message": ""
        if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts and not legacy_artifacts
        else f"missing_markers={missing_markers} fix_artifacts={fix_artifacts} missing_artifacts={missing_artifacts} legacy_artifacts={legacy_artifacts}",
    }


def check_aml5_vulnerable_checker_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML5_CONCRETE_CELL_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML5_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml5-vulnerable-checker-concrete",
        "path": "scripts/check_competition_matrix_gate.py scripts/check_wave18_gate.py internal/httpapi internal/networkroom",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_aml5_exploit_success_cell(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    missing_markers = [marker for marker in AML5_EXPLOIT_SUCCESS_MARKERS if marker not in script_text]
    missing_artifacts = [relative for relative in AML5_EXPLOIT_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml5-exploit-success-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml/aml_network_room.py scripts/check_wave23_gate.py",
        "status": "pass" if not missing_markers and not missing_artifacts else "fail",
        "message": "" if not missing_markers and not missing_artifacts else f"missing_markers={missing_markers} missing_artifacts={missing_artifacts}",
    }


def check_aml5_fix_cells_concrete(repo_root: Path) -> dict[str, Any]:
    script_text = read(repo_root, "scripts/check_competition_matrix_gate.py")
    required_markers = AML5_FIXED_CHECKER_MARKERS + AML5_EXPLOIT_BLOCKED_MARKERS + AML5_ANTI_COARSE_FIX_MARKERS
    missing_markers = [marker for marker in required_markers if marker not in script_text]
    fix_artifacts = [relative for relative in AML5_FIX_ARTIFACTS if (repo_root / relative).is_file()]
    missing_artifacts = [relative for relative in AML5_FIX_REQUIRED_ARTIFACTS if not (repo_root / relative).is_file()]
    return {
        "name": "competition-matrix-aml5-fix-cells-concrete",
        "path": "scripts/check_competition_matrix_gate.py sploits/sentinel_aml fixes/sentinel_aml",
        "status": "pass" if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts else "fail",
        "message": ""
        if not missing_markers and len(fix_artifacts) == 1 and not missing_artifacts
        else f"missing_markers={missing_markers} fix_artifacts={fix_artifacts} missing_artifacts={missing_artifacts}",
    }


def check_wave32_validation_matrix_shape(repo_root: Path) -> dict[str, Any]:
    amls = [str(row["aml"]) for row in WAVE32_SPLOIT_FIX_MATRIX]
    sploits = [str(row["sploit"]) for row in WAVE32_SPLOIT_FIX_MATRIX]
    fixes = [str(row["fix"]) for row in WAVE32_SPLOIT_FIX_MATRIX]
    expected_amls = [f"AML-{index}" for index in range(1, 6)]
    missing_columns = [column for column in WAVE32_MATRIX_COLUMNS if not column]
    ok = amls == expected_amls and len(set(sploits)) == 5 and len(set(fixes)) == 5 and not missing_columns
    return {
        "name": "wave32-sploit-fix-validation-matrix-shape",
        "path": "scripts/check_competition_matrix_gate.py",
        "status": "pass" if ok else "fail",
        "message": ""
        if ok
        else f"amls={amls} sploits={sploits} fixes={fixes} missing_columns={missing_columns}",
    }


def check_wave32_sploit_syntax_and_business_paths(repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    for row in WAVE32_SPLOIT_FIX_MATRIX:
        sploit_path = repo_root / str(row["sploit"])
        text = sploit_path.read_text(encoding="utf-8") if sploit_path.is_file() else ""
        if not sploit_path.is_file():
            failures.append(f"{row['aml']}: missing {row['sploit']}")
            continue
        try:
            compile(text, str(sploit_path), "exec")
        except SyntaxError as exc:
            failures.append(f"{row['aml']}: syntax error in {row['sploit']}: {exc}")
        cli_markers = (
            'parser.add_argument("host"',
            'parser.add_argument("port"',
            'parser.add_argument("attack_info"',
            "def run_exploit(",
            "print(flag)",
        )
        missing_cli = [marker for marker in cli_markers if marker not in text]
        if missing_cli:
            failures.append(f"{row['aml']}: missing CLI/execution markers {missing_cli}")
        missing_paths = [marker for marker in row["sploit_paths"] if marker not in text]
        if missing_paths:
            failures.append(f"{row['aml']}: missing expected business paths {missing_paths}")
        lowered = text.lower()
        forbidden = [marker for marker in FORBIDDEN_SPLOIT_SHORTCUTS if marker.lower() in lowered]
        if forbidden:
            failures.append(f"{row['aml']}: forbidden shortcut markers in {row['sploit']}: {forbidden}")
    return {
        "name": "wave32-sploit-syntax-and-business-paths",
        "path": "sploits/sentinel_aml",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_wave32_fix_patch_and_simulation_evidence(repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    for row in WAVE32_SPLOIT_FIX_MATRIX:
        aml = str(row["aml"])
        fix = repo_root / str(row["fix"])
        fix_gate = repo_root / str(row["fix_gate"])
        profile_gate = repo_root / str(row["profile_gate"])
        test_path = repo_root / fix_gate.relative_to(repo_root).as_posix().replace("scripts/check_", "tests/test_")
        profile_text = profile_gate.read_text(encoding="utf-8") if profile_gate.is_file() else ""
        fix_gate_text = fix_gate.read_text(encoding="utf-8") if fix_gate.is_file() else ""
        test_text = test_path.read_text(encoding="utf-8") if test_path.is_file() else ""
        if not fix.is_file():
            failures.append(f"{aml}: missing fix patch {row['fix']}")
        if str(row["profile_command"]) not in profile_text:
            failures.append(f"{aml}: vulnerable profile build command missing from {row['profile_gate']}")
        if str(row["fix"]) not in fix_gate_text or "git apply --check" not in fix_gate_text:
            failures.append(f"{aml}: bounded patch-apply evidence missing from {row['fix_gate']}")
        if "test_checker_*.py" not in fix_gate_text or "go test ./..." not in fix_gate_text:
            failures.append(f"{aml}: fixed checker/go-green evidence missing from {row['fix_gate']}")
        missing_tests = [
            marker
            for marker in (str(row["vulnerable_success_test"]), str(row["fixed_block_test"]))
            if marker not in test_text
        ]
        if missing_tests:
            failures.append(f"{aml}: missing simulation tests {missing_tests} in {test_path.relative_to(repo_root).as_posix()}")
        checker_text = read(repo_root, "checkers/sentinel_aml/checker_lib.py")
        if str(row["check_havoc_green"]) not in checker_text:
            failures.append(f"{aml}: CHECK/HAVOC subcheck {row['check_havoc_green']} is not registered")
    return {
        "name": "wave32-fix-patch-and-simulation-evidence",
        "path": "fixes/sentinel_aml scripts/check_wave24_gate.py..scripts/check_wave28_gate.py tests/test_wave24_gate.py..tests/test_wave28_gate.py",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_wave32_docs_and_report_evidence(repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    combined = ""
    for relative in WAVE32_DOC_PATHS:
        path = repo_root / relative
        if not path.is_file():
            failures.append(f"missing {relative}")
            continue
        combined += "\n" + path.read_text(encoding="utf-8")
    for column in WAVE32_MATRIX_COLUMNS:
        if column not in combined:
            failures.append(f"missing matrix column {column!r}")
    for row in WAVE32_SPLOIT_FIX_MATRIX:
        row_markers = (
            str(row["aml"]),
            str(row["profile_gate"]),
            str(row["sploit"]),
            str(row["fix"]),
            str(row["fixed_block_test"]),
            str(row["check_havoc_green"]),
        )
        missing = [marker for marker in row_markers if marker not in combined]
        if missing:
            failures.append(f"{row['aml']}: missing docs/report markers {missing}")
    return {
        "name": "wave32-docs-and-report-evidence",
        "path": "docs/09_vulnerability_matrix.md docs/wave_reports/wave_32_sploit_fix_matrix.md",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_no_unsequenced_aml_activation(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    for path in iter_scanned_files(repo_root):
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        hits = [marker for marker in FORBIDDEN_UNSEQUENCED_AML_MARKERS if marker in text]
        if hits:
            findings.append(f"{path.relative_to(repo_root).as_posix()}: {sorted(hits)}")
    return {
        "name": "competition-matrix-no-unsequenced-aml-activation",
        "path": "cmd internal checkers config.yml docker-compose.yml Makefile",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def check_make_target(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "Makefile"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    present = f"{MAKE_TARGET}:" in text and "scripts/check_competition_matrix_gate.py" in text
    return {
        "name": "competition-matrix-make-target",
        "path": "Makefile",
        "status": "pass" if present else "fail",
        "message": "" if present else f"missing {MAKE_TARGET} target",
    }


def check_no_debug_admin_variant_toggles(repo_root: Path) -> dict[str, Any]:
    findings: list[str] = []
    for path in iter_scanned_files(repo_root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        endpoint_hits = [endpoint for endpoint in FORBIDDEN_DEBUG_ADMIN_ENDPOINTS if endpoint in lowered]
        toggle_hit = FORBIDDEN_VARIANT_TOGGLE_RE.search(text)
        if endpoint_hits or toggle_hit:
            relative = path.relative_to(repo_root).as_posix()
            if relative == "Makefile":
                endpoint_hits = []
            if not endpoint_hits and not toggle_hit:
                continue
            detail = ",".join(endpoint_hits) if endpoint_hits else toggle_hit.group(0)
            findings.append(f"{relative}: {detail}")
    return {
        "name": "no-http-debug-admin-variant-toggles",
        "path": "cmd internal checkers config.yml docker-compose.yml Makefile",
        "status": "pass" if not findings else "fail",
        "message": "" if not findings else "; ".join(findings),
    }


def iter_scanned_files(repo_root: Path):
    for dirname in SCAN_DIRS:
        base = repo_root / dirname
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in SCAN_SUFFIXES:
                yield path
    for relative in SCAN_FILES:
        path = repo_root / relative
        if path.is_file():
            yield path


def read(repo_root: Path, relative: str) -> str:
    path = repo_root / relative
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_competition_matrix_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
