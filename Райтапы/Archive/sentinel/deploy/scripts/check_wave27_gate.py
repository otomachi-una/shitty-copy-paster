#!/usr/bin/env python3
"""Validate Wave 27 AML-4 reference fix artifact scope."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


EXPECTED_EXPLOITS = (
    "aml_audit_timeline.py",
    "aml_dedup_preview.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
    "aml_related_graph.py",
)
EXPECTED_FIX_ARTIFACTS = (
    "fixes/sentinel_aml/aml_audit_timeline.patch",
    "fixes/sentinel_aml/aml_dedup_preview.patch",
    "fixes/sentinel_aml/aml_export_redaction.patch",
    "fixes/sentinel_aml/aml_related_graph.patch",
)
FIX_README = "fixes/sentinel_aml/README.md"
AML4_PATCH = "fixes/sentinel_aml/aml_export_redaction.patch"
AML4_HANDOFF_T01 = "docs/wave_reports/wave_27_W27-T01_handoff.md"
AML4_HANDOFF_T02 = "docs/wave_reports/wave_27_W27-T02_handoff.md"
AML4_HANDOFF_T03 = "docs/wave_reports/wave_27_W27-T03_handoff.md"
MAKE_TARGET = "wave27-gate"
GO_RELEASE_TEST_RUNNER = "scripts/run_go_release_tests.py"

AML4_ALLOWED_PATCH_TARGETS = (
    "internal/httpapi/export_profile_linked_case.go",
    "internal/exporting/export_profile_linked_case.go",
    "internal/httpapi/export_profile_linked_case_test.go",
)
AML4_PATCH_REQUIRED_MARKERS = (
    "diff --git a/internal/httpapi/export_profile_linked_case.go b/internal/httpapi/export_profile_linked_case.go",
    "diff --git a/internal/exporting/export_profile_linked_case.go b/internal/exporting/export_profile_linked_case.go",
    "diff --git a/internal/httpapi/export_profile_linked_case_test.go b/internal/httpapi/export_profile_linked_case_test.go",
    "-type exportDuplicatePrivateNotesReader interface",
    "-\tFindDuplicatePrivateNotesForPreview(context.Context, int64, int64, int64) ([]casework.CaseNote, error)",
    "-\tnotes, err := reader.FindDuplicatePrivateNotesForPreview(ctx, ownerUserID, sourceCaseID, linked.CaseID)",
    "-\t\tlinked.Notes = append(linked.Notes, exportNoteSnapshot(note))",
    "-import \"strings\"",
    "-\t\t\tbundle.LinkedPrivateNotes = append(bundle.LinkedPrivateNotes, map[string]any{",
    "-\t\t\t\t\"body\":    strings.TrimSpace(note.Body),",
    "-func TestLinkedCaseExportDetailIncludesOnlyLinkedPrivateNote(t *testing.T) {",
    "+func TestAML4FixedDisputeExportRedactsLinkedPrivateNotesRecursively(t *testing.T) {",
    "+\tassertAML4FixedExportPublicOnly(t, body, rootPrivateNote, linkedPrivateNote, rootEDDComment, linkedEDDComment)",
    "+\tassertAML4FixedExportPublicOnly(t, read.Body.String(), rootPrivateNote, linkedPrivateNote, rootEDDComment, linkedEDDComment)",
    "+func assertAML4FixedExportPublicOnly(t *testing.T, body string, forbiddenSentinels ...string) {",
    "+\tlinkedOwnerNotes := domainRequest(handler, http.MethodGet, fmt.Sprintf(\"/api/cases/%d/notes\", linked.caseID), \"\", otherToken)",
    "+\tlinkedOwnerEDD := domainRequest(handler, http.MethodGet, fmt.Sprintf(\"/api/customers/%d/edd\", linked.customerID), \"\", otherToken)",
    "+\tfor _, required := range []string{\"AML4 root public shell\", \"AML4 linked public shell\", \"linked_cases\", \"redaction_policy\", \"restricted_field\"} {",
)
AML4_REQUIRED_REMOVALS = (
    "exportDuplicatePrivateNotesReader",
    "FindDuplicatePrivateNotesForPreview",
    "casework.CaseNote",
    "linked.Notes = append(linked.Notes, exportNoteSnapshot(note))",
    "import \"strings\"",
    "bundle.LinkedPrivateNotes = append",
    "\"body\":    strings.TrimSpace(note.Body)",
    "TestLinkedCaseExportDetailIncludesOnlyLinkedPrivateNote",
)
AML4_FORBIDDEN_ADDED_MARKERS = (
    "FindDuplicatePrivateNotesForPreview",
    "casework.CaseNote",
    "exportNoteSnapshot(note)",
    "bundle.LinkedPrivateNotes = append",
    "`json:\"linked_private_notes",
    "LinkedPrivateNotes []",
    "`json:\"body\"`",
    "\"body\":    ",
    "\"body\": strings.TrimSpace",
    "CaseNote.body",
    "EDDRecord.confidential_comment",
    "ConfidentialComment string",
    "`json:\"confidential_comment",
    "InternalComment string",
    "`json:\"internal_comment",
    "AnalystInternalNote",
    "`json:\"analyst_internal_note",
    "analyst_internal_note",
    "LinkedNoteBody",
    "`json:\"linked_note_body",
    "PrivateNoteBody",
    "`json:\"private_note_body",
    "DiffJSON string",
    "`json:\"diff_json",
    "RawDiff string",
    "`json:\"raw_diff",
    "ValueHash string",
    "`json:\"value_hash",
    "OldHash string",
    "`json:\"old_hash",
    "NewHash string",
    "`json:\"new_hash",
    "database/sql",
    "sql.Open",
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "exec.Command",
    "os/exec",
    "subprocess",
    "os.system",
    "/api/debug",
    "/api/admin",
    "/debug",
    "/admin",
    "DisableExport",
    "disable export",
    "DisableDispute",
    "credential",
    "session lookup",
    "raw_db_row",
)
AML4_COARSE_REMOVAL_MARKERS = (
    "/api/cases/{case_id}/exports",
    "/api/exports/{export_id}",
    "/api/disputes",
    "/api/disputes/{dispute_id}/export",
    "handleCreateCaseExport",
    "handleExportsSubtree",
    "handleDisputesRoot",
    "handleDisputeExport",
    "CreateExport",
    "GetExportByOwner",
    "BuildBundle",
    "ExportResponse",
    "ExportBundleView",
    "exportBundleView",
    "exportCaseShellView",
    "LinkedCases",
    "DisputeResponse",
    "redaction_policy",
    "linked_cases",
)
AML4_REQUIRED_ANTI_COARSE_MARKERS = (
    "TestAML4FixedDisputeExportRedactsLinkedPrivateNotesRecursively",
    "AML4 root public shell",
    "AML4 linked public shell",
    "linked_cases",
    "redaction_policy",
    "restricted_field",
    "exported.ID == 0 || exported.DisputeID != dispute.ID || exported.RootCaseID != root.caseID || len(exported.Bundle.LinkedCases) != 1",
    "linkedOwnerNotes := domainRequest",
    "linked owner notes should remain available only through owner API",
    "linkedOwnerEDD := domainRequest",
    "linked owner EDD should remain available only through owner API",
)
README_REQUIRED_MARKERS = (
    "AML-4",
    "aml_export_redaction.patch",
    "linked_private_notes[].body",
    "recursive",
    "Expected blocked exploit",
    "sploits/sentinel_aml/aml_export_redaction.py",
    "Anti-coarse-fix",
    "do not remove export endpoints",
)
HANDOFF_T01_REQUIRED_MARKERS = (
    "W27-T01",
    "AML-4",
    "git apply --check",
    "go test ./...",
    "TestAML4FixedDisputeExportRedactsLinkedPrivateNotesRecursively",
    "test_checker_*.py",
    "Ready for Orchestrator Review",
)
HANDOFF_T02_REQUIRED_MARKERS = (
    "W27-T02",
    "Wave 27",
    "AML-4",
    "check_wave27_gate.py",
    "competition matrix",
    "wave27-gate",
    "Ready for Orchestrator Review",
)
HANDOFF_T03_REQUIRED_MARKERS = (
    "W27-T03",
    "AML-4",
    "exploit parser succeeds on vulnerable output",
    "fails safely on fixed output",
    "linked-case public export evidence",
    "anti-coarse-fix",
    "Ready for Orchestrator Review",
)
MAKE_REQUIRED_LINES = (
    '$(PYTHON) -B -m unittest discover -s tests -p "test_checker_*.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_wave27_gate.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_run_go_release_tests.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"',
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_related_graph.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_export_redaction.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_network_room.py",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_audit_timeline.patch",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_related_graph.patch",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_export_redaction.patch",
    "$(PYTHON) -B scripts/run_go_release_tests.py --go $(GO) --package-timeout 120",
    "$(GO_RELEASE_ENV) $(GO) vet ./...",
    "$(PYTHON) -B scripts/check_wave27_gate.py",
    "$(PYTHON) -B scripts/check_competition_matrix_gate.py",
    "$(PYTHON) -B scripts/check_docs_tree.py",
    "$(PYTHON) -B scripts/validate_forcad_config.py",
    "$(PYTHON) -B scripts/check_archive_hygiene.py",
)
MAKE_REQUIRED_ENV_MARKERS = (
    'GOCACHE=$$(mktemp -d "$${TMPDIR:-/tmp}/sentinel-aml-gocache.XXXXXXXXXX")',
    'APPDATA=$$(mktemp -d "$${TMPDIR:-/tmp}/sentinel-aml-appdata.XXXXXXXXXX")',
)
MAKE_FORBIDDEN_LINES = (
    "$(GO_RELEASE_ENV) $(GO) test ./...",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...",
)


def validate_wave27_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_reference_exploits(repo_root),
        check_reference_fix_inventory(repo_root),
        check_patches_apply(repo_root),
        check_aml4_patch_scope(repo_root),
        check_aml4_patch_blocks_export_leak(repo_root),
        check_aml4_patch_anti_coarse_fix(repo_root),
        check_docs(repo_root),
        check_makefile_wave27_gate(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_reference_exploits(repo_root: Path) -> dict[str, Any]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    exploit_files = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    missing = [name for name in EXPECTED_EXPLOITS if name not in exploit_files]
    extra = [name for name in exploit_files if name not in EXPECTED_EXPLOITS]
    ok = exploit_files == sorted(EXPECTED_EXPLOITS)
    return {
        "name": "wave27-five-reference-exploits-still-present",
        "path": "sploits/sentinel_aml",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"missing={missing} extra={extra} exploit_files={exploit_files}",
    }


def check_reference_fix_inventory(repo_root: Path) -> dict[str, Any]:
    fixes_dir = repo_root / "fixes" / "sentinel_aml"
    present = []
    if fixes_dir.is_dir():
        present = sorted(
            path.relative_to(repo_root).as_posix()
            for path in fixes_dir.rglob("*")
            if path.is_file() and path.relative_to(repo_root).as_posix() != FIX_README
        )
    ok = present == sorted(EXPECTED_FIX_ARTIFACTS)
    return {
        "name": "wave27-only-aml1-through-aml4-reference-fix-artifacts-present",
        "path": "fixes/sentinel_aml",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"expected={sorted(EXPECTED_FIX_ARTIFACTS)} present={present}",
    }


def check_patches_apply(repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    for relative in EXPECTED_FIX_ARTIFACTS:
        patch = repo_root / relative
        if not patch.is_file():
            failures.append(f"{relative}: missing")
            continue
        try:
            completed = subprocess.run(
                ["git", "apply", "--check", "--whitespace=error", relative],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            failures.append(f"{relative}: git apply check failed to run: {exc}")
            continue
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            failures.append(f"{relative}: {detail}")
    return {
        "name": "wave27-aml1-through-aml4-patches-apply-cleanly",
        "path": "fixes/sentinel_aml",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_aml4_patch_scope(repo_root: Path) -> dict[str, Any]:
    text = aml4_patch_text(repo_root)
    targets = patch_targets(text)
    unexpected = [target for target in targets if target not in AML4_ALLOWED_PATCH_TARGETS]
    missing_targets = [target for target in AML4_ALLOWED_PATCH_TARGETS if target not in targets]
    missing_markers = [marker for marker in AML4_PATCH_REQUIRED_MARKERS if marker not in text]
    ok = not unexpected and not missing_targets and not missing_markers
    return {
        "name": "wave27-aml4-patch-scope-and-recursive-redaction",
        "path": AML4_PATCH,
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"unexpected_targets={unexpected} missing_targets={missing_targets} missing_markers={missing_markers}",
    }


def check_aml4_patch_blocks_export_leak(repo_root: Path) -> dict[str, Any]:
    text = aml4_patch_text(repo_root)
    added = added_lines(text)
    removed = removed_lines(text)
    missing_removals = [marker for marker in AML4_REQUIRED_REMOVALS if marker not in removed]
    forbidden_added = [marker for marker in AML4_FORBIDDEN_ADDED_MARKERS if marker.lower() in added.lower()]
    exploit = read(repo_root, "sploits/sentinel_aml/aml_export_redaction.py")
    exploit_markers = [
        marker
        for marker in ("linked_private_notes", "body", "/api/disputes/{dispute_id}/export", "/api/exports/{export_id}", "flag-like token not found")
        if marker not in exploit
    ]
    ok = not missing_removals and not forbidden_added and not exploit_markers
    return {
        "name": "wave27-aml4-exploit-blocked-by-recursive-export-redaction",
        "path": f"{AML4_PATCH} sploits/sentinel_aml/aml_export_redaction.py",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"missing_removals={missing_removals} forbidden_added={forbidden_added} exploit_markers={exploit_markers}",
    }


def check_aml4_patch_anti_coarse_fix(repo_root: Path) -> dict[str, Any]:
    text = aml4_patch_text(repo_root)
    added = added_lines(text)
    removed = removed_lines(text)
    coarse_removals = []
    for marker in AML4_COARSE_REMOVAL_MARKERS:
        if marker not in removed:
            continue
        if marker in {"linked_cases", "redaction_policy"} and marker in added:
            continue
        coarse_removals.append(marker)
    missing_added = [marker for marker in AML4_REQUIRED_ANTI_COARSE_MARKERS if marker not in text]
    ok = not coarse_removals and not missing_added
    return {
        "name": "wave27-aml4-anti-coarse-fix-preserves-export-dispute-and-owner-apis",
        "path": AML4_PATCH,
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"coarse_removals={coarse_removals} missing_added={missing_added}",
    }


def check_docs(repo_root: Path) -> dict[str, Any]:
    missing: list[str] = []
    for marker in README_REQUIRED_MARKERS:
        if marker not in read(repo_root, FIX_README):
            missing.append(f"{FIX_README}: {marker}")
    for marker in HANDOFF_T01_REQUIRED_MARKERS:
        if marker not in read(repo_root, AML4_HANDOFF_T01):
            missing.append(f"{AML4_HANDOFF_T01}: {marker}")
    for marker in HANDOFF_T02_REQUIRED_MARKERS:
        if marker not in read(repo_root, AML4_HANDOFF_T02):
            missing.append(f"{AML4_HANDOFF_T02}: {marker}")
    for marker in HANDOFF_T03_REQUIRED_MARKERS:
        if marker not in read(repo_root, AML4_HANDOFF_T03):
            missing.append(f"{AML4_HANDOFF_T03}: {marker}")
    return {
        "name": "wave27-docs-and-handoffs-present",
        "path": "fixes/sentinel_aml/README.md docs/wave_reports",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_makefile_wave27_gate(repo_root: Path) -> dict[str, Any]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, MAKE_TARGET)
    missing = [line for line in MAKE_REQUIRED_LINES if line not in target]
    missing_env = [marker for marker in MAKE_REQUIRED_ENV_MARKERS if marker not in makefile]
    forbidden = [line for line in MAKE_FORBIDDEN_LINES if line in target]
    missing_helper = [] if (repo_root / GO_RELEASE_TEST_RUNNER).is_file() else [GO_RELEASE_TEST_RUNNER]
    ok = bool(target) and not missing and not missing_env and not forbidden and not missing_helper
    details = []
    if missing:
        details.append(f"missing {MAKE_TARGET} lines: {missing}")
    if missing_env:
        details.append(f"missing no-repo-cache release env markers: {missing_env}")
    if forbidden:
        details.append(f"forbidden unbounded Wave 27 lines: {forbidden}")
    if missing_helper:
        details.append(f"missing package-by-package Go release test runner: {missing_helper}")
    return {
        "name": "wave27-make-target-runs-full-gate",
        "path": "Makefile",
        "status": "pass" if ok else "fail",
        "message": "; ".join(details),
    }


def aml4_patch_text(repo_root: Path) -> str:
    return read(repo_root, AML4_PATCH)


def patch_targets(text: str) -> list[str]:
    return [match.group(1) for match in re.finditer(r"(?m)^diff --git a/(.+?) b/\1$", text)]


def added_lines(text: str) -> str:
    return "\n".join(line[1:] for line in text.splitlines() if line.startswith("+") and not line.startswith("+++"))


def removed_lines(text: str) -> str:
    return "\n".join(line[1:] for line in text.splitlines() if line.startswith("-") and not line.startswith("---"))


def make_target_block(text: str, target_name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target_name)}:\s*(?:#.*)?$", text)
    if not match:
        return ""
    next_target = re.search(r"(?m)^[A-Za-z0-9_.-]+:.*$", text[match.end() :])
    end = match.end() + next_target.start() if next_target else len(text)
    return text[match.start() : end]


def read(repo_root: Path, relative: str) -> str:
    path = repo_root / relative
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave27_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
