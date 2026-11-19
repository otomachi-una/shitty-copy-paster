#!/usr/bin/env python3
"""Validate Wave 25 AML-2 reference fix artifact scope."""

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
    "fixes/sentinel_aml/aml_network_room.patch",
    "fixes/sentinel_aml/aml_related_graph.patch",
)
FIX_README = "fixes/sentinel_aml/README.md"
AML2_PATCH = "fixes/sentinel_aml/aml_audit_timeline.patch"
AML2_HANDOFF_T01 = "docs/wave_reports/wave_25_W25-T01_handoff.md"
AML2_HANDOFF_T02 = "docs/wave_reports/wave_25_W25-T02_handoff.md"
AML2_HANDOFF_T03 = "docs/wave_reports/wave_25_W25-T03_handoff.md"
MAKE_TARGET = "wave25-gate"

AML2_ALLOWED_PATCH_TARGETS = (
    "internal/httpapi/audit_profile_detail.go",
    "internal/httpapi/audit_profile_detail_test.go",
)
AML2_PATCH_REQUIRED_MARKERS = (
    "diff --git a/internal/httpapi/audit_profile_detail.go b/internal/httpapi/audit_profile_detail.go",
    "diff --git a/internal/httpapi/audit_profile_detail_test.go b/internal/httpapi/audit_profile_detail_test.go",
    "-\t\t\treturn auditrepo.ActivityDetailCollaborator",
    "+\t\t\treturn auditrepo.ActivityDetailRelated",
    "+func TestAML2FixedEntityActivityKeepsReviewContextScoped(t *testing.T) {",
    "+\tif strings.Contains(body, privateNote) || strings.Contains(body, `\"activity_detail_level\":\"collaborator_detail\"`) {",
    "+\tif !strings.Contains(body, `\"activity_detail_level\":\"related_view\"`) || !strings.Contains(body, `\"field\":\"restricted_field\"`) {",
    "+\townerNotes := domainRequest(handler, http.MethodGet, fmt.Sprintf(\"/api/cases/%d/notes\", root.ID), \"\", ownerToken)",
)
AML2_REQUIRED_REMOVALS = (
    "return auditrepo.ActivityDetailCollaborator",
    "`\"activity_detail_level\":\"collaborator_detail\"`",
    "found := false",
)
AML2_FORBIDDEN_ADDED_MARKERS = (
    "New:      noteBody",
    "New: noteBody",
    "Body string `json:\"body\"`",
    "Body   string `json:\"body\"`",
    "`json:\"diff_json\"`",
    "Redacted: false",
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
    "DisableAudit",
    "disable audit",
    "disable timeline",
    "credential",
    "session lookup",
)
AML2_COARSE_REMOVAL_MARKERS = (
    "handleCaseTimeline",
    "ListCaseTimelineByOwner",
    "recordAudit",
    "/timeline",
    "/activity",
    "parts[1] == \"activity\"",
    "CreateNote",
    "/notes",
    "caseAuditView(event)",
    "CaseTimelineResponse",
)
AML2_REQUIRED_ANTI_COARSE_MARKERS = (
    "`\"activity_detail_level\":\"related_view\"`",
    "`\"field\":\"restricted_field\"`",
    "ownerNotes := domainRequest",
    "AML-2 owner note path should remain available",
)
README_REQUIRED_MARKERS = (
    "AML-2",
    "aml_audit_timeline.patch",
    "activity_narrative",
    "[redacted]",
    "redacted",
    "Anti-coarse-fix",
    "do not remove audit logging",
)
HANDOFF_T01_REQUIRED_MARKERS = (
    "W25-T01",
    "AML-2",
    "git apply --check",
    "go test ./...",
    "test_checker_*.py",
    "blocked by redaction",
    "Ready for Orchestrator Review",
)
HANDOFF_T02_REQUIRED_MARKERS = (
    "W25-T02",
    "Wave 25",
    "AML-2",
    "check_wave25_gate.py",
    "competition matrix",
    "Ready for Orchestrator Review",
)
HANDOFF_T03_REQUIRED_MARKERS = (
    "W25-T03",
    "AML-2",
    "exploit succeeds against vulnerable fixture",
    "fails safely against redacted fixed",
    "event existence",
    "redaction markers",
    "/activity",
    "Ready for Orchestrator Review",
)
MAKE_REQUIRED_LINES = (
    '$(PYTHON) -B -m unittest discover -s tests -p "test_checker_*.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_wave25_gate.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"',
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_related_graph.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_export_redaction.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_network_room.py",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_audit_timeline.patch",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...",
    "$(GO_RELEASE_ENV) $(GO) vet ./...",
    "$(PYTHON) -B scripts/check_wave25_gate.py",
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
)


def validate_wave25_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_reference_exploits(repo_root),
        check_reference_fix_inventory(repo_root),
        check_patches_apply(repo_root),
        check_aml2_patch_scope(repo_root),
        check_aml2_patch_blocks_timeline_leak(repo_root),
        check_aml2_patch_anti_coarse_fix(repo_root),
        check_docs(repo_root),
        check_makefile_wave25_gate(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_reference_exploits(repo_root: Path) -> dict[str, Any]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    exploit_files = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    missing = [name for name in EXPECTED_EXPLOITS if name not in exploit_files]
    extra = [name for name in exploit_files if name not in EXPECTED_EXPLOITS]
    ok = exploit_files == sorted(EXPECTED_EXPLOITS)
    return {
        "name": "wave25-five-reference-exploits-still-present",
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
        "name": "wave25-reference-fix-artifacts-present",
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
        "name": "wave25-aml1-and-aml2-patches-apply-cleanly",
        "path": "fixes/sentinel_aml",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_aml2_patch_scope(repo_root: Path) -> dict[str, Any]:
    text = aml2_patch_text(repo_root)
    targets = patch_targets(text)
    unexpected = [target for target in targets if target not in AML2_ALLOWED_PATCH_TARGETS]
    missing_targets = [target for target in AML2_ALLOWED_PATCH_TARGETS if target not in targets]
    missing_markers = [marker for marker in AML2_PATCH_REQUIRED_MARKERS if marker not in text]
    ok = not unexpected and not missing_targets and not missing_markers
    return {
        "name": "wave25-aml2-patch-scope-and-redaction-projection",
        "path": AML2_PATCH,
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"unexpected_targets={unexpected} missing_targets={missing_targets} missing_markers={missing_markers}",
    }


def check_aml2_patch_blocks_timeline_leak(repo_root: Path) -> dict[str, Any]:
    text = aml2_patch_text(repo_root)
    added = added_lines(text)
    removed = removed_lines(text)
    missing_removals = [marker for marker in AML2_REQUIRED_REMOVALS if marker not in removed]
    forbidden_added = [marker for marker in AML2_FORBIDDEN_ADDED_MARKERS if marker.lower() in added.lower()]
    exploit = read(repo_root, "sploits/sentinel_aml/aml_audit_timeline.py")
    exploit_markers = [
        marker
        for marker in ("activity_narrative", "review_context_excerpt", 'change.get("redacted") is not False', "flag-like token not found")
        if marker not in exploit
    ]
    ok = not missing_removals and not forbidden_added and not exploit_markers
    return {
        "name": "wave25-aml2-exploit-blocked-by-redacted-audit-diff-values",
        "path": f"{AML2_PATCH} sploits/sentinel_aml/aml_audit_timeline.py",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"missing_removals={missing_removals} forbidden_added={forbidden_added} exploit_markers={exploit_markers}",
    }


def check_aml2_patch_anti_coarse_fix(repo_root: Path) -> dict[str, Any]:
    text = aml2_patch_text(repo_root)
    added = added_lines(text)
    removed = removed_lines(text)
    coarse_removals = [marker for marker in AML2_COARSE_REMOVAL_MARKERS if marker in removed and marker not in added]
    missing_added = [marker for marker in AML2_REQUIRED_ANTI_COARSE_MARKERS if marker not in text]
    ok = not coarse_removals and not missing_added
    return {
        "name": "wave25-aml2-anti-coarse-fix-preserves-timeline-audit-and-owner-apis",
        "path": AML2_PATCH,
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"coarse_removals={coarse_removals} missing_added={missing_added}",
    }


def check_docs(repo_root: Path) -> dict[str, Any]:
    missing: list[str] = []
    for marker in README_REQUIRED_MARKERS:
        if marker not in read(repo_root, FIX_README):
            missing.append(f"{FIX_README}: {marker}")
    for marker in HANDOFF_T01_REQUIRED_MARKERS:
        if marker not in read(repo_root, AML2_HANDOFF_T01):
            missing.append(f"{AML2_HANDOFF_T01}: {marker}")
    for marker in HANDOFF_T02_REQUIRED_MARKERS:
        if marker not in read(repo_root, AML2_HANDOFF_T02):
            missing.append(f"{AML2_HANDOFF_T02}: {marker}")
    for marker in HANDOFF_T03_REQUIRED_MARKERS:
        if marker not in read(repo_root, AML2_HANDOFF_T03):
            missing.append(f"{AML2_HANDOFF_T03}: {marker}")
    return {
        "name": "wave25-docs-and-handoffs-present",
        "path": "fixes/sentinel_aml/README.md docs/wave_reports",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_makefile_wave25_gate(repo_root: Path) -> dict[str, Any]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, MAKE_TARGET)
    missing = [line for line in MAKE_REQUIRED_LINES if line not in target]
    missing_env = [marker for marker in MAKE_REQUIRED_ENV_MARKERS if marker not in makefile]
    forbidden = [line for line in MAKE_FORBIDDEN_LINES if line in target]
    ok = bool(target) and not missing and not missing_env and not forbidden
    details = []
    if missing:
        details.append(f"missing {MAKE_TARGET} lines: {missing}")
    if missing_env:
        details.append(f"missing no-repo-cache release env markers: {missing_env}")
    if forbidden:
        details.append(f"forbidden unbounded Wave 25 lines: {forbidden}")
    return {
        "name": "wave25-make-target-runs-full-gate",
        "path": "Makefile",
        "status": "pass" if ok else "fail",
        "message": "; ".join(details),
    }


def aml2_patch_text(repo_root: Path) -> str:
    return read(repo_root, AML2_PATCH)


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
    result = validate_wave25_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
