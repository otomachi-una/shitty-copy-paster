#!/usr/bin/env python3
"""Validate Wave 24 AML-1 reference fix artifact scope."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


FIX_ARTIFACTS = (
    "fixes/sentinel_aml/aml_dedup_preview.patch",
    "fixes/sentinel_aml/aml_dedup_preview.diff",
)
KNOWN_FIX_ARTIFACTS = {
    "fixes/sentinel_aml/aml_audit_timeline.patch",
    "fixes/sentinel_aml/aml_dedup_preview.patch",
    "fixes/sentinel_aml/aml_export_redaction.patch",
    "fixes/sentinel_aml/aml_network_room.patch",
    "fixes/sentinel_aml/aml_related_graph.patch",
}
FIX_README = "fixes/sentinel_aml/README.md"
HANDOFF_T01_PATH = "docs/wave_reports/wave_24_W24-T01_handoff.md"
HANDOFF_T02_PATH = "docs/wave_reports/wave_24_W24-T02_handoff.md"
HANDOFF_T03_PATH = "docs/wave_reports/wave_24_W24-T03_handoff.md"
MAKE_TARGET = "wave24-gate"
EXPECTED_EXPLOITS = (
    "aml_audit_timeline.py",
    "aml_dedup_preview.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
    "aml_related_graph.py",
)
ALLOWED_PATCH_TARGETS = (
    "internal/httpapi/dedup_profile_case_match.go",
    "internal/httpapi/dedup_profile_case_match_test.go",
)
PATCH_REQUIRED_MARKERS = (
    "diff --git a/internal/httpapi/dedup_profile_case_match.go b/internal/httpapi/dedup_profile_case_match.go",
    "diff --git a/internal/httpapi/dedup_profile_case_match_test.go b/internal/httpapi/dedup_profile_case_match_test.go",
    "+func (s *Server) caseDuplicateMergePreviewResponse(_ context.Context, _ int64, sourceCaseID int64, candidate casework.DuplicateCandidate) (any, error) {",
    "-\tif resolver, ok := s.cases.(casework.MatchEvidenceResolver); ok {",
    "-\t\tcasework.MatchEvidenceSourceReviewContext,",
    "+\texplanation := casework.NewMatchExplanationBuilder(casework.PublicMatchEvidenceSources()...).Build(evidence, view.MatchExplanation)",
    "+func TestCaseMatchPreviewUsesPublicEvidenceAsMatchExplanation(t *testing.T) {",
    "assertJSONKeys(t, \"AML-1 candidate\", mapKeys(candidate), []string{\"case_id\", \"public_summary\", \"risk_tags\", \"overlap_score\", \"match_explanation\"})",
)
PATCH_REQUIRED_REMOVALS = (
    "ResolveMatchEvidence",
    "MatchEvidenceRequest",
    "MatchEvidenceSourceReviewContext",
    "CandidateCaseID",
)
ADDED_FORBIDDEN_MARKERS = (
    "private_notes",
    "`json:\"body\"`",
    "FindDuplicatePrivateNotesForPreview",
    "duplicatePrivateNotePreviews",
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
    "DisableDedup",
    "disable dedup",
    "disable duplicate",
)
COARSE_FIX_REMOVAL_MARKERS = (
    "handleCaseNotes",
    "ListNotesByOwner",
    "CreateNote",
    "/notes",
    "/duplicates",
    "/merge-preview",
    "duplicatePreviewView(candidate)",
    "FindDuplicateCandidates",
)
README_REQUIRED_MARKERS = (
    "AML-1",
    "aml_dedup_preview.patch",
    "candidate.match_explanation",
    "public",
    "Anti-coarse-fix",
    "do not remove deduplication",
)
HANDOFF_REQUIRED_MARKERS = (
    "W24-T01",
    "AML-1",
    "git apply --check",
    "go test ./...",
    "test_checker_*.py",
    "test_exploit_fails_safely_against_secure_preview",
    "Ready for Orchestrator Review",
)
MAKE_REQUIRED_LINES = (
    '$(PYTHON) -B -m unittest discover -s tests -p "test_checker_*.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_wave24_gate.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"',
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_related_graph.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_export_redaction.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_network_room.py",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...",
    "$(GO_RELEASE_ENV) $(GO) vet ./...",
    "$(PYTHON) -B scripts/check_wave24_gate.py",
    "$(PYTHON) -B scripts/check_competition_matrix_gate.py",
    "$(PYTHON) -B scripts/check_docs_tree.py",
    "$(PYTHON) -B scripts/validate_forcad_config.py",
    "$(PYTHON) -B scripts/check_archive_hygiene.py",
)
MAKE_REQUIRED_ENV_MARKERS = (
    'GOCACHE=$$(mktemp -d "$${TMPDIR:-/tmp}/sentinel-aml-gocache.XXXXXXXXXX")',
    'APPDATA=$$(mktemp -d "$${TMPDIR:-/tmp}/sentinel-aml-appdata.XXXXXXXXXX")',
)
MAKE_FORBIDDEN_WAVE24_LINES = (
    "$(GO_RELEASE_ENV) $(GO) test ./...",
)


def validate_wave24_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_reference_exploits(repo_root),
        check_reference_fix_inventory(repo_root),
        check_patch_applies(repo_root),
        check_patch_scope(repo_root),
        check_patch_blocks_aml1_leak(repo_root),
        check_patch_anti_coarse_fix(repo_root),
        check_docs(repo_root),
        check_makefile_wave24_gate(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_reference_exploits(repo_root: Path) -> dict[str, Any]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    exploit_files = sorted(item.name for item in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    missing = [name for name in EXPECTED_EXPLOITS if name not in exploit_files]
    extra = [name for name in exploit_files if name not in EXPECTED_EXPLOITS]
    ok = exploit_files == sorted(EXPECTED_EXPLOITS)
    return {
        "name": "wave24-five-reference-exploits-still-present",
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
    expected_present = [relative for relative in FIX_ARTIFACTS if (repo_root / relative).is_file()]
    unexpected = [relative for relative in present if relative not in KNOWN_FIX_ARTIFACTS and relative not in FIX_ARTIFACTS]
    ok = len(expected_present) == 1 and not unexpected
    message = "" if ok else f"expected one AML-1 fix artifact from {list(FIX_ARTIFACTS)} and no unknown fixes, present={present} unexpected={unexpected}"
    return {
        "name": "wave24-aml1-reference-fix-artifact-present",
        "path": "fixes/sentinel_aml",
        "status": "pass" if ok else "fail",
        "message": message,
    }


def check_patch_applies(repo_root: Path) -> dict[str, Any]:
    artifact = find_fix_artifact(repo_root)
    if artifact is None:
        return {
            "name": "wave24-aml1-patch-applies-cleanly",
            "path": "fixes/sentinel_aml",
            "status": "fail",
            "message": "missing AML-1 patch/diff artifact",
        }
    try:
        completed = subprocess.run(
            ["git", "apply", "--check", "--whitespace=error", str(artifact.relative_to(repo_root))],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "name": "wave24-aml1-patch-applies-cleanly",
            "path": artifact.relative_to(repo_root).as_posix(),
            "status": "fail",
            "message": f"git apply check failed to run: {exc}",
        }
    ok = completed.returncode == 0
    detail = (completed.stderr or completed.stdout).strip()
    return {
        "name": "wave24-aml1-patch-applies-cleanly",
        "path": artifact.relative_to(repo_root).as_posix(),
        "status": "pass" if ok else "fail",
        "message": "" if ok else detail,
    }


def check_patch_scope(repo_root: Path) -> dict[str, Any]:
    text = fix_artifact_text(repo_root)
    targets = patch_targets(text)
    unexpected = [target for target in targets if target not in ALLOWED_PATCH_TARGETS]
    missing_targets = [target for target in ALLOWED_PATCH_TARGETS if target not in targets]
    missing_markers = [marker for marker in PATCH_REQUIRED_MARKERS if marker not in text]
    ok = not unexpected and not missing_targets and not missing_markers
    message = "" if ok else f"unexpected_targets={unexpected} missing_targets={missing_targets} missing_markers={missing_markers}"
    return {
        "name": "wave24-aml1-patch-scope-and-safe-projection",
        "path": "fixes/sentinel_aml/aml_dedup_preview.patch",
        "status": "pass" if ok else "fail",
        "message": message,
    }


def check_patch_blocks_aml1_leak(repo_root: Path) -> dict[str, Any]:
    text = fix_artifact_text(repo_root)
    added = added_lines(text)
    removed = removed_lines(text)
    missing_removals = [marker for marker in PATCH_REQUIRED_REMOVALS if marker not in removed]
    forbidden_added = [marker for marker in ADDED_FORBIDDEN_MARKERS if marker.lower() in added.lower()]
    exploit = repo_root / "sploits" / "sentinel_aml" / "aml_dedup_preview.py"
    exploit_text = exploit.read_text(encoding="utf-8") if exploit.is_file() else ""
    exploit_markers = [
        marker
        for marker in ("candidate", "match_explanation", "flag-like token not found in match explanation")
        if marker not in exploit_text
    ]
    ok = not missing_removals and not forbidden_added and not exploit_markers
    message = "" if ok else f"missing_removals={missing_removals} forbidden_added={forbidden_added} exploit_markers={exploit_markers}"
    return {
        "name": "wave24-aml1-exploit-blocked-by-public-evidence-selection",
        "path": "fixes/sentinel_aml/aml_dedup_preview.patch sploits/sentinel_aml/aml_dedup_preview.py",
        "status": "pass" if ok else "fail",
        "message": message,
    }


def check_patch_anti_coarse_fix(repo_root: Path) -> dict[str, Any]:
    text = fix_artifact_text(repo_root)
    added = added_lines(text)
    removed = removed_lines(text)
    coarse_removals = [marker for marker in COARSE_FIX_REMOVAL_MARKERS if marker in removed and marker not in added]
    required_added = [
        "TestCaseMatchPreviewUsesPublicEvidenceAsMatchExplanation",
        "\"case_id\", \"public_summary\", \"risk_tags\", \"overlap_score\", \"match_explanation\"",
        "ownerNotes := domainRequest",
    ]
    missing_added = [marker for marker in required_added if marker not in text]
    ok = not coarse_removals and not missing_added
    message = "" if ok else f"coarse_removals={coarse_removals} missing_added={missing_added}"
    return {
        "name": "wave24-aml1-anti-coarse-fix-preserves-dedup-and-owner-apis",
        "path": "fixes/sentinel_aml/aml_dedup_preview.patch",
        "status": "pass" if ok else "fail",
        "message": message,
    }


def check_docs(repo_root: Path) -> dict[str, Any]:
    missing: list[str] = []
    for marker in README_REQUIRED_MARKERS:
        if marker not in read(repo_root, FIX_README):
            missing.append(f"{FIX_README}: {marker}")
    for marker in HANDOFF_REQUIRED_MARKERS:
        if marker not in read(repo_root, HANDOFF_T01_PATH):
            missing.append(f"{HANDOFF_T01_PATH}: {marker}")
    handoff_t02 = read(repo_root, HANDOFF_T02_PATH)
    if handoff_t02:
        for marker in ("W24-T02", "AML-1", "Ready for Orchestrator Review"):
            if marker not in handoff_t02:
                missing.append(f"{HANDOFF_T02_PATH}: {marker}")
    handoff_t03 = read(repo_root, HANDOFF_T03_PATH)
    if handoff_t03:
        for marker in ("W24-T03", "exploit-blocked", "anti-coarse-fix", "Ready for Orchestrator Review"):
            if marker not in handoff_t03:
                missing.append(f"{HANDOFF_T03_PATH}: {marker}")
    return {
        "name": "wave24-docs-and-handoffs-present",
        "path": "fixes/sentinel_aml/README.md docs/wave_reports",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_makefile_wave24_gate(repo_root: Path) -> dict[str, Any]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, MAKE_TARGET)
    missing = [line for line in MAKE_REQUIRED_LINES if line not in target]
    missing_env = [marker for marker in MAKE_REQUIRED_ENV_MARKERS if marker not in makefile]
    forbidden = [line for line in MAKE_FORBIDDEN_WAVE24_LINES if line in target]
    ok = bool(target) and not missing and not missing_env and not forbidden
    details = []
    if missing:
        details.append(f"missing {MAKE_TARGET} lines: {missing}")
    if missing_env:
        details.append(f"missing no-repo-cache release env markers: {missing_env}")
    if forbidden:
        details.append(f"forbidden unbounded Wave 24 lines: {forbidden}")
    message = "; ".join(details)
    return {"name": "wave24-make-target-runs-full-gate", "path": "Makefile", "status": "pass" if ok else "fail", "message": message}


def find_fix_artifact(repo_root: Path) -> Path | None:
    present = [repo_root / relative for relative in FIX_ARTIFACTS if (repo_root / relative).is_file()]
    return present[0] if len(present) == 1 else None


def fix_artifact_text(repo_root: Path) -> str:
    artifact = find_fix_artifact(repo_root)
    return artifact.read_text(encoding="utf-8") if artifact is not None else ""


def patch_targets(text: str) -> list[str]:
    targets: list[str] = []
    for match in re.finditer(r"(?m)^diff --git a/(.+?) b/\1$", text):
        targets.append(match.group(1))
    return targets


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
    result = validate_wave24_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
