#!/usr/bin/env python3
"""Validate Wave 26 AML-3 reference fix artifact scope."""

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
	"fixes/sentinel_aml/aml_related_graph.patch",
	"fixes/sentinel_aml/aml_export_redaction.patch",
	"fixes/sentinel_aml/aml_network_room.patch",
)
FIX_README = "fixes/sentinel_aml/README.md"
AML3_PATCH = "fixes/sentinel_aml/aml_related_graph.patch"
AML3_HANDOFF_T01 = "docs/wave_reports/wave_26_W26-T01_handoff.md"
AML3_HANDOFF_T02 = "docs/wave_reports/wave_26_W26-T02_handoff.md"
AML3_HANDOFF_T03 = "docs/wave_reports/wave_26_W26-T03_handoff.md"
MAKE_TARGET = "wave26-gate"
GO_RELEASE_TEST_RUNNER = "scripts/run_go_release_tests.py"

AML3_ALLOWED_PATCH_TARGETS = (
	"internal/graph/repository_entity_review.go",
	"internal/httpapi/graph_profile_entity_review_test.go",
)
AML3_PATCH_REQUIRED_MARKERS = (
	"diff --git a/internal/graph/repository_entity_review.go b/internal/graph/repository_entity_review.go",
	"diff --git a/internal/httpapi/graph_profile_entity_review_test.go b/internal/httpapi/graph_profile_entity_review_test.go",
	"-\tpolicy := ExtendedAssessmentSummaryPolicy()",
	"+\tpolicy := GraphAssessmentSummaryPolicy()",
	"+func TestAML3FixedGraphEDDSummariesKeepAssessmentSummaryScoped(t *testing.T) {",
	"+\tif strings.Contains(body, victimEDD) || strings.Contains(body, attackerEDD) {",
	"+\tif !strings.Contains(body, `\"assessment_summary\"`) || !strings.Contains(body, \"EXPORT_RISK_RATIONALE_SENTINEL\") {",
	"+\tassertAML3GraphEDDLeakIsBounded(t, body, victimNote, victimEDD, attackerNote, attackerEDD)",
	"var decoded entityReviewEDDGraphSummariesResponse",
	"+\townerEDD := domainRequest(handler, http.MethodGet, fmt.Sprintf(\"/api/customers/%d/edd\", victimCustomer.ID), \"\", victimToken)",
)
AML3_REQUIRED_REMOVALS = (
	"policy := ExtendedAssessmentSummaryPolicy()",
	"TestEntityReviewGraphEDDSummariesIncludeAssessmentSummary",
	"entity review graph profile did not expose victim assessment summary",
	"AML-3 graph response missing victim assessment summary",
)
AML3_FORBIDDEN_ADDED_MARKERS = (
	"`json:\"confidential_comment",
    "ConfidentialComment",
    "ListReviewEDDSummaries",
    "ReviewEDDSummary",
    "CaseNote.body",
    "`json:\"body\"`",
    "private_notes",
    "`json:\"edd_comment",
    "`json:\"private_edd",
    "`json:\"comment_hash",
    "`json:\"value_hash",
    "`json:\"old_hash",
    "`json:\"new_hash",
    "`json:\"diff_json",
    "ConfidentialNote",
    "PrivateEDD",
    "EDDComment",
    "CommentHash",
    "ValueHash",
    "OldHash",
    "NewHash",
    "DiffJSON",
    "RawDiff",
	"body_hash",
	"source_of_funds",
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
    "DisableGraph",
    "disable graph",
    "disable edd",
    "credential",
    "session lookup",
    "raw_db_row",
)
AML3_COARSE_REMOVAL_MARKERS = (
    "/api/graph/entities",
    "/related-cases",
    "/edd-summaries",
    "handleGraph",
    "GetEntitySummary",
    "ListRelatedCases",
    "EDDGraphSummariesResponse",
    "GraphEntityView",
    "GraphRelatedCaseView",
    "graphMemoryRepo",
    "internal/graph/repository.go",
    "graph_profile_default.go",
    "graph_profile_entity_review_test.go",
    "/api/customers/{customer_id}/edd",
)
AML3_REQUIRED_ANTI_COARSE_MARKERS = (
	"TestAML3FixedGraphEDDSummariesKeepAssessmentSummaryScoped",
	"ownerEDD := domainRequest",
	"AML-3 owner EDD path should remain available",
	"EXPORT_RISK_RATIONALE_SENTINEL",
)
README_REQUIRED_MARKERS = (
	"AML-3",
	"aml_related_graph.patch",
	"AssessmentSummaryPolicy",
	"assessment_summary",
	"public risk rationale",
	"Owner EDD access",
	"Anti-coarse-fix",
	"do not remove graph endpoints",
)
HANDOFF_T01_REQUIRED_MARKERS = (
    "W26-T01",
	"AML-3",
	"git apply --check",
	"go test ./...",
	"TestAML3FixedGraphEDDSummariesKeepAssessmentSummaryScoped",
	"test_checker_*.py",
	"Ready for Orchestrator Review",
)
HANDOFF_T02_REQUIRED_MARKERS = (
    "W26-T02",
    "Wave 26",
    "AML-3",
    "check_wave26_gate.py",
    "competition matrix",
    "Ready for Orchestrator Review",
)
HANDOFF_T03_REQUIRED_MARKERS = (
    "W26-T03",
    "AML-3",
    "exploit parser succeeds on vulnerable fixture",
    "fails safely on fixed graph summary output",
    "owner EDD API remains the only route",
    "anti-coarse-fix",
    "Ready for Orchestrator Review",
)
MAKE_REQUIRED_LINES = (
    '$(PYTHON) -B -m unittest discover -s tests -p "test_checker_*.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_wave26_gate.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"',
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_related_graph.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_export_redaction.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_network_room.py",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_audit_timeline.patch",
    "git apply --check --whitespace=error fixes/sentinel_aml/aml_related_graph.patch",
    "$(PYTHON) -B scripts/run_go_release_tests.py --go $(GO) --package-timeout 120",
    "$(GO_RELEASE_ENV) $(GO) vet ./...",
    "$(PYTHON) -B scripts/check_wave26_gate.py",
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


def validate_wave26_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_reference_exploits(repo_root),
        check_reference_fix_inventory(repo_root),
        check_patches_apply(repo_root),
        check_aml3_patch_scope(repo_root),
        check_aml3_patch_blocks_graph_leak(repo_root),
        check_aml3_patch_anti_coarse_fix(repo_root),
        check_docs(repo_root),
        check_makefile_wave26_gate(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_reference_exploits(repo_root: Path) -> dict[str, Any]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    exploit_files = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    missing = [name for name in EXPECTED_EXPLOITS if name not in exploit_files]
    extra = [name for name in exploit_files if name not in EXPECTED_EXPLOITS]
    ok = exploit_files == sorted(EXPECTED_EXPLOITS)
    return {
        "name": "wave26-five-reference-exploits-still-present",
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
		"name": "wave26-reference-fix-artifacts-present",
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
		"name": "wave26-reference-patches-apply-cleanly",
        "path": "fixes/sentinel_aml",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_aml3_patch_scope(repo_root: Path) -> dict[str, Any]:
    text = aml3_patch_text(repo_root)
    targets = patch_targets(text)
    unexpected = [target for target in targets if target not in AML3_ALLOWED_PATCH_TARGETS]
    missing_targets = [target for target in AML3_ALLOWED_PATCH_TARGETS if target not in targets]
    missing_markers = [marker for marker in AML3_PATCH_REQUIRED_MARKERS if marker not in text]
    ok = not unexpected and not missing_targets and not missing_markers
    return {
        "name": "wave26-aml3-patch-scope-and-public-graph-projection",
        "path": AML3_PATCH,
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"unexpected_targets={unexpected} missing_targets={missing_targets} missing_markers={missing_markers}",
    }


def check_aml3_patch_blocks_graph_leak(repo_root: Path) -> dict[str, Any]:
    text = aml3_patch_text(repo_root)
    added = added_lines(text)
    removed = removed_lines(text)
    missing_removals = [marker for marker in AML3_REQUIRED_REMOVALS if marker not in removed]
    forbidden_added = [marker for marker in AML3_FORBIDDEN_ADDED_MARKERS if marker.lower() in added.lower()]
    exploit = read(repo_root, "sploits/sentinel_aml/aml_related_graph.py")
    exploit_markers = [
        marker
		for marker in ("assessment_summary", "/api/graph/entities/{quoted_hint}/edd-summaries", "flag-like token not found")
        if marker not in exploit
    ]
    ok = not missing_removals and not forbidden_added and not exploit_markers
    return {
        "name": "wave26-aml3-exploit-blocked-by-public-graph-edd-summaries",
        "path": f"{AML3_PATCH} sploits/sentinel_aml/aml_related_graph.py",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"missing_removals={missing_removals} forbidden_added={forbidden_added} exploit_markers={exploit_markers}",
    }


def check_aml3_patch_anti_coarse_fix(repo_root: Path) -> dict[str, Any]:
    text = aml3_patch_text(repo_root)
    added = added_lines(text)
    removed = removed_lines(text)
    coarse_removals = [marker for marker in AML3_COARSE_REMOVAL_MARKERS if marker in removed and marker not in added]
    missing_added = [marker for marker in AML3_REQUIRED_ANTI_COARSE_MARKERS if marker not in text]
    ok = not coarse_removals and not missing_added
    return {
        "name": "wave26-aml3-anti-coarse-fix-preserves-graph-and-owner-edd-apis",
        "path": AML3_PATCH,
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"coarse_removals={coarse_removals} missing_added={missing_added}",
    }


def check_docs(repo_root: Path) -> dict[str, Any]:
    missing: list[str] = []
    for marker in README_REQUIRED_MARKERS:
        if marker not in read(repo_root, FIX_README):
            missing.append(f"{FIX_README}: {marker}")
    for marker in HANDOFF_T01_REQUIRED_MARKERS:
        if marker not in read(repo_root, AML3_HANDOFF_T01):
            missing.append(f"{AML3_HANDOFF_T01}: {marker}")
    for marker in HANDOFF_T02_REQUIRED_MARKERS:
        if marker not in read(repo_root, AML3_HANDOFF_T02):
            missing.append(f"{AML3_HANDOFF_T02}: {marker}")
    for marker in HANDOFF_T03_REQUIRED_MARKERS:
        if marker not in read(repo_root, AML3_HANDOFF_T03):
            missing.append(f"{AML3_HANDOFF_T03}: {marker}")
    return {
        "name": "wave26-docs-and-handoffs-present",
        "path": "fixes/sentinel_aml/README.md docs/wave_reports",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def check_makefile_wave26_gate(repo_root: Path) -> dict[str, Any]:
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
        details.append(f"forbidden unbounded Wave 26 lines: {forbidden}")
    if missing_helper:
        details.append(f"missing package-by-package Go release test runner: {missing_helper}")
    return {
        "name": "wave26-make-target-runs-full-gate",
        "path": "Makefile",
        "status": "pass" if ok else "fail",
        "message": "; ".join(details),
    }


def aml3_patch_text(repo_root: Path) -> str:
    return read(repo_root, AML3_PATCH)


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
    result = validate_wave26_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
