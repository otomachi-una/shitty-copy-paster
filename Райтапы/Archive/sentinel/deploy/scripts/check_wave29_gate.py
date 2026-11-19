#!/usr/bin/env python3
"""Validate the full Sentinel AML A/D competition matrix gate."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


EXPECTED_EXPLOITS = (
    "sploits/sentinel_aml/aml_dedup_preview.py",
    "sploits/sentinel_aml/aml_audit_timeline.py",
    "sploits/sentinel_aml/aml_related_graph.py",
    "sploits/sentinel_aml/aml_export_redaction.py",
    "sploits/sentinel_aml/aml_network_room.py",
)
EXPECTED_PATCHES = (
    "fixes/sentinel_aml/aml_dedup_preview.patch",
    "fixes/sentinel_aml/aml_audit_timeline.patch",
    "fixes/sentinel_aml/aml_related_graph.patch",
    "fixes/sentinel_aml/aml_export_redaction.patch",
    "fixes/sentinel_aml/aml_network_room.patch",
)
VULNERABLE_TAGS = (
    "aml1_vulnerable",
    "aml2_vulnerable",
    "aml3_vulnerable",
    "aml4_vulnerable",
    "aml5_vulnerable",
)
VULNERABLE_TAG_COMMANDS = {
    "aml1_vulnerable": ("./internal/httpapi",),
    "aml2_vulnerable": ("./internal/httpapi",),
    "aml3_vulnerable": ("./internal/httpapi", "./internal/graph"),
    "aml4_vulnerable": ("./internal/httpapi", "./internal/exporting"),
    "aml5_vulnerable": ("./internal/httpapi", "./internal/networkroom"),
}
MAKE_TARGET = "wave29-gate"
GO_RUNNER = "scripts/run_go_release_tests.py"
VULNERABLE_PROFILE_RUNNER = "scripts/run_vulnerable_profile_tests.py"

CHECKER_REQUIRED_MARKERS = (
    ('checkers/sentinel_aml/checker_lib.py', 'PLACE_1_STORE = "CaseNote.body"'),
    ('checkers/sentinel_aml/checker_lib.py', 'PLACE_2_STORE = "EDDRecord.confidential_comment"'),
    ("checkers/sentinel_aml/checker_lib.py", "public attack data contains forbidden markers"),
    ("checkers/sentinel_aml/checker_lib.py", "run_check"),
    ("checkers/sentinel_aml/checker_lib.py", "network-room"),
    ("docs/01_ctf_contract.md", "Place 1: `CaseNote.body`"),
    ("docs/01_ctf_contract.md", "Place 2: `EDDRecord.confidential_comment`"),
    ("docs/08_checker_design.md", "CHECK/HAVOC"),
    ("docs/08_checker_design.md", "must not use hidden checker-only"),
)
CHECKER_FORBIDDEN_MARKERS = (
    "sqlite3",
    "psycopg",
    "database/sql",
    "sql.Open",
    "/api/debug",
    "/api/admin",
)
EXPLOIT_SIDE_VIEW_MARKERS = {
    "sploits/sentinel_aml/aml_dedup_preview.py": (
        "/api/cases/{source_case_id}/duplicates",
        "/api/cases/{source_case_id}/duplicates/{victim_case_id}/merge-preview",
        "match_explanation",
    ),
	"sploits/sentinel_aml/aml_audit_timeline.py": (
		"/api/entities/{entity_hint}/activity",
		"activity_narrative",
		"iter_activity_narrative_values",
	),
    "sploits/sentinel_aml/aml_related_graph.py": (
        "/api/graph/entities/{quoted_hint}/edd-summaries",
        "assessment_summary",
        "iter_assessment_summary_values",
    ),
    "sploits/sentinel_aml/aml_export_redaction.py": (
        "/api/disputes/{dispute_id}/export",
        "/api/exports/{export_id}",
        "linked_evidence",
    ),
    "sploits/sentinel_aml/aml_network_room.py": (
        "/api/network/rooms",
        "/api/network/rooms/{room_id}/join",
        "/api/network/rooms/{room_id}/dossier",
        "context_blocks",
        "evaluation_blocks",
    ),
}
EXPLOIT_FORBIDDEN_MARKERS = (
    "sqlite3",
    "psycopg",
    "database/sql",
    "sql.Open",
    "subprocess",
    "os.system",
    "exec(",
    "/api/debug",
    "/api/admin",
    "/api/cases/{case_id}/notes",
    "/api/customers/{customer_id}/edd",
)
FIX_EVIDENCE_CHECKS = (
    ("scripts/check_wave24_gate.py", "check_patch_scope"),
    ("scripts/check_wave24_gate.py", "check_patch_blocks_aml1_leak"),
    ("scripts/check_wave24_gate.py", "check_patch_anti_coarse_fix"),
    ("scripts/check_wave25_gate.py", "check_aml2_patch_scope"),
    ("scripts/check_wave25_gate.py", "check_aml2_patch_blocks_timeline_leak"),
    ("scripts/check_wave25_gate.py", "check_aml2_patch_anti_coarse_fix"),
    ("scripts/check_wave26_gate.py", "check_aml3_patch_scope"),
    ("scripts/check_wave26_gate.py", "check_aml3_patch_blocks_graph_leak"),
    ("scripts/check_wave26_gate.py", "check_aml3_patch_anti_coarse_fix"),
    ("scripts/check_wave27_gate.py", "check_aml4_patch_scope"),
    ("scripts/check_wave27_gate.py", "check_aml4_patch_blocks_export_leak"),
    ("scripts/check_wave27_gate.py", "check_aml4_patch_anti_coarse_fix"),
    ("scripts/check_wave28_gate.py", "check_aml5_patch_scope"),
    ("scripts/check_wave28_gate.py", "check_aml5_patch_blocks_network_room_leak"),
    ("scripts/check_wave28_gate.py", "check_aml5_patch_anti_coarse_fix"),
)
REFERENCE_FIX_EXPECTATIONS = {
	"fixes/sentinel_aml/aml_dedup_preview.patch": {
		"targets": ("internal/httpapi/dedup_profile_case_match.go", "internal/httpapi/dedup_profile_case_match_test.go"),
		"removed": ("casework.MatchEvidenceSourceReviewContext", "ResolveMatchEvidence"),
		"added": ("casework.PublicMatchEvidenceSources()", "TestCaseMatchPreviewUsesPublicEvidenceAsMatchExplanation"),
	},
	"fixes/sentinel_aml/aml_audit_timeline.patch": {
		"targets": ("internal/httpapi/audit_profile_detail.go", "internal/httpapi/audit_profile_detail_test.go"),
		"removed": ("return auditrepo.ActivityDetailCollaborator", '`"activity_detail_level":"collaborator_detail"`'),
		"added": ("return auditrepo.ActivityDetailRelated", '`"activity_detail_level":"related_view"`', '`"field":"restricted_field"`'),
	},
    "fixes/sentinel_aml/aml_related_graph.patch": {
        "targets": ("internal/graph/repository_entity_review.go", "internal/httpapi/graph_profile_entity_review_test.go"),
        "removed": ("policy := ExtendedAssessmentSummaryPolicy()", "TestEntityReviewGraphEDDSummariesIncludeAssessmentSummary"),
        "added": ("policy := GraphAssessmentSummaryPolicy()", "TestAML3FixedGraphEDDSummariesKeepAssessmentSummaryScoped", "assessment_summary"),
    },
    "fixes/sentinel_aml/aml_export_redaction.patch": {
        "targets": ("internal/exporting/export_profile_linked_case.go", "internal/httpapi/export_profile_linked_case_test.go"),
        "removed": ("appendExportSourceMaterials(bundle, linked.SourceMaterials, traversal.Root)",),
        "added": (
            "appendExportSourceMaterials(bundle, linked.SourceMaterials, traversal.Linked)",
            "AML-4 fixed dispute export missing public linked-case marker",
            "rootPrivateNote, linkedPrivateNote, rootEDDComment, linkedEDDComment",
        ),
    },
    "fixes/sentinel_aml/aml_network_room.patch": {
        "targets": (
            "internal/networkroom/dossier_profile_room_detail.go",
            "internal/httpapi/network_room_profile_detail_test.go",
        ),
        "removed": (
            "summary.ContextBlocks = boundedContextBlocks(c.ContextBlocks)",
            "summary.EvaluationBlocks = boundedEvaluationBlocks(c.EvaluationBlocks)",
        ),
        "added": (
            'boundedContextBlocks(c.ContextBlocks, "room_summary")',
            'boundedEvaluationBlocks(c.EvaluationBlocks, "room_summary")',
            "AML-5 fixed dossier missing expected public marker",
        ),
    },
}
REFERENCE_FIX_FORBIDDEN_ADDED_MARKERS = (
    "foreign_note_body",
    "private_notes",
    "linked_private_notes",
    "foreign_private_notes",
    "foreign_edd_comments",
    "confidential_comment",
    "note.Body",
    "case_notes",
    "edd_records",
    "assessment_blocks",
    "FindDuplicateCaseNarrativesForPreview",
    "DossierPrivateNote",
    "DossierEDDComment",
)
MAKE_REQUIRED_LINES = (
    '$(PYTHON) -B -m unittest discover -s tests -p "test_checker_*.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_wave29_gate.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_wave29_regression.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_run_go_release_tests.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_run_vulnerable_profile_tests.py"',
    "$(PYTHON) -B scripts/run_vulnerable_profile_tests.py --go $(GO) --package-timeout 120",
    "$(PYTHON) -B scripts/run_go_release_tests.py --go $(GO) --package-timeout 120",
    "$(GO_RELEASE_ENV) $(GO) vet ./...",
    "$(PYTHON) -B scripts/check_competition_matrix_gate.py",
    "$(PYTHON) -B scripts/check_wave29_gate.py",
    "$(PYTHON) -B scripts/check_wave29_regression.py --go $(GO) --python $(PYTHON)",
    "$(PYTHON) -B scripts/check_docs_tree.py",
    "$(PYTHON) -B scripts/validate_forcad_config.py",
    "$(PYTHON) -B scripts/check_archive_hygiene.py",
)
MAKE_FORBIDDEN_LINES = (
    "$(GO_RELEASE_ENV) $(GO) test ./...",
    "$(GO_OFFLINE_ENV) $(GO) test ./...",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml1_vulnerable ./...",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml2_vulnerable ./...",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml3_vulnerable ./...",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml4_vulnerable ./...",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml5_vulnerable ./...",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml1_vulnerable ./internal/httpapi",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml2_vulnerable ./internal/httpapi",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml3_vulnerable ./internal/httpapi ./internal/graph",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml4_vulnerable ./internal/httpapi ./internal/exporting",
    "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 -tags aml5_vulnerable ./internal/httpapi ./internal/networkroom",
)


def validate_wave29_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_competition_matrix(repo_root),
        check_checker_contract(repo_root),
        check_exploit_inventory_and_side_views(repo_root),
        check_all_patches_apply(repo_root),
        check_reference_fix_evidence(repo_root),
        check_vulnerable_profile_coverage(repo_root),
        check_makefile_wave29_gate(repo_root),
        check_wave29_docs(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_competition_matrix(repo_root: Path) -> dict[str, Any]:
    module = load_module(repo_root, "scripts/check_competition_matrix_gate.py")
    result = module.validate_competition_matrix_gate(repo_root)
    failures = [check["name"] for check in result["checks"] if check["status"] == "fail"]
    return {
        "name": "wave29-competition-matrix-all-cells-concrete",
        "path": "scripts/check_competition_matrix_gate.py",
        "status": "pass" if result["status"] == "pass" else "fail",
        "message": "" if not failures else f"failing matrix checks: {failures}",
    }


def check_checker_contract(repo_root: Path) -> dict[str, Any]:
    missing = [f"{relative}: {marker}" for relative, marker in CHECKER_REQUIRED_MARKERS if marker not in read(repo_root, relative)]
    findings: list[str] = []
    for path in (repo_root / "checkers" / "sentinel_aml").glob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        hits = [marker for marker in CHECKER_FORBIDDEN_MARKERS if marker.lower() in text.lower()]
        if hits:
            findings.append(f"{path.relative_to(repo_root).as_posix()}: {hits}")
    return {
        "name": "wave29-checker-two-place-pfr-and-no-db-debug-shortcuts",
        "path": "checkers/sentinel_aml docs/01_ctf_contract.md docs/08_checker_design.md",
        "status": "pass" if not missing and not findings else "fail",
        "message": "" if not missing and not findings else f"missing={missing} forbidden={findings}",
    }


def check_exploit_inventory_and_side_views(repo_root: Path) -> dict[str, Any]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    present = sorted(path.relative_to(repo_root).as_posix() for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    missing_files = [relative for relative in EXPECTED_EXPLOITS if relative not in present]
    extra_files = [relative for relative in present if relative not in EXPECTED_EXPLOITS]
    missing_markers: list[str] = []
    forbidden_hits: list[str] = []
    for relative, markers in EXPLOIT_SIDE_VIEW_MARKERS.items():
        text = read(repo_root, relative)
        missing_markers.extend(f"{relative}: {marker}" for marker in markers if marker not in text)
        hits = [marker for marker in EXPLOIT_FORBIDDEN_MARKERS if marker.lower() in text.lower()]
        if hits:
            forbidden_hits.append(f"{relative}: {hits}")
    ok = not missing_files and not extra_files and not missing_markers and not forbidden_hits
    return {
        "name": "wave29-exploits-exactly-five-and-side-view-only",
        "path": "sploits/sentinel_aml",
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"missing_files={missing_files} extra_files={extra_files} missing_markers={missing_markers} forbidden={forbidden_hits}",
    }


def check_all_patches_apply(repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    for relative in EXPECTED_PATCHES:
        if not (repo_root / relative).is_file():
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
            failures.append(f"{relative}: {exc}")
            continue
        if completed.returncode != 0:
            failures.append(f"{relative}: {(completed.stderr or completed.stdout).strip()}")
    return {
        "name": "wave29-all-five-reference-fixes-apply-cleanly",
        "path": "fixes/sentinel_aml",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_reference_fix_evidence(repo_root: Path) -> dict[str, Any]:
    failures: list[str] = []
    for relative, expectation in REFERENCE_FIX_EXPECTATIONS.items():
        text = read(repo_root, relative)
        targets = patch_targets(text)
        added = added_lines(text)
        removed = removed_lines(text)
        missing_targets = [target for target in expectation["targets"] if target not in targets]
        unexpected_targets = [target for target in targets if target not in expectation["targets"]]
        missing_removals = [marker for marker in expectation["removed"] if marker not in removed]
        missing_additions = [marker for marker in expectation["added"] if marker not in added]
        forbidden_additions = [marker for marker in REFERENCE_FIX_FORBIDDEN_ADDED_MARKERS if marker in added]
        if missing_targets or unexpected_targets or missing_removals or missing_additions or forbidden_additions:
            failures.append(
                f"{relative}: missing_targets={missing_targets} unexpected_targets={unexpected_targets} "
                f"missing_removals={missing_removals} missing_additions={missing_additions} "
                f"forbidden_added={forbidden_additions}"
            )
    return {
        "name": "wave29-reference-fix-scope-exploit-blocked-and-anti-coarse-evidence",
        "path": "fixes/sentinel_aml",
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_vulnerable_profile_coverage(repo_root: Path) -> dict[str, Any]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, MAKE_TARGET)
    runner = read(repo_root, VULNERABLE_PROFILE_RUNNER)
    missing_source = [
        f"internal/httpapi/{name}"
        for name in (
            "dedup_profile_case_match_test.go",
            "audit_profile_detail_test.go",
            "graph_profile_entity_review_test.go",
            "export_profile_linked_case_test.go",
            "network_room_profile_detail_test.go",
        )
        if not (repo_root / "internal" / "httpapi" / name).is_file()
    ]
    missing_commands: list[str] = []
    if "$(PYTHON) -B scripts/run_vulnerable_profile_tests.py --go $(GO) --package-timeout 120" not in target:
        missing_commands.append("wave29-gate: run_vulnerable_profile_tests.py")
    for tag, packages in VULNERABLE_TAG_COMMANDS.items():
        if tag not in runner:
            missing_commands.append(tag)
        missing_commands.extend(f"{tag}: {package}" for package in packages if package not in runner)
    return {
        "name": "wave29-vulnerable-profile-tests-covered-for-aml1-through-aml5",
        "path": "Makefile internal/httpapi",
        "status": "pass" if not missing_source and not missing_commands else "fail",
        "message": "" if not missing_source and not missing_commands else f"missing_source={missing_source} missing_commands={missing_commands}",
    }


def check_makefile_wave29_gate(repo_root: Path) -> dict[str, Any]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, MAKE_TARGET)
    missing = [line for line in MAKE_REQUIRED_LINES if line not in target]
    missing_pycompile = [
        relative
        for relative in EXPECTED_EXPLOITS
        if f"$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile {relative}" not in target
    ]
    missing_patch_checks = [
        relative
        for relative in EXPECTED_PATCHES
        if f"git apply --check --whitespace=error {relative}" not in target
    ]
    forbidden = [line for line in MAKE_FORBIDDEN_LINES if line in target]
    missing_runner = [relative for relative in (GO_RUNNER, VULNERABLE_PROFILE_RUNNER) if not (repo_root / relative).is_file()]
    ok = bool(target) and not missing and not missing_pycompile and not missing_patch_checks and not forbidden and not missing_runner
    return {
        "name": "wave29-make-target-runs-full-competition-matrix-gate",
        "path": "Makefile",
        "status": "pass" if ok else "fail",
        "message": ""
        if ok
        else f"missing={missing} missing_pycompile={missing_pycompile} missing_patch_checks={missing_patch_checks} forbidden={forbidden} missing_runner={missing_runner}",
    }


def check_wave29_docs(repo_root: Path) -> dict[str, Any]:
    required = {
        "docs/12_testing_strategy.md": (
            "Wave 29 Full Competition Matrix Gate",
            "Wave 29 End-to-End Regression Evidence",
            "does not mark final release readiness",
            "focused vulnerable-profile package tests",
            "all five reference fix patches",
        ),
        "docs/wave_reports/wave_29_W29-T01_handoff.md": (
            "W29-T01",
            "Full Competition Matrix Gate",
            "Ready for Orchestrator Review",
        ),
    }
    missing = [f"{relative}: {marker}" for relative, markers in required.items() for marker in markers if marker not in read(repo_root, relative)]
    return {
        "name": "wave29-testing-strategy-and-handoff-present",
        "path": "docs/12_testing_strategy.md docs/wave_reports/wave_29_W29-T01_handoff.md",
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing markers: {missing}",
    }


def load_module(repo_root: Path, relative: str):
    module_name = "wave29_" + re.sub(r"\W+", "_", relative)
    spec = importlib.util.spec_from_file_location(module_name, repo_root / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def patch_targets(text: str) -> list[str]:
    return re.findall(r"^\+\+\+ b/(.+)$", text, flags=re.MULTILINE)


def added_lines(text: str) -> str:
    return "\n".join(line[1:] for line in text.splitlines() if line.startswith("+") and not line.startswith("+++"))


def removed_lines(text: str) -> str:
    return "\n".join(line[1:] for line in text.splitlines() if line.startswith("-") and not line.startswith("---"))


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave29_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
