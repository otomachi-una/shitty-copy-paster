#!/usr/bin/env python3
"""Validate Wave 13 CHECK/HAVOC framework behavior and guardrails."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


CHECKER_FILES = [
    "checkers/sentinel_aml/checker.py",
    "checkers/sentinel_aml/checker_lib.py",
]
CHECKER_TESTS = [
    "tests/test_checker_foundation.py",
    "tests/test_checker_check_workflow.py",
    "tests/test_checker_put_workflow.py",
    "tests/test_checker_get_workflow.py",
]
NO_EXPLOIT_ALLOWED_DIRS = (
    "sploits/sentinel_aml",
    "fixes/sentinel_aml",
)
ALLOWED_PLACEHOLDER_FILES = {"README.md"}
PRODUCTION_SCAN_DIRS = ("cmd", "internal", "checkers", "migrations")
PRODUCTION_SCAN_FILES = ("config.yml", "docker-compose.yml")
PRODUCTION_SCAN_SUFFIXES = {".go", ".py", ".sql", ".yml", ".yaml", ".toml", ".sh", ".ps1"}
FORBIDDEN_CHECKER_MARKERS = (
    "psycopg",
    "psycopg2",
    "asyncpg",
    "sqlite3",
    "sqlalchemy",
    "postgresql://",
    "postgres://",
    "database/sql",
    "sentinel-aml/internal",
    "sentinel_aml/internal",
    "internal/",
    "internal\\",
)
FORBIDDEN_ENDPOINTS = (
    "/api/checker",
    "/api/attack-data",
    "/api/public",
    "/api/debug",
    "/api/admin",
    "/debug",
    "/admin",
)
FORBIDDEN_SIDE_VIEW_ENDPOINTS = (
    "/api/graph",
    "/api/exports",
    "/api/network",
    "/timeline",
    "/duplicates",
    "merge-preview",
)
FORBIDDEN_VULNERABLE_MARKERS = (
    "vulnerable",
    "vulnerability_enabled",
    "exploit_mode",
    "aml_1",
    "aml_2",
    "aml_3",
    "aml_4",
    "aml_5",
    "leak_private",
    "insecure_variant",
    "reference_fix_enabled",
)


def validate_wave13_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_checker_imports_and_endpoints(repo_root))
    checks.extend(check_check_framework_runtime(repo_root))
    checks.extend(check_checker_tests(repo_root))
    checks.extend(check_no_early_exploit_or_fix_scripts(repo_root))
    checks.extend(check_no_vulnerable_behavior_markers(repo_root))
    checks.extend(check_makefile_wave13_gate(repo_root))
    checks.extend(check_docs(repo_root))
    checks.extend(check_external_validator(repo_root, "forcad-config", "scripts/validate_forcad_config.py", "validate_config"))
    return {"status": aggregate_status(checks), "checks": checks}


def check_checker_imports_and_endpoints(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    combined = ""
    for relative in CHECKER_FILES:
        path = repo_root / relative
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        combined += "\n" + text
        lowered = text.lower()
        forbidden = sorted(marker for marker in FORBIDDEN_CHECKER_MARKERS if marker in lowered)
        hidden = sorted(marker for marker in FORBIDDEN_ENDPOINTS if marker in lowered)
        checks.append(
            {
                "name": "wave13-checker-no-db-or-internal-dependencies",
                "path": relative,
                "status": "pass" if path.is_file() and not forbidden else "fail",
                "message": "" if path.is_file() and not forbidden else f"forbidden markers: {forbidden}",
            }
        )
        checks.append(
            {
                "name": "wave13-checker-no-hidden-endpoints",
                "path": relative,
                "status": "pass" if path.is_file() and not hidden else "fail",
                "message": "" if path.is_file() and not hidden else f"hidden endpoints: {hidden}",
            }
        )

    place1_get = source_section(combined, "def place1_get", "def place2_put")
    place2_get = source_section(combined, "def place2_get", "def _register_or_login")
    side_views = sorted(marker for marker in FORBIDDEN_SIDE_VIEW_ENDPOINTS if marker in (place1_get + place2_get).lower())
    checks.append(
        {
            "name": "wave13-put-get-owner-views-preserved",
            "path": "checkers/sentinel_aml/checker_lib.py",
            "status": "pass" if place1_get and place2_get and not side_views else "fail",
            "message": "" if place1_get and place2_get and not side_views else f"side_views={side_views}",
        }
    )
    return checks


def check_check_framework_runtime(repo_root: Path) -> list[dict[str, Any]]:
    checker_lib = load_module(repo_root / "checkers" / "sentinel_aml" / "checker_lib.py", "wave13_checker_lib")
    checker = load_checker(repo_root, checker_lib)
    checks: list[dict[str, Any]] = []

    failures: list[str] = []
    if "health" not in checker_lib.DEFAULT_CHECK_SUBCHECKS:
        failures.append("health missing from default subchecks")
    for name in (
        "check_basic",
        "check_case_notes",
        "check_dedup",
        "check_audit",
        "check_graph",
        "check_export",
        "check_network_room",
        "check_retention",
    ):
        if name not in checker_lib.DEFAULT_CHECK_SUBCHECKS:
            failures.append(f"{name} missing from default subchecks")
    registry = checker_lib.check_subchecks()
    for name in (
        "health",
        "check_basic",
        "check_case_notes",
        "check_dedup",
        "check_audit",
        "check_graph",
        "check_export",
        "check_network_room",
        "check_retention",
    ):
        if name not in registry:
            failures.append(f"{name} missing from registry")
    for action in ("check", "havoc"):
        try:
            parsed = checker_lib.parse_checker_args(["checker.py", action, "127.0.0.1"])
            if parsed.action != action:
                failures.append(f"{action} parsed as {parsed.action}")
        except Exception as exc:  # pragma: no cover - diagnostic path for gate output
            failures.append(f"{action} raised {exc.__class__.__name__}")
    for argv in (
        ["checker.py", "putnoise", "127.0.0.1", "gate-seed"],
        ["checker.py", "getnoise", "127.0.0.1", "noise-state"],
    ):
        try:
            parsed = checker_lib.parse_checker_args(argv)
            if parsed.action != argv[1]:
                failures.append(f"{argv[1]} parsed as {parsed.action}")
        except Exception as exc:  # pragma: no cover - diagnostic path for gate output
            failures.append(f"{argv[1]} raised {exc.__class__.__name__}")
    checks.append(
        {
            "name": "wave13-check-havoc-dispatch-runtime",
            "path": "checkers/sentinel_aml/checker_lib.py",
            "status": "pass" if not failures else "fail",
            "message": "" if not failures else "; ".join(failures),
        }
    )

    redaction_failures: list[str] = []

    def leaky(_client: Any, _secret: str, _context: Any) -> None:
        raise checker_lib.ServiceMumbleError("token=owner-token password=owner-password FLAG{gate-secret} private_state=encoded")

    try:
        checker_lib.run_check_subchecks(
            checker_lib.SentinelAMLClient("example.test"),
            ["leaky"],
            "gate-secret",
            registry={"leaky": checker_lib.CheckSubcheck("leaky", "leaky", leaky)},
        )
        redaction_failures.append("leaky subcheck did not fail")
    except checker_lib.CheckFailedError as exc:
        message = str(exc)
        for sensitive in ("owner-token", "owner-password", "FLAG{gate-secret}", "encoded"):
            if sensitive in message:
                redaction_failures.append(f"leaked {sensitive}")
    try:
        checker_lib.run_check_subchecks(checker_lib.SentinelAMLClient("example.test"), ["missing"], "gate-secret", registry={})
        redaction_failures.append("unsupported subcheck did not fail")
    except checker_lib.CheckFailedError as exc:
        if exc.exit_code != checker_lib.EXIT_MUMBLE:
            redaction_failures.append("unsupported subcheck exit code mismatch")
    checks.append(
        {
            "name": "wave13-check-failure-redaction-and-classification",
            "path": "checkers/sentinel_aml/checker_lib.py",
            "status": "pass" if not redaction_failures else "fail",
            "message": "" if not redaction_failures else "; ".join(redaction_failures),
        }
    )

    checker_source = (repo_root / "checkers" / "sentinel_aml" / "checker.py").read_text(encoding="utf-8")
    source_markers = ["run_check(parsed.host)", "run_havoc(parsed.host)", "safe_error_message(exc)"]
    missing = [marker for marker in source_markers if marker not in checker_source]
    checks.append(
        {
            "name": "wave13-checker-entrypoint-uses-framework",
            "path": "checkers/sentinel_aml/checker.py",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {missing}",
        }
    )
    return checks


def check_checker_tests(repo_root: Path) -> list[dict[str, Any]]:
    combined = ""
    missing_files: list[str] = []
    for relative in CHECKER_TESTS:
        path = repo_root / relative
        if not path.is_file():
            missing_files.append(relative)
            continue
        combined += "\n" + path.read_text(encoding="utf-8")
    required_markers = [
        "test_check_dispatch_runs_named_subchecks",
        "test_unsupported_subcheck_fails_mumble",
        "test_subcheck_failure_messages_are_independent_and_redacted",
        "test_default_check_uses_basic_notes_edd_dedup_audit_and_graph_routes",
        "test_checker_cli_check_outputs_ok_and_uses_dispatcher",
        "test_havoc_cli_uses_same_safe_framework",
        "test_check_cli_errors_do_not_print_sensitive_strings",
        "test_check_dedup_fails_when_candidate_is_missing",
        "test_check_dedup_rejects_private_fields_in_merge_preview",
        "test_check_case_notes_does_not_read_foreign_case_body",
        "test_check_audit_timeline_has_event_but_no_raw_private_body",
        "test_check_audit_rejects_raw_private_body_in_timeline",
        "test_check_audit_missing_module_fails_closed",
        "test_check_graph_returns_public_metadata_only",
        "test_check_graph_rejects_private_fields",
        "test_check_graph_missing_module_fails_closed",
        "test_check_export_creates_and_retrieves_redacted_bundle",
        "test_check_export_disabled_fails_closed",
        "test_check_export_rejects_private_fields",
        "test_check_network_room_summary_and_dossier_public_shape",
        "test_check_network_room_disabled_fails_closed",
        "test_check_network_room_missing_materialized_room_fails_closed",
        "test_check_network_room_rejects_private_fields",
        "test_putnoise_public_data_contains_no_credentials_or_flags",
        "test_noise_does_not_write_flags_to_checker_flag_stores",
        "test_getnoise_verifies_encoded_noise_state",
        "test_putnoise_cli_outputs_noise_shape",
        "test_noise_state_round_trip",
        "test_noise_state_tamper_rejected",
        "test_noise_public_data_excludes_credentials_flags_and_private_material",
        "test_retention_sensitive_table_list_matches_architecture",
        "test_retention_smoke_rejects_premature_physical_delete",
        "test_place1_put_full_successful_route_sequence",
        "test_place2_put_full_successful_route_sequence",
        "test_successful_get_logs_in_and_reads_owner_notes_only",
        "test_successful_place2_get_logs_in_before_owner_edd",
    ]
    missing_markers = [marker for marker in required_markers if marker not in combined]
    return [
        {
            "name": "wave13-checker-framework-tests-present",
            "path": "tests/test_checker_*workflow.py",
            "status": "pass" if not missing_files and not missing_markers else "fail",
            "message": "" if not missing_files and not missing_markers else f"missing_files={missing_files} missing_markers={missing_markers}",
        }
    ]


def check_no_early_exploit_or_fix_scripts(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for relative in NO_EXPLOIT_ALLOWED_DIRS:
        base = repo_root / relative
        files = []
        if base.is_dir():
            files = sorted(
                str(path.relative_to(base).as_posix())
                for path in base.rglob("*")
                if path.is_file() and path.name not in ALLOWED_PLACEHOLDER_FILES
            )
        checks.append(
            {
                "name": "wave13-no-early-exploit-or-fix-scripts",
                "path": relative,
                "status": "pass" if base.is_dir() and not files else "fail",
                "message": "" if base.is_dir() and not files else f"unexpected files: {files}",
            }
        )
    return checks


def check_no_vulnerable_behavior_markers(repo_root: Path) -> list[dict[str, Any]]:
    findings: list[str] = []
    for path in iter_production_files(repo_root):
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        hits = sorted(marker for marker in FORBIDDEN_VULNERABLE_MARKERS if marker in text)
        if hits:
            findings.append(f"{path.relative_to(repo_root).as_posix()}: {hits}")
    return [
        {
            "name": "wave13-no-vulnerable-behavior-yet",
            "path": "cmd internal checkers migrations config.yml docker-compose.yml",
            "status": "pass" if not findings else "fail",
            "message": "" if not findings else "; ".join(findings),
        }
    ]


def iter_production_files(repo_root: Path):
    for dirname in PRODUCTION_SCAN_DIRS:
        base = repo_root / dirname
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in PRODUCTION_SCAN_SUFFIXES and not path.name.endswith("_test.go"):
                yield path
    for relative in PRODUCTION_SCAN_FILES:
        path = repo_root / relative
        if path.is_file():
            yield path


def check_makefile_wave13_gate(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "Makefile"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    target = source_section(text, "wave13-gate:", "competition-matrix-gate:")
    required = [
        'python -B -m unittest discover -s tests -p "test_checker_*.py"',
        'python -B -m unittest discover -s tests -p "test_wave13_gate.py"',
        "$(GO_OFFLINE_ENV) go test ./...",
        "$(GO_OFFLINE_ENV) go vet ./...",
        "python -B scripts/check_docs_tree.py",
        "python -B scripts/check_wave13_gate.py",
        "python -B scripts/validate_forcad_config.py",
    ]
    missing = [marker for marker in required if marker not in target]
    return [
        {
            "name": "wave13-make-target-runs-full-gate",
            "path": "Makefile",
            "status": "pass" if target and not missing else "fail",
            "message": "" if target and not missing else f"missing markers: {missing}",
        }
    ]


def check_docs(repo_root: Path) -> list[dict[str, Any]]:
    docs = {
        "docs/08_checker_design.md": (repo_root / "docs" / "08_checker_design.md").read_text(encoding="utf-8"),
        "docs/12_testing_strategy.md": (repo_root / "docs" / "12_testing_strategy.md").read_text(encoding="utf-8"),
    }
    required = {
        "docs/08_checker_design.md": [
            "Wave 13 CHECK/HAVOC Framework",
            "DEFAULT_CHECK_SUBCHECKS",
            "check_basic",
            "check_case_notes",
            "check_dedup",
            "check_audit",
            "check_graph",
            "check_export",
            "check_network_room",
            "check_retention",
            "putnoise",
            "getnoise",
            "safe_error_message",
        ],
        "docs/12_testing_strategy.md": [
            "Wave 13 CHECK/HAVOC Framework Gate",
            "scripts/check_wave13_gate.py",
            "make wave13-gate",
            "test_checker_check_workflow.py",
            "check_basic",
            "check_case_notes",
            "check_dedup",
            "check_audit",
            "check_graph",
            "check_export",
            "check_network_room",
            "check_retention",
            "putnoise",
            "getnoise",
            "exploit/reference-fix implementation files are still absent",
            "no current vulnerable",
            "CHECK must not reveal flags or credentials",
        ],
    }
    checks: list[dict[str, Any]] = []
    for relative, markers in required.items():
        missing = [marker for marker in markers if marker not in docs[relative]]
        checks.append(
            {
                "name": "wave13-docs-check-framework",
                "path": relative,
                "status": "pass" if not missing else "fail",
                "message": "" if not missing else f"missing markers: {missing}",
            }
        )
    return checks


def check_external_validator(repo_root: Path, name: str, script_path: str, function_name: str) -> list[dict[str, Any]]:
    path = repo_root / script_path
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        return [{"name": name, "path": script_path, "status": "fail", "message": "validator unavailable"}]
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = getattr(module, function_name)(repo_root / "config.yml")
    return [{"name": name, "path": script_path, "status": "pass" if not result else "fail", "message": "; ".join(result)}]


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{path} is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_checker(repo_root: Path, checker_lib: Any) -> Any:
    sys.modules["checker_lib"] = checker_lib
    return load_module(repo_root / "checkers" / "sentinel_aml" / "checker.py", "wave13_checker")


def source_section(source: str, start_marker: str, end_marker: str) -> str:
    start = source.find(start_marker)
    if start < 0:
        return ""
    end = source.find(end_marker, start)
    if end < 0:
        return source[start:]
    return source[start:end]


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave13_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
