#!/usr/bin/env python3
"""Validate Wave 12 multi-place checker behavior and guardrails."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any


CHECKER_FILES = [
    "checkers/sentinel_aml/checker.py",
    "checkers/sentinel_aml/checker_lib.py",
]
CHECKER_TESTS = [
    "tests/test_checker_foundation.py",
    "tests/test_checker_put_workflow.py",
    "tests/test_checker_get_workflow.py",
]
EXPECTED_WAVE_REPORTS = [
    "docs/wave_reports/wave_12_W12-T01_handoff.md",
    "docs/wave_reports/wave_12_W12-T02_handoff.md",
    "docs/wave_reports/wave_12_W12-T03_handoff.md",
    "docs/wave_reports/wave_12_W12-T04_handoff.md",
    "docs/wave_reports/wave_12_review.md",
]
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
PUBLIC_FORBIDDEN_VALUES = (
    "username",
    "password",
    "token",
    "session",
    "flag",
    "checker_secret",
    "private_state",
    "private state",
    "confidential_comment",
)
FORBIDDEN_EXPLOIT_NAMES = {
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
}


def validate_wave12_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_checker_imports_and_endpoints(repo_root))
    checks.extend(check_checker_contract_runtime(repo_root))
    checks.extend(check_checker_tests(repo_root))
    checks.extend(check_no_exploit_or_fix_scripts(repo_root))
    checks.extend(check_docs_and_handoffs(repo_root))
    checks.extend(check_makefile(repo_root))
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
                "name": "wave12-checker-no-db-or-internal-dependencies",
                "path": relative,
                "status": "pass" if path.is_file() and not forbidden else "fail",
                "message": "" if path.is_file() and not forbidden else f"forbidden markers: {forbidden}",
            }
        )
        checks.append(
            {
                "name": "wave12-checker-no-hidden-endpoints",
                "path": relative,
                "status": "pass" if path.is_file() and not hidden else "fail",
                "message": "" if path.is_file() and not hidden else f"hidden endpoints: {hidden}",
            }
        )

    place1_get = source_section(combined, "def place1_get", "def place2_put")
    place2_get = source_section(combined, "def place2_get", "def _register_or_login")
    side_views = sorted(marker for marker in FORBIDDEN_SIDE_VIEW_ENDPOINTS if marker in (place1_get + place2_get).lower())
    owner_note_get = 'f"/api/cases/{case_id}/notes"' in combined or 'f"/api/cases/{state.case_id}/notes"' in combined
    owner_edd_get = 'f"/api/customers/{customer_id}/edd"' in combined or 'f"/api/customers/{state.customer_id}/edd"' in combined
    checks.append(
        {
            "name": "wave12-get-owner-views-only",
            "path": "checkers/sentinel_aml/checker_lib.py",
            "status": "pass" if place1_get and place2_get and owner_note_get and owner_edd_get and not side_views else "fail",
            "message": ""
            if place1_get and place2_get and owner_note_get and owner_edd_get and not side_views
            else f"owner_note_get={owner_note_get} owner_edd_get={owner_edd_get} side_views={side_views}",
        }
    )
    return checks


def check_checker_contract_runtime(repo_root: Path) -> list[dict[str, Any]]:
    checker_lib = load_checker_lib(repo_root)
    checks: list[dict[str, Any]] = []

    parse_failures: list[str] = []
    for action, argv, expected_place in (
        ("put1", ["checker.py", "put", "127.0.0.1", "FLAG{gate-p1}", "1"], checker_lib.PLACE_1),
        ("get1", ["checker.py", "get", "127.0.0.1", "state", "FLAG{gate-p1}", "1"], checker_lib.PLACE_1),
        ("put2", ["checker.py", "put", "127.0.0.1", "FLAG{gate-p2}", "2"], checker_lib.PLACE_2),
        ("get2", ["checker.py", "get", "127.0.0.1", "state", "FLAG{gate-p2}", "2"], checker_lib.PLACE_2),
    ):
        try:
            parsed = checker_lib.parse_checker_args(argv)
            if parsed.place != expected_place:
                parse_failures.append(f"{action} place mismatch")
        except Exception as exc:  # pragma: no cover - diagnostic path for gate output
            parse_failures.append(f"{action} raised {exc.__class__.__name__}")
    try:
        checker_lib.parse_checker_args(["checker.py", "put", "127.0.0.1", "FLAG{gate}", "3"])
        parse_failures.append("unknown place did not fail")
    except checker_lib.UnsupportedPlaceError:
        pass
    checks.append(
        {
            "name": "wave12-cli-action-place-parsing",
            "path": "checkers/sentinel_aml/checker_lib.py",
            "status": "pass" if not parse_failures else "fail",
            "message": "" if not parse_failures else "; ".join(parse_failures),
        }
    )

    secret = "wave12-gate-secret"
    p1_flag = "FLAG{wave12-gate-p1}"
    p2_flag = "FLAG{wave12-gate-p2}"
    try:
        p1_idempotency_key = checker_lib.derive_idempotency_key(p1_flag, checker_lib.PLACE_1, secret)
        p2_idempotency_key = checker_lib.derive_idempotency_key(p2_flag, checker_lib.PLACE_2, secret)
    except Exception as exc:  # pragma: no cover - diagnostic path for gate output
        checks.append(
            {
                "name": "wave12-pfr-public-private-separation",
                "path": "checkers/sentinel_aml/checker_lib.py",
                "status": "fail",
                "message": f"state construction raised {exc.__class__.__name__}",
            }
        )
        return checks

    p1_state = checker_lib.Place1PrivateState(
        schema_version=checker_lib.PRIVATE_STATE_SCHEMA_VERSION,
        service=checker_lib.SERVICE_NAME,
        store=checker_lib.PLACE_1_STORE,
        place=checker_lib.PLACE_1,
        customer_id=11,
        case_id=22,
        note_id=33,
        dedup_hint="dedup-hint",
        typology_hint="large-value-transfer",
        idempotency_key=p1_idempotency_key,
    )
    p2_state = checker_lib.Place2PrivateState(
        schema_version=checker_lib.PRIVATE_STATE_SCHEMA_VERSION,
        service=checker_lib.SERVICE_NAME,
        store=checker_lib.PLACE_2_STORE,
        place=checker_lib.PLACE_2,
        customer_id=44,
        edd_record_id=55,
        entity_hint="checker-p2-entity",
        typology_hint="enhanced-due-diligence",
        idempotency_key=p2_idempotency_key,
    )
    private1 = checker_lib.encode_private_state(p1_state, secret)
    private2 = checker_lib.encode_private_state(p2_state, secret)
    public1 = checker_lib.public_attack_data_for_place1(p1_state)
    public2 = checker_lib.public_attack_data_for_place2(p2_state)
    public_failures = public_data_failures(checker_lib, public1, p1_flag, p1_state, private1)
    public_failures.extend(public_data_failures(checker_lib, public2, p2_flag, p2_state, private2))
    shape_ok = set(public1) == {"service", "store", "case_id", "customer_id", "dedup_hint", "typology_hint"} and set(public2) == {
        "service",
        "store",
        "customer_id",
        "entity_hint",
        "typology_hint",
    }
    round_trip_ok = checker_lib.decode_private_state(private1, secret, expected_place=checker_lib.PLACE_1) == p1_state
    round_trip_ok = round_trip_ok and checker_lib.decode_private_state(private2, secret, expected_place=checker_lib.PLACE_2) == p2_state
    cross_place_rejected = False
    try:
        checker_lib.decode_private_state(private1, secret, expected_place=checker_lib.PLACE_2)
    except checker_lib.StateIntegrityError:
        try:
            checker_lib.decode_private_state(private2, secret, expected_place=checker_lib.PLACE_1)
        except checker_lib.StateIntegrityError:
            cross_place_rejected = True
    checks.append(
        {
            "name": "wave12-pfr-public-private-separation",
            "path": "checkers/sentinel_aml/checker_lib.py",
            "status": "pass" if shape_ok and round_trip_ok and cross_place_rejected and not public_failures else "fail",
            "message": ""
            if shape_ok and round_trip_ok and cross_place_rejected and not public_failures
            else f"shape_ok={shape_ok} round_trip_ok={round_trip_ok} cross_place_rejected={cross_place_rejected} leaks={public_failures}",
        }
    )
    return checks


def public_data_failures(checker_lib: Any, public_data: dict[str, Any], flag: str, state: Any, private_state: str) -> list[str]:
    serialized = checker_lib.canonical_json(public_data).lower()
    markers = [
        *PUBLIC_FORBIDDEN_VALUES,
        flag.lower(),
        private_state.lower(),
    ]
    return sorted(marker for marker in markers if marker in serialized)


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
        "test_place1_put_full_successful_route_sequence",
        "test_place2_put_full_successful_route_sequence",
        "test_place2_flag_is_sent_only_to_edd_confidential_comment_request",
        "test_successful_get_logs_in_and_reads_owner_notes_only",
        "test_successful_place2_get_logs_in_before_owner_edd",
        "test_place1_state_passed_to_place2_is_rejected",
        "test_place2_state_passed_to_place1_is_rejected",
        "test_public_attack_data_excludes_credentials_and_private_material",
        "test_place2_public_attack_data_omits_flag_and_credentials",
        "assert_no_side_views",
        "test_checker_imports_do_not_pull_db_or_go_internals",
    ]
    missing_markers = [marker for marker in required_markers if marker not in combined]
    return [
        {
            "name": "wave12-checker-regression-tests-present",
            "path": "tests/test_*checker*.py",
            "status": "pass" if not missing_files and not missing_markers else "fail",
            "message": "" if not missing_files and not missing_markers else f"missing_files={missing_files} missing_markers={missing_markers}",
        }
    ]


def check_no_exploit_or_fix_scripts(repo_root: Path) -> list[dict[str, Any]]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    scripts = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    planned = sorted(name for name in scripts if name in FORBIDDEN_EXPLOIT_NAMES)
    fix_scripts = sorted(
        str(path.relative_to(repo_root)).replace(os.sep, "/")
        for path in repo_root.rglob("*fix*.py")
        if "vendor" not in path.parts and "archive" not in path.parts
    )
    return [
        {
            "name": "wave12-no-exploit-or-fix-scripts",
            "path": "sploits/sentinel_aml",
            "status": "pass" if not scripts and not planned and not fix_scripts else "fail",
            "message": "" if not scripts and not planned and not fix_scripts else f"exploit_scripts={scripts} planned={planned} fix_scripts={fix_scripts}",
        }
    ]


def check_docs_and_handoffs(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for relative in EXPECTED_WAVE_REPORTS:
        path = repo_root / relative
        checks.append(
            {
                "name": "wave12-report-present",
                "path": relative,
                "status": "pass" if path.is_file() else "fail",
                "message": "" if path.is_file() else "required Wave 12 handoff is missing",
            }
        )
    docs_path = repo_root / "docs" / "12_testing_strategy.md"
    docs = docs_path.read_text(encoding="utf-8") if docs_path.is_file() else ""
    required_doc_markers = [
        "Wave 12 Multi-Place Checker Security Matrix",
        "scripts/check_wave12_gate.py",
        "make wave12-gate",
        "Place 1 remains `CaseNote.body`",
        "Place 2 is active as `EDDRecord.confidential_comment`",
        "CHECK/HAVOC remains Wave 13",
        "No planned vulnerability behavior",
    ]
    missing = [marker for marker in required_doc_markers if marker not in docs]
    checks.append(
        {
            "name": "wave12-docs-current-checker-contract",
            "path": "docs/12_testing_strategy.md",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {missing}",
        }
    )
    return checks


def check_makefile(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "Makefile"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    required = [
        "wave12-gate",
        "scripts/check_wave12_gate.py",
        "python -B -m unittest discover -s tests -p \"test_*checker*.py\"",
        "python -B -m unittest discover -s tests -p \"test_wave12_gate.py\"",
        "GOFLAGS=-mod=vendor",
        "go test ./...",
        "go vet ./...",
        "scripts/check_docs_tree.py",
        "scripts/validate_forcad_config.py",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave12-make-target-present",
            "path": "Makefile",
            "status": "pass" if path.is_file() and not missing else "fail",
            "message": "" if path.is_file() and not missing else f"missing markers: {missing}",
        }
    ]


def check_external_validator(repo_root: Path, name: str, script_path: str, function_name: str) -> list[dict[str, Any]]:
    path = repo_root / script_path
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        return [{"name": name, "path": script_path, "status": "fail", "message": "validator unavailable"}]
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    validator_arg = repo_root / "config.yml" if function_name == "validate_config" else repo_root
    result = getattr(module, function_name)(validator_arg)
    if isinstance(result, list):
        return [{"name": name, "path": script_path, "status": "pass" if not result else "fail", "message": "; ".join(result)}]
    return [{"name": name, "path": script_path, "status": result["status"], "message": "" if result["status"] == "pass" else json.dumps(result)}]


def load_checker_lib(repo_root: Path) -> Any:
    checker_path = repo_root / "checkers" / "sentinel_aml" / "checker_lib.py"
    spec = importlib.util.spec_from_file_location("wave12_checker_lib", checker_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("checker_lib.py is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
    result = validate_wave12_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
