#!/usr/bin/env python3
"""Validate Wave 11 checker behavior and no-bypass guardrails."""

from __future__ import annotations

import importlib.util
import json
import os
import re
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
    "docs/wave_reports/wave_11_W11-T01_handoff.md",
    "docs/wave_reports/wave_11_W11-T02_handoff.md",
    "docs/wave_reports/wave_11_W11-T03_handoff.md",
    "docs/wave_reports/wave_11_W11-T04_handoff.md",
    "docs/wave_reports/wave_11_W11-T05_handoff.md",
    "docs/wave_reports/wave_11_validation_summary.md",
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
)
FORBIDDEN_EXPLOIT_NAMES = {
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
}


def validate_wave11_gate(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_checker_imports_and_endpoints(repo_root))
    checks.extend(check_checker_contract_runtime(repo_root))
    checks.extend(check_checker_tests(repo_root))
    checks.extend(check_no_exploit_or_fix_scripts(repo_root))
    checks.extend(check_docs_and_handoffs(repo_root))
    checks.extend(check_docs_status(repo_root))
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
                "name": "wave11-checker-no-db-or-internal-dependencies",
                "path": relative,
                "status": "pass" if path.is_file() and not forbidden else "fail",
                "message": "" if path.is_file() and not forbidden else f"forbidden markers: {forbidden}",
            }
        )
        checks.append(
            {
                "name": "wave11-checker-no-hidden-endpoints",
                "path": relative,
                "status": "pass" if path.is_file() and not hidden else "fail",
                "message": "" if path.is_file() and not hidden else f"hidden endpoints: {hidden}",
            }
        )

    get_section = source_section(combined, "def place1_get", "def _register_or_login")
    side_views = sorted(marker for marker in FORBIDDEN_SIDE_VIEW_ENDPOINTS if marker in get_section.lower())
    owner_note_get = 'f"/api/cases/{case_id}/notes"' in combined or 'f"/api/cases/{state.case_id}/notes"' in combined
    checks.append(
        {
            "name": "wave11-get-owner-note-only",
            "path": "checkers/sentinel_aml/checker_lib.py",
            "status": "pass" if get_section and owner_note_get and not side_views else "fail",
            "message": "" if get_section and owner_note_get and not side_views else f"owner_note_get={owner_note_get} side_views={side_views}",
        }
    )
    return checks


def check_checker_contract_runtime(repo_root: Path) -> list[dict[str, Any]]:
    checker_lib = load_checker_lib(repo_root)
    checks: list[dict[str, Any]] = []

    parse_failures: list[str] = []
    try:
        parsed = checker_lib.parse_checker_args(["checker.py", "put", "127.0.0.1", "FLAG{gate}", "1"])
        if parsed.action != "put" or parsed.place != checker_lib.PLACE_1 or parsed.flag != "FLAG{gate}":
            parse_failures.append("put parse mismatch")
    except Exception as exc:  # pragma: no cover - diagnostic path for gate output
        parse_failures.append(f"put parse raised {exc.__class__.__name__}")
    try:
        checker_lib.parse_checker_args(["checker.py", "get", "127.0.0.1", "state", "FLAG{gate}", "2"])
        parse_failures.append("place 2 get did not fail")
    except checker_lib.UnsupportedPlaceError:
        pass

    checks.append(
        {
            "name": "wave11-cli-action-place-parsing",
            "path": "checkers/sentinel_aml/checker_lib.py",
            "status": "pass" if not parse_failures else "fail",
            "message": "" if not parse_failures else "; ".join(parse_failures),
        }
    )

    secret = "wave11-gate-secret"
    flag = "FLAG{wave11-gate}"
    state = checker_lib.Place1PrivateState(
        schema_version=checker_lib.PRIVATE_STATE_SCHEMA_VERSION,
        service=checker_lib.SERVICE_NAME,
        store=checker_lib.PLACE_1_STORE,
        place=checker_lib.PLACE_1,
        customer_id=11,
        case_id=22,
        note_id=33,
        dedup_hint="dedup-hint",
        typology_hint="large-value-transfer",
        idempotency_key=checker_lib.derive_idempotency_key(flag, checker_lib.PLACE_1, secret),
    )
    private_state = checker_lib.encode_private_state(state, secret)
    public_attack_data = checker_lib.public_attack_data_for_place1(state)
    public_text = checker_lib.canonical_json(public_attack_data).lower()
    payload = json.loads(checker_lib._b64url_decode(private_state).decode("utf-8"))["payload"]
    leaked = sorted(
        marker
        for marker in [*PUBLIC_FORBIDDEN_VALUES, flag.lower(), private_state.lower()]
        if marker.lower() in public_text
    )
    state_has_credentials = bool({"username", "password", "token", "session"} & set(payload))
    shape_ok = set(public_attack_data) == {"service", "store", "case_id", "customer_id", "dedup_hint", "typology_hint"}
    round_trip_ok = checker_lib.decode_private_state(private_state, secret) == state
    checks.append(
        {
            "name": "wave11-pfr-public-private-separation",
            "path": "checkers/sentinel_aml/checker_lib.py",
            "status": "pass" if shape_ok and round_trip_ok and not leaked and not state_has_credentials else "fail",
            "message": ""
            if shape_ok and round_trip_ok and not leaked and not state_has_credentials
            else f"shape_ok={shape_ok} round_trip_ok={round_trip_ok} leaked={leaked} state_has_credentials={state_has_credentials}",
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
        "test_checker_cli_put_outputs_pfr_shape",
        "test_public_attack_data_excludes_credentials_and_private_material",
        "test_flag_is_sent_only_to_private_case_note_request",
        "test_successful_get_logs_in_and_reads_owner_notes_only",
        "test_wrong_flag_is_detected_before_http",
        "test_tampered_private_state_fails_before_http",
        "assert_no_side_views",
        "test_place2_get_remains_deferred",
        "test_place2_put_remains_deferred",
        "test_checker_imports_do_not_pull_db_or_go_internals",
    ]
    missing_markers = [marker for marker in required_markers if marker not in combined]
    return [
        {
            "name": "wave11-checker-regression-tests-present",
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
            "name": "wave11-no-exploit-or-fix-scripts",
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
                "name": "wave11-report-present",
                "path": relative,
                "status": "pass" if path.is_file() else "fail",
                "message": "" if path.is_file() else "required Wave 11 handoff is missing",
            }
        )

    docs = "\n".join(
        (repo_root / relative).read_text(encoding="utf-8")
        for relative in ("docs/08_checker_design.md", "docs/07_flag_stores.md", "docs/12_testing_strategy.md")
        if (repo_root / relative).is_file()
    )
    required_doc_markers = [
        "Wave 11",
        "GET /api/cases/{case_id}/notes",
        "POST /api/cases/{case_id}/notes",
        "Public attack data",
        "place 2",
        "scripts/check_wave11_gate.py",
        "No checker bypass",
    ]
    missing = [marker for marker in required_doc_markers if marker not in docs]
    checks.append(
        {
            "name": "wave11-docs-current-checker-contract",
            "path": "docs/08_checker_design.md docs/07_flag_stores.md docs/12_testing_strategy.md",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {missing}",
        }
    )
    return checks


def check_docs_status(repo_root: Path) -> list[dict[str, Any]]:
    paths = [
        "docs/13_roadmap.md",
        "docs/waves.md",
        "docs/source_of_truth_map.md",
        "docs/12_testing_strategy.md",
        "docs/15_risk_register.md",
        "docs/wave_reports/wave_11_validation_summary.md",
    ]
    docs = "\n".join(
        (repo_root / relative).read_text(encoding="utf-8")
        for relative in paths
        if (repo_root / relative).is_file()
    )
    required = [
        "| Wave 10 | complete |",
        "| Wave 11 | needs fixes |",
        "| W10 | Export redaction and network-room secure baselines | complete |",
        "| W11 | Checker PUT/GET for case notes | needs fixes |",
        "Wave 11 remains `needs fixes` until W11-T01, W11-T02, W11-T03, W11-T04, and W11-T05 pass orchestrator review",
        "Current branch validation authority lives in `scripts/check_wave11_gate.py` and `docs/wave_reports/wave_11_validation_summary.md`",
        "R-047",
        "R-048",
        "R-049",
        "Place 2 remains Wave 12",
        "CHECK/HAVOC remains Wave 13",
        "Planned vulnerability waves remain locked",
    ]
    missing = [marker for marker in required if marker not in docs]
    return [
        {
            "name": "wave11-doc-status-and-authority",
            "path": "docs/13_roadmap.md docs/waves.md docs/source_of_truth_map.md docs/12_testing_strategy.md docs/15_risk_register.md docs/wave_reports/wave_11_validation_summary.md",
            "status": "pass" if not missing else "fail",
            "message": "" if not missing else f"missing markers: {missing}",
        }
    ]


def check_makefile(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "Makefile"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    required = [
        "wave11-gate",
        "scripts/check_wave11_gate.py",
        "python -B -m unittest discover -s tests -p \"test_*.py\"",
        "GOFLAGS=-mod=vendor",
        "GOCACHE=$(CURDIR)/.gocache",
        "APPDATA=$(CURDIR)/.appdata",
        "go test ./...",
        "go vet ./...",
        "scripts/validate_forcad_config.py",
    ]
    missing = [marker for marker in required if marker not in text]
    return [
        {
            "name": "wave11-make-target-present",
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
    spec = importlib.util.spec_from_file_location("wave11_checker_lib", checker_path)
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
    result = validate_wave11_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
