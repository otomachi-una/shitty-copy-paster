#!/usr/bin/env python3
"""Validate Wave 01 repository scope and handoff readiness."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


EXPECTED_DIRS = [
    "cmd/aml-api",
    "cmd/aml-worker",
    "internal/httpapi",
    "internal/authz",
    "internal/config",
    "internal/logging",
    "checkers/sentinel_aml",
    "sploits/sentinel_aml",
    "scripts",
    "tests",
    "docs/wave_reports",
    "docs/agent_packets",
]

EXPECTED_FILES = [
    "go.mod",
    "README.md",
    "Makefile",
    "config.yml",
    "checkers/sentinel_aml/checker.py",
    "checkers/sentinel_aml/checker_lib.py",
    "checkers/sentinel_aml/requirements.txt",
    "sploits/sentinel_aml/README.md",
]

HANDOFF_REPORTS = [
    "docs/wave_reports/wave_01_W01-T01_handoff.md",
    "docs/wave_reports/wave_01_W01-T02_handoff.md",
    "docs/wave_reports/wave_01_W01-T03_handoff.md",
    "docs/wave_reports/wave_01_W01-F01_handoff.md",
    "docs/wave_reports/wave_01_W01-F02_handoff.md",
]

FORBIDDEN_PATHS = [
    "db/migrations",
    "internal/debug",
    "cmd/checker",
    "checkers/voltax",
    "sploits/voltax",
]

FORBIDDEN_CONFIG_REFERENCES = ["debug", "admin", "db", "database", "sploits", "exploit"]
FORBIDDEN_FIELD_NAMES = ["flag" + "_value", "secret" + "_for_checker"]
FORBIDDEN_IMPLEMENTATION_IMPORTS = ["requests", "urllib", "http.client", "psycopg", "psycopg2", "sqlite3"]
FORBIDDEN_ROUTE_MARKERS = ["/debug", "/admin", "/flag", "backdoor", "shell command"]
EXPECTED_FUTURE_EXPLOIT_NAMES = [
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
]
FORBIDDEN_GENERIC_EXPLOIT_NAMES = [
    "ex_case_note_body.py",
    "ex_edd_confidential_comment.py",
]


def validate_wave01_scope(repo_root: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    checks.extend(check_expected_paths(repo_root))
    checks.extend(check_handoff_reports(repo_root))
    checks.extend(check_config(repo_root))
    checks.extend(check_forbidden_paths(repo_root))
    checks.extend(check_sploit_directory(repo_root))
    checks.extend(check_sploit_readme(repo_root))
    checks.extend(check_checker_placeholder(repo_root))
    checks.extend(check_reserved_field_names(repo_root))
    checks.extend(check_implementation_strings(repo_root))

    return {"status": aggregate_status(checks), "checks": checks}


def check_expected_paths(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path in EXPECTED_DIRS:
        full_path = repo_root / path
        checks.append({"name": "expected-dir", "path": path, "status": "pass" if full_path.is_dir() else "fail"})
    for path in EXPECTED_FILES:
        full_path = repo_root / path
        checks.append({"name": "expected-file", "path": path, "status": "pass" if full_path.is_file() else "fail"})
    return checks


def check_handoff_reports(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path in HANDOFF_REPORTS:
        full_path = repo_root / path
        checks.append(
            {
                "name": "handoff-report",
                "path": path,
                "status": "pass" if full_path.is_file() else "pending",
                "message": "" if full_path.is_file() else "handoff report must exist before orchestrator close",
            }
        )
    return checks


def check_config(repo_root: Path) -> list[dict[str, Any]]:
    validator_path = repo_root / "scripts" / "validate_forcad_config.py"
    spec = importlib.util.spec_from_file_location("validate_forcad_config", validator_path)
    if spec is None or spec.loader is None:
        return [{"name": "forcad-config", "path": "config.yml", "status": "fail", "message": "validator unavailable"}]

    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)

    errors = validator.validate_config(repo_root / "config.yml")
    return [
        {
            "name": "forcad-config",
            "path": "config.yml",
            "status": "pass" if not errors else "fail",
            "message": "; ".join(errors),
        }
    ]


def check_forbidden_paths(repo_root: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path in FORBIDDEN_PATHS:
        full_path = repo_root / path
        checks.append(
            {
                "name": "forbidden-path",
                "path": path,
                "status": "fail" if full_path.exists() else "pass",
                "message": "out-of-scope path exists" if full_path.exists() else "",
            }
        )
    return checks


def check_sploit_directory(repo_root: Path) -> list[dict[str, Any]]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    checks: list[dict[str, Any]] = []
    python_files = sorted(path.name for path in sploit_dir.glob("*.py"))
    checks.append(
        {
            "name": "no-real-sploit-scripts",
            "path": "sploits/sentinel_aml",
            "status": "pass" if not python_files else "fail",
            "message": "" if not python_files else f"unexpected Python exploit files: {', '.join(python_files)}",
        }
    )

    executable_files: list[str] = []
    if sploit_dir.is_dir():
        for path in sploit_dir.iterdir():
            if path.name == "README.md":
                continue
            if path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                executable_files.append(path.name)

    checks.append(
        {
            "name": "no-executable-sploits",
            "path": "sploits/sentinel_aml",
            "status": "pass" if not executable_files else "fail",
            "message": "" if not executable_files else f"unexpected executable files: {', '.join(executable_files)}",
        }
    )
    return checks


def check_sploit_readme(repo_root: Path) -> list[dict[str, Any]]:
    readme_path = repo_root / "sploits" / "sentinel_aml" / "README.md"
    if not readme_path.is_file():
        return [
            {
                "name": "future-sploit-readme-contract",
                "path": "sploits/sentinel_aml/README.md",
                "status": "fail",
                "message": "sploit README is missing",
            }
        ]

    text = readme_path.read_text(encoding="utf-8")
    missing = [filename for filename in EXPECTED_FUTURE_EXPLOIT_NAMES if filename not in text]
    generic = [filename for filename in FORBIDDEN_GENERIC_EXPLOIT_NAMES if filename in text]
    status = "pass" if not missing and not generic else "fail"
    details = []
    if missing:
        details.append(f"missing future exploit names: {', '.join(missing)}")
    if generic:
        details.append(f"generic store names still present: {', '.join(generic)}")
    return [
        {
            "name": "future-sploit-readme-contract",
            "path": "sploits/sentinel_aml/README.md",
            "status": status,
            "message": "; ".join(details),
        }
    ]


def check_checker_placeholder(repo_root: Path) -> list[dict[str, Any]]:
    checker_files = [
        repo_root / "checkers" / "sentinel_aml" / "checker.py",
        repo_root / "checkers" / "sentinel_aml" / "checker_lib.py",
    ]
    checks: list[dict[str, Any]] = []
    for path in checker_files:
        text = path.read_text(encoding="utf-8")
        imported_forbidden = [name for name in FORBIDDEN_IMPLEMENTATION_IMPORTS if f"import {name}" in text or f"from {name}" in text]
        checks.append(
            {
                "name": "checker-placeholder-no-network-db",
                "path": str(path.relative_to(repo_root)).replace(os.sep, "/"),
                "status": "pass" if not imported_forbidden else "fail",
                "message": "" if not imported_forbidden else f"forbidden imports: {', '.join(imported_forbidden)}",
            }
        )

    checker_text = (repo_root / "checkers" / "sentinel_aml" / "checker.py").read_text(encoding="utf-8")
    checks.append(
        {
            "name": "checker-fails-closed",
            "path": "checkers/sentinel_aml/checker.py",
            "status": "pass" if "return 2" in checker_text and "Wave 11" in checker_text else "fail",
            "message": "checker placeholder must remain clearly not implemented until Wave 11",
        }
    )
    return checks


def check_reserved_field_names(repo_root: Path) -> list[dict[str, Any]]:
    hits: list[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file() or should_skip_file(repo_root, path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for field_name in FORBIDDEN_FIELD_NAMES:
            if field_name in text:
                hits.append(str(path.relative_to(repo_root)).replace(os.sep, "/"))
                break

    return [
        {
            "name": "reserved-field-names",
            "path": ".",
            "status": "pass" if not hits else "fail",
            "message": "" if not hits else f"reserved field names found in: {', '.join(sorted(hits))}",
        }
    ]


def check_implementation_strings(repo_root: Path) -> list[dict[str, Any]]:
    files = [
        repo_root / "config.yml",
        *sorted((repo_root / "cmd").rglob("*.go")),
        *sorted((repo_root / "internal").rglob("*.go")),
        repo_root / "checkers" / "sentinel_aml" / "checker.py",
    ]
    hits: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8").lower()
        if any(marker in text for marker in FORBIDDEN_ROUTE_MARKERS):
            hits.append(str(path.relative_to(repo_root)).replace(os.sep, "/"))

    return [
        {
            "name": "no-debug-backdoor-routes",
            "path": "implementation-surface",
            "status": "pass" if not hits else "fail",
            "message": "" if not hits else f"forbidden route markers found in: {', '.join(hits)}",
        }
    ]


def should_skip_file(repo_root: Path, path: Path) -> bool:
    parts = path.relative_to(repo_root).parts
    return (
        ".git" in parts
        or "__pycache__" in parts
        or path.suffix in {".pyc", ".exe", ".test"}
        or path.name == "pasted-text.txt"
    )


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    statuses = {check["status"] for check in checks}
    if "fail" in statuses:
        return "fail"
    if "pending" in statuses:
        return "pending"
    return "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave01_scope(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
