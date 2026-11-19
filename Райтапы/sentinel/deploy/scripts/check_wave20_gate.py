#!/usr/bin/env python3
"""Validate Wave 20 AML-2 reference exploit scope."""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any


EXPLOIT_PATH = "sploits/sentinel_aml/aml_audit_timeline.py"
EXPLOIT_README = "sploits/sentinel_aml/README.md"
HANDOFF_PATH = "docs/wave_reports/wave_20_W20-T01_handoff.md"
HANDOFF_T02_PATH = "docs/wave_reports/wave_20_W20-T02_handoff.md"
HANDOFF_F01_PATH = "docs/wave_reports/wave_20_W20-F01_handoff.md"
MAKE_TARGET = "wave20-gate"
EXPECTED_EXPLOITS = (
    "aml_audit_timeline.py",
    "aml_dedup_preview.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
    "aml_related_graph.py",
)
EXPECTED_FIXES = (
    "aml_audit_timeline.patch",
    "aml_dedup_preview.patch",
    "aml_export_redaction.patch",
    "aml_network_room.patch",
    "aml_related_graph.patch",
)
SCRIPT_REQUIRED_MARKERS = (
    "argparse",
    "urllib.request",
    "host",
    "port",
	"attack_info",
	"attack_data",
	"entity_hint",
	"/api/auth/register",
	"/api/auth/login",
	"/api/customers",
	"/api/entities/{entity_hint}/activity",
	"activity_narrative",
	"review_context_excerpt",
	"redacted",
	"extract_flag",
)
SCRIPT_CLI_MARKERS = (
    "def main(",
    "def parse_args(",
    "if __name__ == \"__main__\":",
    "raise SystemExit(main())",
)
FORBIDDEN_SCRIPT_MARKERS = (
    "psycopg",
    "sqlite3",
    "MySQLdb",
    "pymysql",
    "pg8000",
    "subprocess",
    "os.system",
    "popen",
    "DATABASE_URL",
    "SENTINEL_AML_CHECKER_SECRET",
    "checker_private",
    "private_state",
    "/api/debug",
    "/api/admin",
    "/debug",
    "/admin",
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "postgres://",
    "mysql://",
    "sqlite://",
    "/var/lib/postgresql",
    "pg_hba.conf",
    "/api/cases/{case_id}/notes",
    "/notes",
)
FORBIDDEN_ATTACK_DATA_SECRET_RE = re.compile(
    r"attack_data(?:\.get)?\([^)]*(?:password|token|session|private_state|checker)"
    r"|attack_data\[[^\]]*(?:password|token|session|private_state|checker)",
    re.IGNORECASE,
)
FORBIDDEN_IMPORTS = {
    "asyncpg",
    "MySQLdb",
    "mysql",
    "os",
    "pg8000",
    "psycopg",
    "psycopg2",
    "pymysql",
    "shlex",
    "sqlite3",
    "subprocess",
}
DOC_MARKERS = {
	EXPLOIT_README: ("aml_audit_timeline.py", "AML-2", "activity_narrative", "review context"),
    HANDOFF_PATH: ("Summary", "Implementation Details", "Ready for Orchestrator Review"),
    HANDOFF_T02_PATH: ("Summary", "Implementation Details", "Ready for Orchestrator Review"),
    HANDOFF_F01_PATH: ("Summary", "Implementation Details", "Ready for Orchestrator Review"),
}
MAKE_REQUIRED_LINES = (
    '$(PYTHON) -B -m unittest discover -s tests -p "test_checker_*.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_wave20_gate.py"',
    '$(PYTHON) -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"',
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py",
    "$(PYTHON_NOREPO_CACHE_ENV) $(PYTHON) -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py",
    "$(GO_RELEASE_ENV) $(GO) test ./...",
    "$(GO_RELEASE_ENV) $(GO) vet ./...",
    "$(PYTHON) -B scripts/check_wave20_gate.py",
    "$(PYTHON) -B scripts/check_competition_matrix_gate.py",
    "$(PYTHON) -B scripts/check_docs_tree.py",
    "$(PYTHON) -B scripts/validate_forcad_config.py",
    "$(PYTHON) -B scripts/check_archive_hygiene.py",
)


def validate_wave20_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_reference_exploit(repo_root),
        check_exploit_scope(repo_root),
        check_exploit_cli_import_safety(repo_root),
        check_no_later_exploits_or_fixes(repo_root),
        check_makefile_wave20_gate(repo_root),
        check_docs(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_reference_exploit(repo_root: Path) -> dict[str, Any]:
    path = repo_root / EXPLOIT_PATH
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    exploit_files = sorted(item.name for item in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    ok = path.is_file() and exploit_files == sorted(EXPECTED_EXPLOITS)
    message = "" if ok else f"missing={not path.is_file()} exploit_files={exploit_files}"
    return {"name": "wave20-aml2-reference-exploit-present", "path": EXPLOIT_PATH, "status": "pass" if ok else "fail", "message": message}


def check_exploit_scope(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, EXPLOIT_PATH)
    missing = [marker for marker in SCRIPT_REQUIRED_MARKERS if marker not in text]
    forbidden = [marker for marker in FORBIDDEN_SCRIPT_MARKERS if marker.lower() in text.lower()]
    forbidden.extend(forbidden_imports(text))
    if FORBIDDEN_ATTACK_DATA_SECRET_RE.search(text):
        forbidden.append("public attack-data secret lookup")
    ok = not missing and not forbidden
    message = "" if ok else f"missing={missing} forbidden={forbidden}"
    return {"name": "wave20-aml2-exploit-scoped-to-audit-side-view", "path": EXPLOIT_PATH, "status": "pass" if ok else "fail", "message": message}


def check_exploit_cli_import_safety(repo_root: Path) -> dict[str, Any]:
    text = read(repo_root, EXPLOIT_PATH)
    missing = [marker for marker in SCRIPT_CLI_MARKERS if marker not in text]
    import_side_effects = [
        marker
        for marker in ("urlopen", "request_json", "register_and_login", "run_exploit")
        if top_level_call_uses_name(text, marker)
    ]
    forbidden = forbidden_imports(text)
    ok = not missing and not import_side_effects and not forbidden
    message = "" if ok else f"missing={missing} import_side_effects={import_side_effects} forbidden_imports={forbidden}"
    return {"name": "wave20-exploit-cli-and-import-safe", "path": EXPLOIT_PATH, "status": "pass" if ok else "fail", "message": message}


def check_no_later_exploits_or_fixes(repo_root: Path) -> dict[str, Any]:
    sploit_dir = repo_root / "sploits" / "sentinel_aml"
    present_exploits = sorted(path.name for path in sploit_dir.glob("*.py")) if sploit_dir.is_dir() else []
    unexpected_exploits = [name for name in present_exploits if name not in EXPECTED_EXPLOITS]
    fixes_dir = repo_root / "fixes" / "sentinel_aml"
    present_fixes: list[str] = []
    if fixes_dir.is_dir():
        for path in fixes_dir.rglob("*"):
            if path == fixes_dir / "README.md":
                continue
            if path.is_file():
                present_fixes.append(path.name)
    unexpected_fixes = [name for name in sorted(present_fixes) if name not in EXPECTED_FIXES]
    ok = not unexpected_exploits and not unexpected_fixes
    message = "" if ok else f"unexpected_exploits={unexpected_exploits} unexpected_fixes={unexpected_fixes}"
    return {"name": "wave20-no-nonstandard-exploits-or-reference-fixes", "path": "sploits/sentinel_aml fixes/sentinel_aml", "status": "pass" if ok else "fail", "message": message}


def check_docs(repo_root: Path) -> dict[str, Any]:
    missing: list[str] = []
    for relative, markers in DOC_MARKERS.items():
        text = read(repo_root, relative)
        for marker in markers:
            if marker not in text:
                missing.append(f"{relative}: {marker}")
    ok = not missing
    return {"name": "wave20-docs-and-handoff-present", "path": "docs sploits/sentinel_aml/README.md", "status": "pass" if ok else "fail", "message": "" if ok else f"missing markers: {missing}"}


def check_makefile_wave20_gate(repo_root: Path) -> dict[str, Any]:
    target = make_target_block(read(repo_root, "Makefile"), MAKE_TARGET)
    missing = [line for line in MAKE_REQUIRED_LINES if line not in target]
    ok = bool(target) and not missing
    message = "" if ok else f"missing {MAKE_TARGET} lines: {missing}"
    return {"name": "wave20-make-target-runs-full-gate", "path": "Makefile", "status": "pass" if ok else "fail", "message": message}


def make_target_block(text: str, target_name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target_name)}:\s*(?:#.*)?$", text)
    if not match:
        return ""
    next_target = re.search(r"(?m)^[A-Za-z0-9_.-]+:.*$", text[match.end() :])
    end = match.end() + next_target.start() if next_target else len(text)
    return text[match.start() : end]


def top_level_call_uses_name(text: str, name: str) -> bool:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and call_name(child.func) == name:
                return True
    return False


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def forbidden_imports(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [f"syntax error: {exc.msg}"]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in FORBIDDEN_IMPORTS:
                    found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            if root in FORBIDDEN_IMPORTS:
                found.add(node.module)
    return sorted(found)


def read(repo_root: Path, relative: str) -> str:
    path = repo_root / relative
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave20_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
