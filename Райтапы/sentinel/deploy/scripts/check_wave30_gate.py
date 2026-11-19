#!/usr/bin/env python3
"""Validate the final Wave 30 release-readiness gate wiring."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


MAKE_TARGET = "wave30-gate"
REQUIRED_TARGET_LINES = (
    '$(PYTHON) -B -m unittest discover -s tests -p "test_wave30_gate.py"',
    "$(MAKE) wave29-gate",
    "$(MAKE) competition-matrix-gate",
    "$(PYTHON) -B scripts/check_wave30_gate.py",
    "$(PYTHON) -B scripts/validate_forcad_config.py",
    "$(PYTHON) -B scripts/check_archive_hygiene.py",
    "$(MAKE) release-archive",
)
FORBIDDEN_TARGET_LINES = (
    "$(GO_RELEASE_ENV) $(GO) test ./...",
    "$(GO_OFFLINE_ENV) $(GO) test ./...",
    "true",
    "@true",
)
DOC_REQUIREMENTS = {
    "docs/12_testing_strategy.md": (
        "timeout 300 make wave30-gate",
        "single final acceptance command",
        "does not claim final competition readiness",
    ),
    "docs/wave_reports/wave_30_release_readiness_manifest.md": (
        "timeout 300 make wave30-gate",
        "Final release gate",
        "orchestrator acceptance",
    ),
    "docs/wave_reports/wave_30_final_validation_summary.md": (
        "timeout 300 make wave30-gate",
        "Wave 30 final release gate",
        "does not claim final competition readiness",
    ),
}


def validate_wave30_gate(repo_root: Path) -> dict[str, Any]:
    checks = [
        check_wave30_make_target(repo_root),
        check_wave29_delegate_gate(repo_root),
        check_bounded_vulnerable_profile_runner(repo_root),
        check_wave30_docs(repo_root),
    ]
    return {"status": aggregate_status(checks), "checks": checks}


def check_wave30_make_target(repo_root: Path) -> dict[str, str]:
    makefile = read(repo_root, "Makefile")
    target = make_target_block(makefile, MAKE_TARGET)
    phony_has_target = ".PHONY:" in makefile and MAKE_TARGET in makefile.splitlines()[0]
    missing = [line for line in REQUIRED_TARGET_LINES if line not in target]
    forbidden = [line for line in FORBIDDEN_TARGET_LINES if re.search(rf"(?m)^\s*{re.escape(line)}\s*$", target)]
    ok = bool(target) and phony_has_target and not missing and not forbidden
    return {
        "name": "wave30-final-release-target-concrete",
        "path": "Makefile",
        "status": "pass" if ok else "fail",
        "message": ""
        if ok
        else f"target_present={bool(target)} phony_has_target={phony_has_target} missing={missing} forbidden={forbidden}",
    }


def check_wave29_delegate_gate(repo_root: Path) -> dict[str, str]:
    try:
        module = load_module(repo_root, "scripts/check_wave29_gate.py")
        result = module.validate_wave29_gate(repo_root)
    except Exception as exc:  # pragma: no cover - defensive diagnostic path
        return {
            "name": "wave30-wave29-matrix-delegate-valid",
            "path": "scripts/check_wave29_gate.py Makefile",
            "status": "fail",
            "message": str(exc),
        }
    failures = [check["name"] for check in result["checks"] if check["status"] != "pass"]
    return {
        "name": "wave30-wave29-matrix-delegate-valid",
        "path": "scripts/check_wave29_gate.py Makefile",
        "status": "pass" if result["status"] == "pass" else "fail",
        "message": "" if result["status"] == "pass" else f"failing Wave 29 checks: {failures}",
    }


def check_bounded_vulnerable_profile_runner(repo_root: Path) -> dict[str, str]:
    runner = read(repo_root, "scripts/run_vulnerable_profile_tests.py")
    required = (
        "from run_go_release_tests import Runner, run_command",
        "runner: Runner = run_command",
        "outer_timeout = min(package_timeout + 30, 45)",
        "outer_timeout={outer_timeout}s",
    )
    missing = [marker for marker in required if marker not in runner]
    forbidden = ["subprocess.run("] if "subprocess.run(" in runner else []
    return {
        "name": "wave30-vulnerable-profile-runner-process-tree-bounded",
        "path": "scripts/run_vulnerable_profile_tests.py",
        "status": "pass" if not missing and not forbidden else "fail",
        "message": "" if not missing and not forbidden else f"missing={missing} forbidden={forbidden}",
    }


def check_wave30_docs(repo_root: Path) -> dict[str, str]:
    missing = [
        f"{relative}: {marker}"
        for relative, markers in DOC_REQUIREMENTS.items()
        for marker in markers
        if marker not in read(repo_root, relative)
    ]
    forbidden_claims: list[str] = []
    for relative in DOC_REQUIREMENTS:
        text = read(repo_root, relative).lower()
        if "sentinel aml is competition-ready" in text or "final competition readiness is accepted" in text:
            forbidden_claims.append(relative)
    return {
        "name": "wave30-release-docs-name-final-gate-without-self-acceptance",
        "path": "docs/12_testing_strategy.md docs/wave_reports/wave_30_*",
        "status": "pass" if not missing and not forbidden_claims else "fail",
        "message": "" if not missing and not forbidden_claims else f"missing={missing} forbidden_claims={forbidden_claims}",
    }


def read(repo_root: Path, relative: str) -> str:
    path = repo_root / relative
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def make_target_block(text: str, target_name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target_name)}:\s*(?:#.*)?$", text)
    if not match:
        return ""
    start = match.end()
    next_target = re.search(r"(?m)^[A-Za-z0-9_.-]+:\s*(?:#.*)?$", text[start:])
    end = start + next_target.start() if next_target else len(text)
    return text[start:end]


def load_module(repo_root: Path, relative: str):
    module_name = "wave30_" + re.sub(r"\W+", "_", relative)
    spec = importlib.util.spec_from_file_location(module_name, repo_root / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    result = validate_wave30_gate(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
