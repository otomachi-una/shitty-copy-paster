#!/usr/bin/env python3
"""Build an admin/checker candidate tree.

This script stages checker/operator files for later packaging review. It does
not create final archives, manifests, checksums, or promoted release artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "tmp" / "admin-checker-candidate"
IGNORED_REPO_OUTPUT_DIRS = {"tmp", "temp"}
CHECKER_FILES = (
    Path("checkers") / "sentinel_aml" / "checker.py",
    Path("checkers") / "sentinel_aml" / "checker_lib.py",
    Path("checkers") / "sentinel_aml" / "requirements.txt",
)
PACKAGING_DOC_DIR = ROOT / "packaging" / "admin"
OPERATOR_ENV_TEMPLATE = "SENTINEL_AML_CHECKER_SECRET=\n"


def build_admin_candidate(output_dir: Path) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    ensure_candidate_output_allowed(output_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    write_admin_readme(output_dir)
    write_packaging_status(output_dir)
    write_operator_env_template(output_dir)
    copy_file(ROOT / "config.yml", output_dir / "config.yml")
    for relative in CHECKER_FILES:
        copy_checker_file(ROOT / relative, output_dir / Path("sentinel_aml") / relative.name)

    files = inventory(output_dir)
    return {
        "status": "pass",
        "candidate_type": "admin-checker",
        "output_dir": str(output_dir),
        "file_count": len(files),
        "files": files,
    }


def ensure_candidate_output_allowed(output_dir: Path) -> None:
    if output_dir == ROOT:
        raise ValueError("candidate output must not be the organizer repository root")
    try:
        relative = output_dir.relative_to(ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] not in IGNORED_REPO_OUTPUT_DIRS:
        raise ValueError("repo-local candidate output must be under ignored tmp/ or temp/")


def write_admin_readme(output_dir: Path) -> None:
    copy_file(PACKAGING_DOC_DIR / "README.md", output_dir / "README.md")


def write_packaging_status(output_dir: Path) -> None:
    status = {
        "artifact_class": "admin-checker",
        "candidate_state": "staged",
        "final_package": False,
        "contains_checker": True,
        "contains_forcad_config": True,
        "contains_reference_attacks": False,
        "contains_reference_patches": False,
        "contains_sample_secrets": False,
        "promotion_blocker": "final operator packaging wrapper and deployment-specific secret injection remain out of scope",
    }
    (output_dir / "PACKAGING_STATUS.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_operator_env_template(output_dir: Path) -> None:
    env_path = output_dir / "config" / "operator.env.example"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(OPERATOR_ENV_TEMPLATE, encoding="utf-8")


def copy_file(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    dest.chmod(0o644)


def copy_checker_file(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix != ".py":
        shutil.copyfile(source, dest)
        dest.chmod(0o644)
        return
    text = source.read_text(encoding="utf-8")
    text = sanitize_checker_source_for_admin_candidate(text)
    dest.write_text(text, encoding="utf-8")
    dest.chmod(0o755)


def sanitize_checker_source_for_admin_candidate(text: str) -> str:
    replacements = {
        '"""Wave 13 checker entrypoint for Sentinel AML.': '"""Sentinel AML checker entrypoint.',
        '"""Sentinel AML checker foundation for Wave 12 places 1 and 2.': '"""Sentinel AML checker foundation for places 1 and 2.',
        "# Legacy Wave 01 validators looked for the literal text \"return 2\" in the\n"
        "# placeholder checker. Wave 11 uses explicit Hackerdom-compatible exit codes.\n": "",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def inventory(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)).replace("\\", "/") for path in root.rglob("*") if path.is_file())


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(os.environ.get("SENTINEL_AML_ADMIN_CANDIDATE", DEFAULT_OUTPUT_DIR)),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = build_admin_candidate(args.output_dir)
    except Exception as exc:
        result = {
            "status": "fail",
            "candidate_type": "admin-checker",
            "output_dir": str(args.output_dir),
            "message": str(exc),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
