#!/usr/bin/env python3
"""Validate an admin/checker candidate tree inventory.

The admin package may contain checker/operator material, but it must not carry
reference attack/fix artifacts, vulnerable-profile source, wave reports, or
sample secret values.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any, NamedTuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import validate_forcad_config
import check_player_bundle_hygiene as bundle_io


ROOT = Path(__file__).resolve().parents[1]
MAX_CONTENT_BYTES = 4 * 1024 * 1024
REQUIRED_FILES = {
    "README.md",
    "PACKAGING_STATUS.json",
    "config.yml",
    "config/operator.env.example",
    "sentinel_aml/checker.py",
    "sentinel_aml/checker_lib.py",
    "sentinel_aml/requirements.txt",
}
ALLOWED_FILES = REQUIRED_FILES
ORGANIZER_REQUIRED_FILES = {
    "Makefile",
    "config.yml",
    "checkers/sentinel_aml/checker.py",
    "checkers/sentinel_aml/checker_lib.py",
    "checkers/sentinel_aml/requirements.txt",
    "sploits/sentinel_aml/aml_dedup_preview.py",
    "sploits/sentinel_aml/aml_audit_timeline.py",
    "sploits/sentinel_aml/aml_related_graph.py",
    "sploits/sentinel_aml/aml_export_redaction.py",
    "sploits/sentinel_aml/aml_network_room.py",
    "fixes/sentinel_aml/aml_dedup_preview.patch",
    "fixes/sentinel_aml/aml_audit_timeline.patch",
    "fixes/sentinel_aml/aml_related_graph.patch",
    "fixes/sentinel_aml/aml_export_redaction.patch",
    "fixes/sentinel_aml/aml_network_room.patch",
    "tests/test_checker_check_workflow.py",
    "tests/test_checker_put_workflow.py",
    "docs/wave_reports/wave_32_sploit_fix_matrix.md",
}
FORBIDDEN_PREFIXES = (
    "sploits/",
    "exploits/",
    "fixes/",
    "tests/",
    "docs/",
    "internal/",
    "cmd/",
    "migrations/",
    "tmp/",
    "vendor/",
)
DENIED_PATH_TOKENS = (
    ("aml1", re.compile(r"(?<![A-Za-z0-9])aml[-_]?1(?![A-Za-z0-9])", re.IGNORECASE)),
    ("aml2", re.compile(r"(?<![A-Za-z0-9])aml[-_]?2(?![A-Za-z0-9])", re.IGNORECASE)),
    ("aml3", re.compile(r"(?<![A-Za-z0-9])aml[-_]?3(?![A-Za-z0-9])", re.IGNORECASE)),
    ("aml4", re.compile(r"(?<![A-Za-z0-9])aml[-_]?4(?![A-Za-z0-9])", re.IGNORECASE)),
    ("aml5", re.compile(r"(?<![A-Za-z0-9])aml[-_]?5(?![A-Za-z0-9])", re.IGNORECASE)),
    ("vulnerable", re.compile(r"(?<![A-Za-z0-9])vulnerable(?![A-Za-z0-9])", re.IGNORECASE)),
    ("sploit", re.compile(r"(?<![A-Za-z0-9])sploits?(?![A-Za-z0-9])", re.IGNORECASE)),
    ("exploit", re.compile(r"(?<![A-Za-z0-9])exploits?(?![A-Za-z0-9])", re.IGNORECASE)),
    ("fix", re.compile(r"(?<![A-Za-z0-9])fix(?:es)?(?![A-Za-z0-9])", re.IGNORECASE)),
)
DENIED_CONTENT_TOKENS = (
    *DENIED_PATH_TOKENS,
    ("dev-secret", re.compile(r"sentinel_aml_checker_wave11_dev_secret|_dev_secret", re.IGNORECASE)),
    ("sample-flag", re.compile(r"(?:FLAG|CTF|SENTINEL)\{[^}]+\}", re.IGNORECASE)),
    ("leak-target", re.compile(r"LEAK_TARGET|MUST_NOT_LEAK", re.IGNORECASE)),
    ("wave", re.compile(r"(?<![A-Za-z0-9])wave(?:s|[-_ ]reports?)?(?![A-Za-z0-9])", re.IGNORECASE)),
)
LOCAL_GENERATED_FORBIDDEN_SEGMENTS = {
    ".cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vite",
    "__pycache__",
    "node_modules",
    "out",
    "temp",
    "tmp",
    "validation",
}
LOCAL_GENERATED_FORBIDDEN_SUFFIXES = {
    ".map",
    ".pyc",
    ".pyo",
    ".tar",
    ".test",
    ".tgz",
    ".tsbuildinfo",
    ".zip",
}
LOCAL_GENERATED_FORBIDDEN_SUFFIX_CHAINS = (
    ".tar.gz",
)
LOCAL_GENERATED_FORBIDDEN_PREFIXES = (
    ".appdata",
    ".gocache",
)


class LoadedBundle(NamedTuple):
    files: list[str]
    content: dict[str, bytes]


def validate_admin_bundle(candidate: Path) -> dict[str, Any]:
    candidate = candidate.resolve()
    checks: list[dict[str, str]] = [check_candidate_root(candidate)]
    if checks[0]["status"] == "fail":
        return {"status": "fail", "checks": checks}

    try:
        loaded = load_bundle(candidate)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
        checks.append(fail("admin-bundle-readable", str(candidate), str(exc)))
        return {"status": "fail", "checks": checks}

    if is_organizer_artifact(loaded.files):
        checks.append(check_organizer_inventory(loaded.files))
        checks.append(check_no_generated_artifacts(loaded.files))
    else:
        files = loaded.files
        checks.append(check_inventory(files))
        checks.append(check_paths(files))
        checks.append(check_content_bytes(loaded.content))
        checks.append(check_packaging_status(candidate, loaded.content))
        checks.append(check_forcad_config(candidate, loaded.content))
        checks.append(check_requirements(candidate, loaded.content))
        checks.append(check_no_generated_artifacts(files))
    return {"status": aggregate_status(checks), "checks": checks}


def check_candidate_root(candidate: Path) -> dict[str, str]:
    if not candidate.exists():
        return fail("admin-candidate-root", str(candidate), "candidate path does not exist")
    if candidate == ROOT:
        return fail("admin-candidate-root", str(candidate), "refusing to scan organizer repository root as an admin package")
    if candidate.is_dir():
        return passed("admin-candidate-root", str(candidate), "candidate path is a directory")
    return passed("admin-candidate-root", str(candidate), "candidate path is an archive")


def load_bundle(candidate: Path) -> LoadedBundle:
    members = list(bundle_io.iter_bundle_members(candidate))
    members = bundle_io.strip_transfer_archive_root(members)
    content: dict[str, bytes] = {}
    for member in members:
        if member.is_dir or member.data is None:
            continue
        path = bundle_io.normalize_member_path(member.path)
        content[path] = member.data[:MAX_CONTENT_BYTES]
    return LoadedBundle(files=sorted(content), content=content)


def is_organizer_artifact(files: list[str]) -> bool:
    file_set = set(files)
    return "Makefile" in file_set and "checkers/sentinel_aml/checker.py" in file_set


def check_inventory(files: list[str]) -> dict[str, str]:
    missing = sorted(REQUIRED_FILES - set(files))
    unexpected = sorted(set(files) - ALLOWED_FILES)
    if missing or unexpected:
        return fail("admin-candidate-inventory", "admin candidate", f"missing={missing} unexpected={unexpected}")
    return passed("admin-candidate-inventory", "admin candidate", f"{len(files)} files match allowlist")


def check_organizer_inventory(files: list[str]) -> dict[str, str]:
    file_set = set(files)
    missing = sorted(ORGANIZER_REQUIRED_FILES - file_set)
    if missing:
        return fail("admin-organizer-artifact-required-evidence", "admin organizer artifact", f"missing={missing}")
    return passed(
        "admin-organizer-artifact-required-evidence",
        "admin organizer artifact",
        f"required checker/sploit/fix evidence present in {len(files)} files",
    )


def check_paths(files: list[str]) -> dict[str, str]:
    findings: list[str] = []
    for path in files:
        for prefix in FORBIDDEN_PREFIXES:
            if path.startswith(prefix):
                findings.append(f"{path}: forbidden path prefix {prefix}")
        for name, pattern in DENIED_PATH_TOKENS:
            if pattern.search(path):
                findings.append(f"{path}: denied token in path {name}")
    if findings:
        return fail("admin-candidate-no-attack-fix-paths", "admin candidate", "; ".join(findings[:20]))
    return passed("admin-candidate-no-attack-fix-paths", "admin candidate", "no forbidden path material")


def check_content_bytes(content: dict[str, bytes]) -> dict[str, str]:
    findings: list[str] = []
    for relative, data in content.items():
        text = data.decode("utf-8", errors="ignore")
        for name, pattern in DENIED_CONTENT_TOKENS:
            if pattern.search(text):
                findings.append(f"{relative}: denied content token {name}")
    if findings:
        return fail("admin-candidate-no-reference-material-or-sample-secrets", "admin candidate", "; ".join(findings[:20]))
    return passed(
        "admin-candidate-no-reference-material-or-sample-secrets",
        "admin candidate",
        "no reference attack/fix material or sample secrets",
    )


def check_packaging_status(candidate: Path, content: dict[str, bytes]) -> dict[str, str]:
    try:
        raw = content.get("PACKAGING_STATUS.json")
        if raw is None and candidate.is_dir():
            raw = (candidate / "PACKAGING_STATUS.json").read_bytes()
        if raw is None:
            raise OSError("PACKAGING_STATUS.json missing")
        status = json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail("admin-candidate-packaging-status", "PACKAGING_STATUS.json", str(exc))
    expected = {
        "artifact_class": "admin-checker",
        "contains_checker": True,
        "contains_forcad_config": True,
        "contains_reference_attacks": False,
        "contains_reference_patches": False,
        "contains_sample_secrets": False,
    }
    mismatches = [f"{key}={status.get(key)!r}" for key, expected_value in expected.items() if status.get(key) != expected_value]
    if status.get("final_package") is not False:
        mismatches.append(f"final_package={status.get('final_package')!r}")
    if mismatches:
        return fail("admin-candidate-packaging-status", "PACKAGING_STATUS.json", "; ".join(mismatches))
    return passed("admin-candidate-packaging-status", "PACKAGING_STATUS.json", "staged admin package metadata is explicit")


def check_forcad_config(candidate: Path, content: dict[str, bytes]) -> dict[str, str]:
    if candidate.is_dir():
        config_path = candidate / "config.yml"
        errors = validate_forcad_config.validate_config(config_path)
        path = "config.yml"
    else:
        raw = content.get("config.yml")
        if raw is None:
            return fail("admin-candidate-forcad-config", "config.yml", "missing config.yml")
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yml"
            config_path.write_bytes(raw)
            errors = validate_forcad_config.validate_config(config_path)
        path = "config.yml"
    if errors:
        return fail("admin-candidate-forcad-config", path, "; ".join(errors))
    return passed("admin-candidate-forcad-config", path, "ForcAD registration shape is valid")


def check_requirements(candidate: Path, content: dict[str, bytes]) -> dict[str, str]:
    requirements = candidate / "sentinel_aml" / "requirements.txt"
    raw = content.get("sentinel_aml/requirements.txt")
    if raw is None and candidate.is_dir():
        raw = requirements.read_bytes()
    if raw is None:
        return fail("admin-candidate-checker-requirements", requirements.as_posix(), "missing requirements.txt")
    active_lines = [
        line.strip()
        for line in raw.decode("utf-8", errors="ignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if active_lines:
        return fail("admin-candidate-checker-requirements", requirements.as_posix(), f"unexpected third-party requirements={active_lines}")
    return passed("admin-candidate-checker-requirements", requirements.as_posix(), "checker uses Python standard library only")


def check_no_generated_artifacts(files: list[str]) -> dict[str, str]:
    findings: list[str] = []
    for path in files:
        reason = generated_artifact_path_reason(path)
        if reason:
            findings.append(f"{path}: {reason}")
    if findings:
        return fail("admin-artifact-no-local-generated-cache", "admin artifact", "; ".join(findings[:30]))
    return passed("admin-artifact-no-local-generated-cache", "admin artifact", "no local/generated/cache artifacts")


def generated_artifact_path_reason(path: str) -> str:
    normalized = bundle_io.normalize_member_path(path).rstrip("/")
    if not normalized:
        return ""
    segments = [segment for segment in normalized.split("/") if segment]
    lowered_segments = [segment.lower() for segment in segments]
    lowered_name = lowered_segments[-1]
    for segment in lowered_segments:
        if segment in LOCAL_GENERATED_FORBIDDEN_SEGMENTS:
            return f"forbidden segment {segment}"
        if segment.startswith(LOCAL_GENERATED_FORBIDDEN_PREFIXES):
            return f"forbidden cache segment {segment}"
    if lowered_name.endswith(LOCAL_GENERATED_FORBIDDEN_SUFFIX_CHAINS):
        return f"forbidden suffix {lowered_name}"
    suffix = Path(lowered_name).suffix
    if suffix in LOCAL_GENERATED_FORBIDDEN_SUFFIXES:
        return f"forbidden suffix {suffix}"
    return ""


def inventory(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)).replace("\\", "/") for path in root.rglob("*") if path.is_file())


def aggregate_status(checks: list[dict[str, str]]) -> str:
    return "fail" if any(check["status"] == "fail" for check in checks) else "pass"


def passed(name: str, path: str, message: str = "") -> dict[str, str]:
    return {"name": name, "path": path, "status": "pass", "message": message}


def fail(name: str, path: str, message: str) -> dict[str, str]:
    return {"name": name, "path": path, "status": "fail", "message": message}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="admin/checker candidate directory to validate")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = validate_admin_bundle(args.candidate)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
