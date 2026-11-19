#!/usr/bin/env python3
"""Validate that repository snapshots and release archives exclude local artifacts."""

from __future__ import annotations

import json
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any


FORBIDDEN_DIR_NAMES = {
    ".appdata",
    ".gocache",
    ".gotelemetry",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vscode",
    "__pycache__",
    "bin",
    "temp",
    "tmp",
}
FORBIDDEN_DIR_PREFIXES = (
    ".appdata",
    ".gocache",
)
FORBIDDEN_FILE_NAMES = {
    ".DS_Store",
    ".env",
    "Thumbs.db",
    ".coverage",
    "coverage.out",
}
FORBIDDEN_FILE_PREFIXES = (
    ".env.",
)
FORBIDDEN_FILE_SUFFIXES = {
    ".coverprofile",
    ".exe",
    ".pyc",
    ".pyo",
    ".tar",
    ".test",
    ".tgz",
    ".zip",
}
FORBIDDEN_FILE_SUFFIX_CHAINS = (
    ".tar.gz",
)
IGNORED_TRAVERSAL_DIRS = {
    ".git",
}
REQUIRED_RELEASE_FILES = {
    "Makefile",
    "README.md",
    "config.yml",
    "docker-compose.yml",
    "go.mod",
    "go.sum",
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
    "docs/source_of_truth_map.md",
    "docs/definition_of_done.md",
    "docs/wave_reports/wave_30_release_readiness_manifest.md",
}
FORBIDDEN_ARCHIVE_PREFIXES = (
    "docs/archive/",
)


def validate_archive_hygiene(repo_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    if repo_root.is_file():
        return validate_release_archive(repo_root)

    findings = sorted(find_forbidden_artifacts(repo_root))
    return {
        "status": "fail" if findings else "pass",
        "checks": [
            {
                "name": "archive-no-local-cache-ide-bytecode-artifacts",
                "path": ".",
                "status": "fail" if findings else "pass",
                "message": "" if not findings else "; ".join(findings),
            }
        ],
    }


def validate_release_archive(archive_path: Path) -> dict[str, Any]:
    findings: list[str] = []
    members: set[str] = set()

    if not archive_path.exists():
        findings.append(f"{archive_path}: archive does not exist")
    elif is_tar_archive(archive_path):
        try:
            members = read_tar_members(archive_path)
        except (OSError, tarfile.TarError) as exc:
            findings.append(f"{archive_path}: unreadable tar archive ({exc})")
    elif zipfile.is_zipfile(archive_path):
        try:
            members = read_zip_members(archive_path)
        except (OSError, zipfile.BadZipFile) as exc:
            findings.append(f"{archive_path}: unreadable zip archive ({exc})")
    else:
        findings.append(f"{archive_path}: unsupported release archive format")

    if members:
        findings.extend(find_forbidden_archive_members(members))
        missing = sorted(REQUIRED_RELEASE_FILES - members)
        if missing:
            findings.append(f"missing required release files: {', '.join(missing)}")

    findings = sorted(findings)
    return {
        "status": "fail" if findings else "pass",
        "checks": [
            {
                "name": "archive-member-hygiene-and-required-ctf-artifacts",
                "path": relative_name(Path.cwd(), archive_path),
                "status": "fail" if findings else "pass",
                "message": "" if not findings else "; ".join(findings),
            }
        ],
    }


def is_tar_archive(path: Path) -> bool:
    lowered = path.name.lower()
    return lowered.endswith((".tar", ".tar.gz", ".tgz")) or tarfile.is_tarfile(path)


def read_tar_members(path: Path) -> set[str]:
    with tarfile.open(path, "r:*") as archive:
        return {normalize_member_name(member.name) for member in archive.getmembers() if member.isfile()}


def read_zip_members(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as archive:
        return {normalize_member_name(info.filename) for info in archive.infolist() if not info.is_dir()}


def normalize_member_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def find_forbidden_archive_members(members: set[str]) -> list[str]:
    findings: list[str] = []
    for member in sorted(members):
        if is_unsafe_member_name(member):
            findings.append(f"{member}: unsafe archive member path")
            continue
        if any(member.startswith(prefix) for prefix in FORBIDDEN_ARCHIVE_PREFIXES):
            findings.append(f"{member}: foreign or archived material is not part of release archive")
            continue
        path = Path(member)
        if any(part in FORBIDDEN_DIR_NAMES or part.startswith(FORBIDDEN_DIR_PREFIXES) for part in path.parts[:-1]):
            findings.append(member)
            continue
        name = path.name
        lowered = name.lower()
        if (
            name in FORBIDDEN_FILE_NAMES
            or name.startswith(FORBIDDEN_FILE_PREFIXES)
            or path.suffix.lower() in FORBIDDEN_FILE_SUFFIXES
            or any(lowered.endswith(suffix) for suffix in FORBIDDEN_FILE_SUFFIX_CHAINS)
        ):
            findings.append(member)
    return findings


def is_unsafe_member_name(member: str) -> bool:
    path = Path(member)
    return member.startswith("/") or member.startswith("\\") or ".." in path.parts


def find_forbidden_artifacts(repo_root: Path) -> list[str]:
    findings: list[str] = []
    if not repo_root.exists():
        return [f"{repo_root}: repository root does not exist"]

    def walk(path: Path) -> None:
        try:
            entries = list(path.iterdir())
        except OSError as exc:
            findings.append(f"{relative_name(repo_root, path)}: unreadable ({exc})")
            return
        for entry in entries:
            name = entry.name
            if entry.is_dir():
                if name in FORBIDDEN_DIR_NAMES or name.startswith(FORBIDDEN_DIR_PREFIXES):
                    findings.append(f"{relative_name(repo_root, entry)}/")
                    continue
                if name in IGNORED_TRAVERSAL_DIRS:
                    continue
                walk(entry)
                continue
            lowered = name.lower()
            if (
                name in FORBIDDEN_FILE_NAMES
                or name.startswith(FORBIDDEN_FILE_PREFIXES)
                or entry.suffix.lower() in FORBIDDEN_FILE_SUFFIXES
                or any(lowered.endswith(suffix) for suffix in FORBIDDEN_FILE_SUFFIX_CHAINS)
            ):
                findings.append(relative_name(repo_root, entry))

    walk(repo_root)
    return findings


def relative_name(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def main(argv: list[str]) -> int:
    repo_root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    result = validate_archive_hygiene(repo_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
