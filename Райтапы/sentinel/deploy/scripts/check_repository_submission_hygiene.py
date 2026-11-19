#!/usr/bin/env python3
"""Validate repository-submission archives for local generated artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import re
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable, NamedTuple


class SubmissionMember(NamedTuple):
    path: str
    is_dir: bool = False


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPOSITORY_SUBMISSION_ARCHIVE = Path("out/repository-submission/sentinel-aml-repository-submission.zip")
REPOSITORY_SUBMISSION_ROOT = "sentinel-aml-repository-submission"
REPOSITORY_ARTIFACT_REFERENCE = "REPOSITORY_SUBMISSION_ARTIFACTS.json"
REPOSITORY_SUBMISSION_README = "README_REPOSITORY_SUBMISSION.md"
REPOSITORY_SUBMISSION_README_TEXT = """# Sentinel AML Repository Submission

This archive is an internal repository handoff for organizer review and long-term source archiving.

It is not a participant artifact. Participant teams receive `sentinel-aml-player-source.tar.gz`.

The organizer-only package is `sentinel-aml-admin-organizer.tar.gz`.

Generated transfer artifacts are referenced by checksum when available and are not nested inside this archive.
"""
FORBIDDEN_DIR_NAMES = {
    "__pycache__",
    ".cache",
    ".playwright",
    ".vite",
    "blob-report",
    "browser-profile",
    "chrome-profile",
    "chromium-profile",
    "edge-profile",
    "node_modules",
    "playwright-report",
    "screenshots",
    "test-results",
    "traces",
    "validation",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "out",
    "temp",
    "tmp",
}
FORBIDDEN_DIR_PREFIXES = (
    ".gocache",
    ".appdata",
    ".gotelemetry",
)
FORBIDDEN_FILE_SUFFIXES = {
    ".coverprofile",
    ".map",
    ".pyc",
    ".pyo",
    ".test",
    ".tgz",
    ".tsbuildinfo",
    ".zip",
}
FORBIDDEN_FILE_SUFFIX_CHAINS = (
    ".tar.gz",
)
FORBIDDEN_FILE_NAMES = {
    ".env",
    ".coverage",
    ".DS_Store",
    "Thumbs.db",
    "coverage.out",
}
FORBIDDEN_FILE_PREFIXES = (
    ".env.",
)
FORBIDDEN_PATH_PREFIXES = (
    "frontend/dist/",
    "frontend/node_modules/",
    "frontend/.playwright/",
    "frontend/blob-report/",
    "frontend/playwright-report/",
    "frontend/test-results/",
    "validation/",
    "out/",
    "temp/",
    "tmp/",
)
NESTED_ARCHIVE_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".zip",
)
LOCAL_WAVE33_CANDIDATE_ROOTS = {
    "tmp/admin-checker-candidate",
    "tmp/player-service-candidate",
    "tmp/wave33-admin-checker-candidate",
    "tmp/wave33-player-service-candidate",
}
GENERATED_CLEAN_PATHS = (
    "tmp",
    "temp",
    "out",
    "frontend/dist",
    "frontend/node_modules",
    "frontend/test-results",
    "frontend/playwright-report",
    "frontend/blob-report",
    "frontend/.playwright",
)
GENERATED_CLEAN_GLOBS = (
    "frontend/*.tsbuildinfo",
    ".gocache*",
    ".appdata*",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
)
ARCHIVE_BUILDER_EXCLUDED_DIR_NAMES = {
    ".git",
    ".idea",
    ".vscode",
    ".codex",
    ".agents",
}
ARCHIVE_BUILDER_ALLOWED_TOP_LEVEL_DIRS = {
    "checkers",
    "cmd",
    "docs",
    "exploits",
    "fixes",
    "frontend",
    "internal",
    "migrations",
    "packaging",
    "scripts",
    "sploits",
    "tests",
    "vendor",
}
ARCHIVE_BUILDER_ALLOWED_TOP_LEVEL_FILES = {
    ".gitignore",
    "AGENTS.md",
    ".dockerignore",
    "config.yml",
    "docker-compose.yml",
    "FRONTEND_START_HERE.md",
    "go.mod",
    "go.sum",
    "Makefile",
    "README.md",
}
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def validate_repository_submission(
    target: Path,
    *,
    allow_wave33_local_candidates: bool = False,
    allow_nested_archives: bool = False,
) -> dict[str, object]:
    target = target.resolve()
    failures: list[str] = []
    member_count = 0
    is_archive = target.is_file()

    if not target.exists():
        failures.append(f"{target}: target does not exist")
    else:
        try:
            for member in iter_submission_members(target):
                member_count += 1
                failures.extend(
                    check_member(
                        member,
                        allow_wave33_local_candidates=allow_wave33_local_candidates and not is_archive,
                        allow_nested_archives=allow_nested_archives,
                    )
                )
        except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
            failures.append(str(exc))

    return {
        "status": "fail" if failures else "pass",
        "checks": [
            {
                "name": "repository-submission-no-generated-cache-artifacts",
                "path": str(target),
                "status": "fail" if failures else "pass",
                "message": "; ".join(failures[:60]) if failures else f"scanned {member_count} members",
            }
        ],
    }


def iter_submission_members(target: Path) -> Iterable[SubmissionMember]:
    if target.is_dir():
        yield from iter_directory_members(target)
        return
    if target.suffix.lower() == ".zip":
        yield from iter_zip_members(target)
        return
    suffixes = [suffix.lower() for suffix in target.suffixes]
    if ".tar" in suffixes or target.suffix.lower() in {".tgz", ".tbz2", ".txz"}:
        yield from iter_tar_members(target)
        return
    raise ValueError(f"unsupported submission target type: {target}")


def iter_directory_members(root: Path) -> Iterable[SubmissionMember]:
    for path in sorted(root.rglob("*")):
        yield SubmissionMember(normalize_member_path(path.relative_to(root).as_posix()), path.is_dir())


def iter_tar_members(path: Path) -> Iterable[SubmissionMember]:
    with tarfile.open(path, "r:*") as archive:
        members = [SubmissionMember(member.name, member.isdir()) for member in archive.getmembers()]
    yield from strip_common_archive_root(members)


def iter_zip_members(path: Path) -> Iterable[SubmissionMember]:
    with zipfile.ZipFile(path) as archive:
        members = [SubmissionMember(member.filename, member.is_dir()) for member in archive.infolist()]
    yield from strip_common_archive_root(members)


def strip_common_archive_root(members: list[SubmissionMember]) -> list[SubmissionMember]:
    paths = [normalize_member_path(member.path).rstrip("/") for member in members if normalize_member_path(member.path).rstrip("/")]
    if not paths:
        return members
    first_parts = [path.split("/", 1)[0] for path in paths]
    root = first_parts[0]
    if any(part != root for part in first_parts):
        return members
    lowered_root = root.lower()
    if (
        lowered_root in FORBIDDEN_DIR_NAMES
        or lowered_root.startswith(FORBIDDEN_DIR_PREFIXES)
        or any(prefix.rstrip("/") == lowered_root for prefix in FORBIDDEN_PATH_PREFIXES)
    ):
        return members
    stripped: list[SubmissionMember] = []
    for member in members:
        path = normalize_member_path(member.path)
        suffix = path[len(root) :].lstrip("/")
        if not suffix:
            continue
        if member.is_dir and not suffix.endswith("/"):
            suffix += "/"
        stripped.append(SubmissionMember(suffix, member.is_dir))
    return stripped


def check_member(
    member: SubmissionMember,
    *,
    allow_wave33_local_candidates: bool,
    allow_nested_archives: bool,
) -> list[str]:
    failures: list[str] = []
    raw = member.path
    path = normalize_member_path(raw)
    if is_unsafe_member_path(raw):
        return [f"{raw}: unsafe archive member path"]

    parts = tuple(part for part in path.rstrip("/").split("/") if part)
    path_for_prefix = path.rstrip("/") + "/"
    for prefix in FORBIDDEN_PATH_PREFIXES:
        if path_for_prefix == prefix or path_for_prefix.startswith(prefix):
            if allow_wave33_local_candidates and (path.rstrip("/") == "tmp" or local_wave33_candidate_path(path)):
                continue
            if prefix == "tmp/" and generated_candidate_path(parts):
                failures.append(f"{path}: generated candidate must not be in repository submission")
            else:
                failures.append(f"{path}: forbidden repository submission path prefix {prefix}")
            break
    for index, part in enumerate(parts):
        if part in FORBIDDEN_DIR_NAMES or part.startswith(FORBIDDEN_DIR_PREFIXES):
            if allow_wave33_local_candidates and part == "tmp" and (path.rstrip("/") == "tmp" or local_wave33_candidate_path(path)):
                break
            failures.append(f"{path}: forbidden cache/generated directory {part}")
            break
        if part == "tmp" and generated_candidate_path(parts[index:]):
            if allow_wave33_local_candidates and local_wave33_candidate_path(path):
                break
            failures.append(f"{path}: generated candidate must not be in repository submission")
            break

    name = parts[-1] if parts else ""
    lowered = name.lower()
    is_nested_archive = any(lowered.endswith(suffix) for suffix in NESTED_ARCHIVE_SUFFIXES)
    is_forbidden_generated_file = (
        name in FORBIDDEN_FILE_NAMES
        or any(name.startswith(prefix) for prefix in FORBIDDEN_FILE_PREFIXES)
        or Path(name).suffix.lower() in FORBIDDEN_FILE_SUFFIXES
        or any(lowered.endswith(suffix) for suffix in FORBIDDEN_FILE_SUFFIX_CHAINS)
    )
    if is_forbidden_generated_file and not (allow_nested_archives and is_nested_archive):
        failures.append(f"{path}: forbidden generated/cache file")
    if not allow_nested_archives and is_nested_archive:
        failures.append(f"{path}: nested generated transfer archive is not allowed in repository submission")
    return failures


def generated_candidate_path(parts: tuple[str, ...]) -> bool:
    return any("candidate" in part.lower() for part in parts[1:])


def local_wave33_candidate_path(path: str) -> bool:
    normalized = path.rstrip("/")
    return any(
        normalized == root
        or normalized.startswith(root + "/")
        or normalized == f"{root}.hygiene-allowlist.json"
        or normalized == f"{root}.allowlist.json"
        for root in LOCAL_WAVE33_CANDIDATE_ROOTS
    )


def normalize_member_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized


def is_unsafe_member_path(path: str) -> bool:
    raw = path.replace("\\", "/")
    return raw.startswith("/") or re.match(r"^[A-Za-z]:", raw) is not None or any(part == ".." for part in raw.split("/"))


def clean_generated(repo_root: Path) -> dict[str, object]:
    return clean_generated_paths(repo_root, preserve_frontend_ui_build=False)


def clean_generated_paths(repo_root: Path, *, preserve_frontend_ui_build: bool = False) -> dict[str, object]:
    repo_root = repo_root.resolve()
    removed: list[str] = []
    clean_paths = GENERATED_CLEAN_PATHS
    clean_globs = GENERATED_CLEAN_GLOBS
    if preserve_frontend_ui_build:
        clean_paths = tuple(
            relative
            for relative in GENERATED_CLEAN_PATHS
            if relative
            not in {
                "frontend/dist",
                "frontend/node_modules",
            }
        )
        clean_globs = tuple(pattern for pattern in GENERATED_CLEAN_GLOBS if pattern != "frontend/*.tsbuildinfo")
    for relative in clean_paths:
        target = (repo_root / relative).resolve()
        if remove_generated_target(repo_root, target):
            removed.append(relative)
    for pattern in clean_globs:
        for target in repo_root.glob(pattern):
            if remove_generated_target(repo_root, target.resolve()):
                removed.append(target.relative_to(repo_root).as_posix())
    return {
        "status": "pass",
        "removed": sorted(set(removed)),
    }


def create_repository_submission_archive(repo_root: Path, output_path: Path) -> dict[str, object]:
    repo_root = repo_root.resolve()
    output_path = output_path.resolve()
    if not repo_root.is_dir():
        raise ValueError(f"repository root does not exist or is not a directory: {repo_root}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    skipped: list[str] = []
    written: list[str] = []
    artifact_reference = artifact_reference_payload(repo_root)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted((item for item in repo_root.rglob("*") if item.is_file()), key=lambda item: item.relative_to(repo_root).as_posix()):
            relative = path.relative_to(repo_root).as_posix()
            if should_exclude_from_submission_archive(repo_root, path, output_path):
                skipped.append(relative)
                continue
            archive_name = f"{REPOSITORY_SUBMISSION_ROOT}/{relative}"
            write_zip_member(archive, archive_name, path.read_bytes())
            written.append(relative)
        reference_name = f"{REPOSITORY_SUBMISSION_ROOT}/{REPOSITORY_ARTIFACT_REFERENCE}"
        write_zip_member(archive, reference_name, (json.dumps(artifact_reference, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        written.append(REPOSITORY_ARTIFACT_REFERENCE)
        readme_name = f"{REPOSITORY_SUBMISSION_ROOT}/{REPOSITORY_SUBMISSION_README}"
        write_zip_member(archive, readme_name, REPOSITORY_SUBMISSION_README_TEXT.encode("utf-8"))
        written.append(REPOSITORY_SUBMISSION_README)

    digest = sha256_path(output_path)
    validation = validate_repository_submission(output_path)
    return {
        "status": validation["status"],
        "archive": str(output_path),
        "sha256": digest,
        "member_count": len(written),
        "skipped_count": len(skipped),
        "artifact_reference": artifact_reference,
        "validation": validation,
    }


def should_exclude_from_submission_archive(repo_root: Path, path: Path, output_path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(repo_root)
    except ValueError:
        return True
    if path.resolve() == output_path:
        return True
    parts = relative.parts
    if not is_allowlisted_submission_path(relative):
        return True
    if any(part in ARCHIVE_BUILDER_EXCLUDED_DIR_NAMES for part in parts):
        return True
    if check_member(
        SubmissionMember(relative.as_posix(), path.is_dir()),
        allow_wave33_local_candidates=False,
        allow_nested_archives=False,
    ):
        return True
    return False


def is_allowlisted_submission_path(relative: Path) -> bool:
    parts = relative.parts
    if not parts:
        return False
    if len(parts) == 1:
        return parts[0] in ARCHIVE_BUILDER_ALLOWED_TOP_LEVEL_FILES
    return parts[0] in ARCHIVE_BUILDER_ALLOWED_TOP_LEVEL_DIRS


def artifact_reference_payload(repo_root: Path) -> dict[str, object]:
    canonical_paths = (
        "out/artifacts/sentinel-aml-player-source.tar.gz",
        "out/artifacts/sentinel-aml-admin-organizer.tar.gz",
        "out/artifacts/sentinel-aml-player-binary.tar.gz",
    )
    artifacts_by_path: dict[str, dict[str, str]] = {}
    for relative in canonical_paths:
        artifact = repo_root / relative
        if artifact.is_file():
            artifacts_by_path[relative] = {"path": relative, "sha256": sha256_path(artifact)}

    checksum_paths = (repo_root / "out" / "artifacts" / "SHA256SUMS", repo_root / "out" / "checksums" / "SHA256SUMS")
    source_checksum_path = next((path.relative_to(repo_root).as_posix() for path in checksum_paths if path.is_file()), "")
    for checksum_path in checksum_paths:
        if not checksum_path.is_file():
            continue
        for reference in checksum_artifact_references(checksum_path):
            if reference["path"] in canonical_paths and reference["path"] not in artifacts_by_path:
                artifacts_by_path[reference["path"]] = reference
    return {
        "schema": "sentinel-aml-repository-submission-artifact-references.v1",
        "archive_role": "internal-repository-submission",
        "player_facing": False,
        "repository_submission_not_player_artifact": True,
        "transfer_artifacts_nested": False,
        "player_source_artifact": "out/artifacts/sentinel-aml-player-source.tar.gz",
        "admin_organizer_artifact": "out/artifacts/sentinel-aml-admin-organizer.tar.gz",
        "checksums_path": source_checksum_path or "out/artifacts/SHA256SUMS",
        "artifacts": sorted(artifacts_by_path.values(), key=lambda item: item["path"]),
    }


def checksum_artifact_references(checksum_path: Path) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, relative = line.partition("  ")
        if relative.startswith("artifacts/"):
            path = f"out/{relative}"
        elif relative.startswith("sentinel-aml-"):
            path = f"out/artifacts/{relative}"
        else:
            continue
        references.append({"path": path, "sha256": digest})
    return references


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def remove_generated_target(repo_root: Path, target: Path) -> bool:
    if not target.exists():
        return False
    if not is_safe_generated_cleanup_target(repo_root, target):
        raise RuntimeError(f"refusing to clean unsafe generated target: {target}")
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    return True


def is_safe_generated_cleanup_target(repo_root: Path, target: Path) -> bool:
    try:
        relative = target.relative_to(repo_root)
    except ValueError:
        return False
    if not relative.parts:
        return False
    normalized = relative.as_posix()
    allowed = set(GENERATED_CLEAN_PATHS)
    if normalized in allowed:
        return True
    if normalized.startswith(("frontend/", ".gocache", ".appdata")):
        return True
    if normalized in {".pytest_cache", ".mypy_cache", ".ruff_cache"}:
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target",
        nargs="?",
        type=Path,
        default=Path.cwd(),
        help="repository submission archive or extracted tree to scan",
    )
    parser.add_argument(
        "--allow-wave33-local-candidates",
        action="store_true",
        help="permit known ignored tmp/*candidate* directories in a live local Wave 33 workspace only",
    )
    parser.add_argument(
        "--allow-nested-archives",
        action="store_true",
        help="permit nested archive files only for an explicitly documented non-submission scan",
    )
    parser.add_argument(
        "--clean-generated",
        action="store_true",
        help="remove known local generated outputs from the repository workspace",
    )
    parser.add_argument(
        "--preserve-frontend-ui-build",
        action="store_true",
        help="with --clean-generated, keep frontend/dist, frontend/node_modules, and TypeScript build info for canonical player UI artifact builds",
    )
    parser.add_argument(
        "--create-archive",
        action="store_true",
        help="create a clean deterministic repository-submission zip and validate its bytes",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_REPOSITORY_SUBMISSION_ARCHIVE,
        help="output path for --create-archive",
    )
    args = parser.parse_args(argv)

    if args.clean_generated:
        result = clean_generated_paths(args.target, preserve_frontend_ui_build=args.preserve_frontend_ui_build)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.create_archive:
        result = create_repository_submission_archive(args.target, args.output)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "pass" else 1

    result = validate_repository_submission(
        args.target,
        allow_wave33_local_candidates=args.allow_wave33_local_candidates,
        allow_nested_archives=args.allow_nested_archives,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
