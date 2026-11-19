#!/usr/bin/env python3
"""Build a deterministic Sentinel AML release archive outside the repository."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Iterable

try:
    import check_archive_hygiene
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import check_archive_hygiene


DEFAULT_ARCHIVE_NAME = "sentinel_aml_release.tar.gz"
EXCLUDED_DIR_NAMES = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vscode",
    "__pycache__",
    "bin",
    "tmp",
    "temp",
}
EXCLUDED_DIR_PREFIXES = (
    ".appdata",
    ".gocache",
)
EXCLUDED_FILE_NAMES = {
    ".coverage",
    ".DS_Store",
    ".env",
    "Thumbs.db",
    "coverage.out",
}
EXCLUDED_FILE_PREFIXES = (
    ".env.",
)
EXCLUDED_FILE_SUFFIXES = {
    ".coverprofile",
    ".exe",
    ".pyc",
    ".pyo",
    ".tar",
    ".test",
    ".tgz",
    ".zip",
}
EXCLUDED_FILE_SUFFIX_CHAINS = (
    ".tar.gz",
)
EXCLUDED_PREFIXES = (
    ("docs", "archive"),
)


def build_release_archive(repo_root: Path, output_dir: Path, archive_name: str = DEFAULT_ARCHIVE_NAME) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    ensure_output_outside_repo(repo_root, output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    archive_path = output_dir / archive_name
    files = list(iter_release_files(repo_root))
    tar_payload = build_tar_payload(repo_root, files)
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(tar_payload)

    checksum = sha256_file(archive_path)
    hygiene = check_archive_hygiene.validate_archive_hygiene(archive_path)
    required_missing = sorted(check_archive_hygiene.REQUIRED_RELEASE_FILES - {path.as_posix() for path in files})
    status = "pass" if hygiene["status"] == "pass" and not required_missing else "fail"
    return {
        "archive": str(archive_path),
        "checks": [
            {
                "name": "release-archive-output-outside-repo",
                "path": str(output_dir),
                "status": "pass",
                "message": "",
            },
            {
                "name": "release-archive-required-files",
                "path": str(archive_path),
                "status": "pass" if not required_missing else "fail",
                "message": "" if not required_missing else f"missing required files: {', '.join(required_missing)}",
            },
            {
                "name": "release-archive-hygiene",
                "path": str(archive_path),
                "status": hygiene["status"],
                "message": hygiene["checks"][0]["message"],
            },
        ],
        "file_count": len(files),
        "sha256": checksum,
        "status": status,
    }


def ensure_output_outside_repo(repo_root: Path, output_dir: Path) -> None:
    try:
        output_dir.relative_to(repo_root)
    except ValueError:
        return
    raise ValueError("release archive output directory must be outside the repository")


def iter_release_files(repo_root: Path) -> Iterable[Path]:
    for path in sorted((entry for entry in repo_root.rglob("*") if entry.is_file()), key=lambda item: item.relative_to(repo_root).as_posix()):
        relative = path.relative_to(repo_root)
        if should_exclude(relative):
            continue
        yield relative


def should_exclude(relative: Path) -> bool:
    parts = relative.parts
    if any(parts[: len(prefix)] == prefix for prefix in EXCLUDED_PREFIXES):
        return True
    if any(part in EXCLUDED_DIR_NAMES or part.startswith(EXCLUDED_DIR_PREFIXES) for part in parts[:-1]):
        return True
    name = relative.name
    lowered = name.lower()
    return (
        name in EXCLUDED_FILE_NAMES
        or name.startswith(EXCLUDED_FILE_PREFIXES)
        or relative.suffix.lower() in EXCLUDED_FILE_SUFFIXES
        or any(lowered.endswith(suffix) for suffix in EXCLUDED_FILE_SUFFIX_CHAINS)
    )


def build_tar_payload(repo_root: Path, files: list[Path]) -> bytes:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for relative in files:
            source = repo_root / relative
            info = archive.gettarinfo(str(source), arcname=relative.as_posix())
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.mode = 0o644
            with source.open("rb") as handle:
                archive.addfile(info, handle)
    return payload.getvalue()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a deterministic Sentinel AML release archive")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(os.environ.get("TMPDIR") or tempfile.gettempdir()) / "sentinel-aml-release",
    )
    parser.add_argument("--archive-name", default=DEFAULT_ARCHIVE_NAME)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = build_release_archive(args.repo_root, args.output_dir, args.archive_name)
    except Exception as exc:
        result = {
            "status": "fail",
            "checks": [
                {
                    "name": "release-archive-build",
                    "path": str(args.output_dir),
                    "status": "fail",
                    "message": str(exc),
                }
            ],
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
