#!/usr/bin/env python3
"""Build the ForcAD runtime checker artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ROOT = "sentinel_aml"
DEFAULT_OUTPUT = ROOT / "inputs" / "jury-runtime" / "sentinel-aml-checker-runtime.tar.gz"
MANIFEST_NAME = "CHECKER_RUNTIME_MANIFEST.json"
CHECKSUM_NAME = "SHA256SUMS"
FIXED_MTIME = 0
CHECKER_FILES = (
    "checker.py",
    "checker_lib.py",
    "requirements.txt",
)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = build_checker_runtime_artifact(args.output)
    except Exception as exc:
        print(json.dumps({"status": "fail", "message": str(exc)}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args(argv)


def build_checker_runtime_artifact(output: Path) -> dict[str, object]:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_path = output.parent / MANIFEST_NAME
    checksum_path = output.parent / CHECKSUM_NAME

    with tempfile.TemporaryDirectory(prefix="sentinel-aml-checker-runtime-") as tmp:
        stage = Path(tmp) / ARCHIVE_ROOT
        stage.mkdir(parents=True)
        for name in CHECKER_FILES:
            source = ROOT / "checkers" / "sentinel_aml" / name
            if not source.is_file():
                raise FileNotFoundError(f"required checker runtime file missing: {source.relative_to(ROOT).as_posix()}")
            (stage / name).write_bytes(source.read_bytes())
        files = sorted(path.relative_to(stage) for path in stage.rglob("*") if path.is_file())
        archive_entries = write_archive(stage, output, files)

    artifact_sha = sha256_file(output)
    manifest = {
        "schema": "sentinel-aml-checker-runtime-manifest.v1",
        "artifact": {
            "name": output.name,
            "path": output.as_posix(),
            "sha256": artifact_sha,
            "archive_root": ARCHIVE_ROOT,
            "file_count": len(archive_entries),
            "artifact_class": "checker-runtime",
            "player_facing": False,
        },
        "included_files": [entry["path"] for entry in archive_entries],
        "excluded_material": [
            "sploits/",
            "fixes/",
            "organizer docs",
            "validation reports",
            "service source",
            "secrets",
        ],
        "files": archive_entries,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    checksum_path.write_text(
        f"{artifact_sha}  {output.name}\n{sha256_file(manifest_path)}  {manifest_path.name}\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "status": "pass",
        "artifact": output.as_posix(),
        "sha256": artifact_sha,
        "file_count": len(archive_entries),
        "manifest": manifest_path.as_posix(),
        "checksums": checksum_path.as_posix(),
    }


def write_archive(stage: Path, output: Path, files: list[Path]) -> list[dict[str, object]]:
    payload = io.BytesIO()
    entries: list[dict[str, object]] = []
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for relative in files:
            source = stage / relative
            member_name = f"{ARCHIVE_ROOT}/{relative.as_posix()}"
            info = archive.gettarinfo(str(source), arcname=member_name)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = FIXED_MTIME
            info.mode = 0o755 if relative.as_posix() == "checker.py" else 0o644
            digest = sha256_file(source)
            with source.open("rb") as handle:
                archive.addfile(info, handle)
            entries.append({"path": member_name, "sha256": digest, "size_bytes": source.stat().st_size})
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=FIXED_MTIME) as gz:
            gz.write(payload.getvalue())
    return entries


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
