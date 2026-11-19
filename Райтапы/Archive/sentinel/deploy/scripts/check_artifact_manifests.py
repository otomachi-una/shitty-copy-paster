#!/usr/bin/env python3
"""Validate player source artifact manifest and checksum files."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


MANIFEST_NAME = "PLAYER_SOURCE_MANIFEST.json"
CHECKSUM_NAME = "SHA256SUMS"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--checksums", type=Path)
    args = parser.parse_args(argv)
    result = check_manifest(args.artifact, args.manifest, args.checksums)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def check_manifest(artifact: Path, manifest: Path | None = None, checksums: Path | None = None) -> dict[str, object]:
    manifest = manifest or artifact.parent / MANIFEST_NAME
    checksums = checksums or artifact.parent / CHECKSUM_NAME
    failures: list[str] = []
    if not artifact.is_file():
        failures.append(f"missing artifact {artifact}")
    if not manifest.is_file():
        failures.append(f"missing manifest {manifest}")
    if not checksums.is_file():
        failures.append(f"missing checksums {checksums}")
    if failures:
        return result(failures)

    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    artifact_sha = sha256_file(artifact)
    if manifest_data.get("artifact", {}).get("sha256") != artifact_sha:
        failures.append("manifest artifact sha256 does not match bytes")
    if manifest_data.get("artifact", {}).get("primary_player_artifact") is not True:
        failures.append("manifest must mark source artifact primary")
    if manifest_data.get("artifact", {}).get("flattened_competition_tree") is not True:
        failures.append("manifest must mark flattened source tree")
    checksum_pairs = parse_checksums(checksums)
    if checksum_pairs.get(artifact.name) != artifact_sha:
        failures.append("SHA256SUMS missing artifact digest")
    if checksum_pairs.get(manifest.name) != sha256_file(manifest):
        failures.append("SHA256SUMS missing manifest digest")
    return result(failures, manifest_data.get("artifact", {}).get("file_count"))


def result(failures: list[str], file_count: int | None = None) -> dict[str, object]:
    return {
        "status": "pass" if not failures else "fail",
        "file_count": file_count,
        "checks": [
            {
                "name": "player-source-manifest",
                "status": "pass" if not failures else "fail",
                "message": "; ".join(failures),
            }
        ],
    }


def parse_checksums(path: Path) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        pairs[name.strip()] = digest
    return pairs


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
