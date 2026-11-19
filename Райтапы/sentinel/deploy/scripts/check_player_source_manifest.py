#!/usr/bin/env python3
"""Validate the canonical player-source manifest and artifact digest binding."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = ROOT / "out"
ARTIFACT_NAME = "sentinel-aml-player-source.tar.gz"
MANIFEST_NAME = "player_source_manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"


@dataclass(frozen=True)
class Finding:
    path: str
    message: str


def main() -> int:
    args = parse_args()
    if args.artifact:
        result = check_player_source_manifest_files(args.artifact, args.manifest, args.checksums)
    else:
        result = check_player_source_manifest(args.output_root)
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", nargs="?", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--checksums", type=Path)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--json-report", type=Path)
    return parser.parse_args()


def check_player_source_manifest_files(
    artifact: Path,
    manifest: Path | None = None,
    checksums: Path | None = None,
) -> dict[str, object]:
    artifact = artifact.resolve()
    manifest = (manifest or artifact.parent / "PLAYER_SOURCE_MANIFEST.json").resolve()
    checksums = (checksums or artifact.parent / CHECKSUMS_NAME).resolve()
    root = artifact.parent
    findings: list[Finding] = []

    if not artifact.is_file():
        findings.append(Finding(artifact.as_posix(), "player-source artifact is missing"))
    if not manifest.is_file():
        findings.append(Finding(manifest.as_posix(), "player-source manifest is missing"))
    if not checksums.is_file():
        findings.append(Finding(checksums.as_posix(), "artifact checksum file is missing"))

    manifest_data: dict[str, object] = {}
    if manifest.is_file():
        try:
            manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            findings.append(Finding(manifest.as_posix(), f"manifest is not valid JSON: {exc}"))

    artifact_sha = sha256_file(artifact) if artifact.is_file() else None
    manifest_artifact = manifest_data.get("artifact", {}) if isinstance(manifest_data.get("artifact"), dict) else {}
    if manifest_data:
        if manifest_artifact.get("sha256") != artifact_sha:
            findings.append(Finding(manifest.as_posix(), "manifest artifact SHA does not match current artifact bytes"))
        if manifest_artifact.get("primary_player_artifact") is not True:
            findings.append(Finding(manifest.as_posix(), "manifest must mark source artifact primary"))
        if manifest_artifact.get("distribution_model") not in {"source-based-player", "backend-source-static-frontend-player"}:
            findings.append(Finding(manifest.as_posix(), "manifest artifact distribution_model must be backend-source-static-frontend-player"))
        if manifest_artifact.get("flattened_competition_tree") is not True:
            findings.append(Finding(manifest.as_posix(), "manifest must mark flattened source tree"))

    checksum_entries = parse_checksums(checksums) if checksums.is_file() else {}
    if artifact_sha and checksum_entries.get(artifact.name) != artifact_sha:
        findings.append(Finding(checksums.as_posix(), f"checksum entry for {artifact.name} does not match current artifact bytes"))
    if manifest.is_file() and checksum_entries.get(manifest.name) != sha256_file(manifest):
        findings.append(Finding(checksums.as_posix(), f"checksum entry for {manifest.name} does not match current manifest bytes"))

    return {
        "status": "fail" if findings else "pass",
        "output_root": str(root),
        "artifact": artifact.as_posix(),
        "manifest": manifest.as_posix(),
        "artifact_sha256": artifact_sha,
        "findings": [asdict(finding) for finding in findings],
    }


def check_player_source_manifest(output_root: Path) -> dict[str, object]:
    output_root = output_root.resolve()
    artifact = output_root / "artifacts" / ARTIFACT_NAME
    manifest = output_root / "manifests" / MANIFEST_NAME
    checksums = output_root / "checksums" / CHECKSUMS_NAME
    findings: list[Finding] = []

    if not artifact.is_file():
        findings.append(Finding(relative(output_root, artifact), "canonical player-source artifact is missing"))
    if not manifest.is_file():
        findings.append(Finding(relative(output_root, manifest), "canonical player-source manifest is missing"))
    if not checksums.is_file():
        findings.append(Finding(relative(output_root, checksums), "artifact checksum file is missing"))

    manifests_dir = output_root / "manifests"
    if manifests_dir.is_dir():
        source_manifests = sorted(path.name for path in manifests_dir.glob("*source*manifest*.json"))
        if source_manifests != [MANIFEST_NAME]:
            findings.append(Finding(relative(output_root, manifests_dir), f"expected one canonical source manifest {MANIFEST_NAME}; found {source_manifests}"))

    manifest_data: dict[str, object] = {}
    if manifest.is_file():
        try:
            manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            findings.append(Finding(relative(output_root, manifest), f"manifest is not valid JSON: {exc}"))

    artifact_sha = sha256_file(artifact) if artifact.is_file() else None
    manifest_artifact = manifest_data.get("artifact", {}) if isinstance(manifest_data.get("artifact"), dict) else {}
    contract = manifest_data.get("artifact_contract", {}) if isinstance(manifest_data.get("artifact_contract"), dict) else {}
    if manifest_data:
        expected = {
            "name": ARTIFACT_NAME,
            "artifact_class": "player-source",
            "primary": True,
            "player_facing": True,
        }
        for key, value in expected.items():
            if manifest_artifact.get(key) != value:
                findings.append(Finding(relative(output_root, manifest), f"artifact.{key}={manifest_artifact.get(key)!r}; expected {value!r}"))
        if manifest_artifact.get("distribution_model") not in {"source-based-player", "backend-source-static-frontend-player"}:
            findings.append(Finding(relative(output_root, manifest), "artifact.distribution_model must be backend-source-static-frontend-player"))
        if contract.get("primary_player_artifact") is not True:
            findings.append(Finding(relative(output_root, manifest), "artifact_contract.primary_player_artifact must be true"))
        if contract.get("distribution_model") not in {"source-based-player", "backend-source-static-frontend-player"}:
            findings.append(Finding(relative(output_root, manifest), "artifact_contract.distribution_model must be backend-source-static-frontend-player"))
        if artifact_sha and manifest_artifact.get("sha256") != artifact_sha:
            findings.append(Finding(relative(output_root, manifest), "manifest artifact SHA does not match current artifact bytes"))
        if artifact.is_file() and manifest_artifact.get("size_bytes") not in (None, artifact.stat().st_size):
            findings.append(Finding(relative(output_root, manifest), "manifest artifact size does not match current artifact bytes"))

    checksum_entries = parse_checksums(checksums) if checksums.is_file() else {}
    checksum_key = f"artifacts/{ARTIFACT_NAME}"
    if artifact_sha and checksum_entries.get(checksum_key) != artifact_sha:
        findings.append(Finding(relative(output_root, checksums), f"checksum entry for {checksum_key} does not match current artifact bytes"))

    return {
        "status": "fail" if findings else "pass",
        "output_root": str(output_root),
        "artifact": relative(output_root, artifact),
        "manifest": relative(output_root, manifest),
        "artifact_sha256": artifact_sha,
        "findings": [asdict(finding) for finding in findings],
    }


def parse_checksums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            entries[parts[1].replace("\\", "/")] = parts[0]
    return entries


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    raise SystemExit(main())
