#!/usr/bin/env python3
"""Validate admin/organizer artifact hygiene and separation."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import tarfile
from pathlib import Path
from typing import Any


ARCHIVE_ROOT = "sentinel-aml-admin-organizer"
FORBIDDEN_SEGMENTS = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vscode",
    "__pycache__",
    "node_modules",
    "out",
    "temp",
    "tmp",
    "dist",
    "playwright-report",
    "test-results",
}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".exe", ".map", ".tar", ".tgz", ".zip", ".tsbuildinfo", ".test"}
FORBIDDEN_SUFFIX_CHAINS = (".tar.gz",)
FORBIDDEN_PREFIXES = (
    "sentinel-aml-player-source/",
    "sentinel-aml-player-service/",
    "sentinel-aml-player-binary/",
    "frontend/node_modules/",
    "frontend/dist/",
    "validation/admin-extracted/",
    "validation/exact-artifact-live/",
    "validation/organizer-extracted/",
    "validation/player-extracted/",
    "validation/unit-live-acceptance/",
    "validation/unit-live-acceptance-bad/",
)
FORBIDDEN_FILENAMES = {
    "sentinel-aml-player-source.tar.gz",
    "sentinel-aml-player-binary.tar.gz",
    "sentinel-aml-player-service.tar.gz",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args(argv)
    result = check_admin_artifact_hygiene(args.artifact)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def check_admin_artifact_hygiene(artifact: Path) -> dict[str, Any]:
    findings: list[dict[str, object]] = []
    if not artifact.is_file():
        findings.append(finding(artifact.as_posix(), "artifact", "artifact is missing"))
        return report(artifact, 0, findings)
    files, content = load_archive(artifact)
    for path in files:
        reason = forbidden_path_reason(path)
        if reason:
            findings.append(finding(path, Path(path).name, reason))
    manifest = parse_manifest(content.get("ADMIN_MANIFEST.json"), findings)
    if manifest:
        artifact_meta = manifest.get("artifact", {})
        if artifact_meta.get("player_facing") is not False or artifact_meta.get("organizer_only") is not True:
            findings.append(finding("ADMIN_MANIFEST.json", "organizer_only", "manifest must label artifact as organizer-only and non-player-facing"))
        if artifact_meta.get("archive_root") != ARCHIVE_ROOT:
            findings.append(finding("ADMIN_MANIFEST.json", "archive_root", "archive root mismatch"))
    readme = content.get("README_ADMIN.md", b"").decode("utf-8", errors="ignore").lower()
    if "organizer-only" not in readme or "must not be distributed to participant teams" not in readme:
        findings.append(finding("README_ADMIN.md", "organizer-only", "admin runbook must clearly label sensitive organizer-only package"))
    if "do not copy this package into player source distributions" not in readme:
        findings.append(finding("README_ADMIN.md", "player-source-separation", "admin runbook must warn against player package mixing"))
    return report(artifact, len(files), findings)


def forbidden_path_reason(path: str) -> str:
    normalized = path.replace("\\", "/").strip("/")
    lowered = normalized.lower()
    parts = [part.lower() for part in lowered.split("/") if part]
    if any(lowered.startswith(prefix) for prefix in FORBIDDEN_PREFIXES):
        return "participant/generated extraction path is forbidden"
    if any(part in FORBIDDEN_SEGMENTS or part.startswith((".appdata", ".gocache")) for part in parts):
        return "generated/cache path segment is forbidden"
    if parts and parts[-1] in FORBIDDEN_FILENAMES:
        return "nested player transfer artifact is forbidden"
    if any(lowered.endswith(suffix) for suffix in FORBIDDEN_SUFFIX_CHAINS):
        return "nested transfer archive is forbidden"
    if Path(lowered).suffix in FORBIDDEN_SUFFIXES:
        return "generated/cache/archive file suffix is forbidden"
    return ""


def load_archive(artifact: Path) -> tuple[list[str], dict[str, bytes]]:
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        files: list[str] = []
        content: dict[str, bytes] = {}
        for member in archive.getmembers():
            if not member.isfile():
                continue
            if not member.name.startswith(f"{ARCHIVE_ROOT}/"):
                raise ValueError(f"unexpected archive root: {member.name}")
            relative = member.name[len(ARCHIVE_ROOT) + 1 :]
            files.append(relative)
            handle = archive.extractfile(member)
            if handle is not None:
                content[relative] = handle.read()
        return sorted(files), content


def parse_manifest(raw: bytes | None, findings: list[dict[str, object]]) -> dict[str, Any] | None:
    if raw is None:
        findings.append(finding("ADMIN_MANIFEST.json", "manifest", "manifest is missing"))
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(finding("ADMIN_MANIFEST.json", "json", str(exc)))
        return None


def report(artifact: Path, file_count: int, findings: list[dict[str, object]]) -> dict[str, Any]:
    return {
        "status": "pass" if not findings else "fail",
        "artifact": artifact.as_posix(),
        "file_count": file_count,
        "hit_count": len(findings),
        "findings": findings,
        "checks": [
            {
                "name": "admin-artifact-hygiene",
                "status": "pass" if not findings else "fail",
                "message": "" if not findings else f"findings={len(findings)}",
            }
        ],
    }


def finding(path: str, token: str, reason: str) -> dict[str, object]:
    return {"path": path, "line": 0, "token": token, "severity": "critical", "allowlisted": False, "reason": reason}


if __name__ == "__main__":
    raise SystemExit(main())
