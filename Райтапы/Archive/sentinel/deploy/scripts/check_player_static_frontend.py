#!/usr/bin/env python3
"""Validate that a player artifact carries a built static frontend bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path


ARCHIVE_ROOT = "sentinel-aml-player-source"
STATIC_ROOT = "web/dist"


@dataclass(frozen=True)
class Finding:
    path: str
    token: str
    message: str


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = check_player_static_frontend(args.artifact)
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--json-report", type=Path)
    return parser.parse_args(argv)


def check_player_static_frontend(artifact: Path) -> dict[str, object]:
    findings: list[Finding] = []
    members: dict[str, tarfile.TarInfo] = {}
    if not artifact.is_file():
        findings.append(Finding(artifact.as_posix(), "artifact", "artifact is missing"))
        return report(artifact, findings, 0, None, [])
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        members = {strip_root(member.name): member for member in archive.getmembers() if member.isfile()}
        required = (f"{STATIC_ROOT}/index.html", f"{STATIC_ROOT}/runtime-config.js")
        for path in required:
            if path not in members:
                findings.append(Finding(path, "required-file", "static frontend runtime file is missing"))
        static_files = sorted(path for path in members if path.startswith(f"{STATIC_ROOT}/"))
        if len(static_files) < 3:
            findings.append(Finding(STATIC_ROOT, "file-count", "static frontend bundle must include index, runtime config, and at least one asset"))
        for path in static_files:
            if path.lower().endswith(".map"):
                findings.append(Finding(path, ".map", "source maps are forbidden in player static frontend"))
        refs: list[str] = []
        if f"{STATIC_ROOT}/index.html" in members:
            index = read_member(archive, members[f"{STATIC_ROOT}/index.html"].name)
            refs = referenced_assets(index)
            if "Sentinel AML" not in index:
                findings.append(Finding(f"{STATIC_ROOT}/index.html", "title", "static frontend index must be the built Sentinel AML UI"))
            for ref in refs:
                target = f"{STATIC_ROOT}/{ref}"
                if target not in members:
                    findings.append(Finding(target, "asset-ref", "index.html references a missing static asset"))
        digest = sha256_members(archive, [members[path] for path in static_files]) if static_files else None
    return report(artifact, findings, len(static_files), digest, refs)


def report(artifact: Path, findings: list[Finding], file_count: int, digest: str | None, refs: list[str]) -> dict[str, object]:
    return {
        "status": "fail" if findings else "pass",
        "artifact": artifact.as_posix(),
        "static_root": STATIC_ROOT,
        "frontend_static_sha256": digest,
        "frontend_dist_file_count": file_count,
        "referenced_assets": refs,
        "findings": [asdict(finding) for finding in findings],
    }


def referenced_assets(index: str) -> list[str]:
    refs: list[str] = []
    for match in re.finditer(r"""(?:src|href)=["']([^"']+)["']""", index):
        ref = match.group(1)
        if ref.startswith(("http://", "https://", "data:")):
            continue
        refs.append(ref.lstrip("/"))
    return refs


def sha256_members(archive: tarfile.TarFile, members: list[tarfile.TarInfo]) -> str:
    digest = hashlib.sha256()
    for member in sorted(members, key=lambda item: strip_root(item.name)):
        path = strip_root(member.name).removeprefix(f"{STATIC_ROOT}/").encode("utf-8")
        digest.update(path)
        digest.update(b"\0")
        data = archive.extractfile(member)
        content = data.read() if data is not None else b""
        digest.update(hashlib.sha256(content).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def read_member(archive: tarfile.TarFile, name: str) -> str:
    handle = archive.extractfile(name)
    return "" if handle is None else handle.read().decode("utf-8", errors="ignore")


def strip_root(path: str) -> str:
    prefix = f"{ARCHIVE_ROOT}/"
    return path[len(prefix) :] if path.startswith(prefix) else path


if __name__ == "__main__":
    raise SystemExit(main())
