#!/usr/bin/env python3
"""Validate that the player artifact excludes frontend source/build inputs."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path


ARCHIVE_ROOT = "sentinel-aml-player-source"
FORBIDDEN_PREFIXES = (
    "frontend/",
    "node_modules/",
)
FORBIDDEN_NAMES = {
    "package.json",
    "package-lock.json",
    "vite.config.ts",
    "vite.config.js",
    "tsconfig.json",
    "tsconfig.app.json",
    "tsconfig.node.json",
    "playwright.config.ts",
}
FORBIDDEN_PARTS = {
    "coverage",
    "playwright-report",
    "test-results",
}
FORBIDDEN_SUFFIXES = (".map", ".tsx", ".tsbuildinfo")


@dataclass(frozen=True)
class Finding:
    path: str
    token: str
    message: str


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = check_player_no_frontend_source(args.artifact)
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


def check_player_no_frontend_source(artifact: Path) -> dict[str, object]:
    findings: list[Finding] = []
    if not artifact.is_file():
        findings.append(Finding(artifact.as_posix(), "artifact", "artifact is missing"))
        return report(artifact, findings)
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            path = strip_root(member.name)
            lowered = path.lower()
            parts = set(Path(path).parts)
            if lowered.startswith(FORBIDDEN_PREFIXES):
                findings.append(Finding(path, "frontend-source", "frontend source/build input path is forbidden"))
            if Path(path).name in FORBIDDEN_NAMES:
                findings.append(Finding(path, Path(path).name, "frontend package/build metadata is forbidden"))
            if parts & FORBIDDEN_PARTS:
                findings.append(Finding(path, sorted(parts & FORBIDDEN_PARTS)[0], "frontend test or coverage output is forbidden"))
            if lowered.endswith(FORBIDDEN_SUFFIXES):
                findings.append(Finding(path, Path(path).suffix, "frontend source map or TypeScript build artifact is forbidden"))
    return report(artifact, findings)


def report(artifact: Path, findings: list[Finding]) -> dict[str, object]:
    return {
        "status": "fail" if findings else "pass",
        "artifact": artifact.as_posix(),
        "findings": [asdict(finding) for finding in findings],
    }


def strip_root(path: str) -> str:
    prefix = f"{ARCHIVE_ROOT}/"
    return path[len(prefix) :] if path.startswith(prefix) else path


if __name__ == "__main__":
    raise SystemExit(main())
