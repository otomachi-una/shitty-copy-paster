#!/usr/bin/env python3
"""Check player source artifact members for dual-policy source patterns."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import tarfile
from pathlib import Path


ARCHIVE_ROOT = "sentinel-aml-player-source"
PAIR_SUFFIX_RE = re.compile(r"^(?P<stem>.+)_(?P<kind>default|detail)\.go$")
FORBIDDEN_PATTERNS = (
    re.compile(r".*_secure\.[^.]+$"),
    re.compile(r".*_vulnerable\.[^.]+$"),
    re.compile(r".*_profile_.*\.[^.]+$"),
    re.compile(r"profile_.*\.[^.]+$"),
    re.compile(r".*_policy_.*\.[^.]+$"),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args(argv)
    result = check_no_dual_policy(args.artifact)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def check_no_dual_policy(artifact: Path) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    if not artifact.is_file():
        return {
            "status": "fail",
            "hit_count": 1,
            "findings": [finding(artifact.as_posix(), "artifact", "artifact is missing")],
        }
    paths = archive_paths(artifact)
    by_dir_stem: dict[tuple[str, str], set[str]] = {}
    for path in paths:
        if path.startswith("vendor/"):
            continue
        name = Path(path).name
        for pattern in FORBIDDEN_PATTERNS:
            if pattern.fullmatch(name):
                findings.append(finding(path, name, "filename reveals alternate policy role"))
        match = PAIR_SUFFIX_RE.fullmatch(name)
        if match:
            key = (Path(path).parent.as_posix(), match.group("stem"))
            by_dir_stem.setdefault(key, set()).add(match.group("kind"))
            findings.append(finding(path, name, "filename suggests default/detail policy split"))
    for (directory, stem), kinds in sorted(by_dir_stem.items()):
        if {"default", "detail"} <= kinds:
            findings.append(finding(f"{directory}/{stem}_*.go", "default/detail", "dual policy source pair is forbidden"))
    return {
        "status": "pass" if not findings else "fail",
        "artifact": artifact.as_posix(),
        "hit_count": len(findings),
        "findings": findings,
        "checks": [
            {
                "name": "player-source-no-dual-policy",
                "status": "pass" if not findings else "fail",
                "message": "" if not findings else f"dual policy findings={len(findings)}",
            }
        ],
    }


def finding(path: str, token: str, reason: str) -> dict[str, object]:
    return {"path": path, "line": 0, "token": token, "severity": "critical", "allowlisted": False, "reason": reason}


def archive_paths(artifact: Path) -> list[str]:
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        return sorted(strip_root(member.name) for member in archive.getmembers() if member.isfile())


def strip_root(path: str) -> str:
    prefix = f"{ARCHIVE_ROOT}/"
    return path[len(prefix) :] if path.startswith(prefix) else path


if __name__ == "__main__":
    raise SystemExit(main())
