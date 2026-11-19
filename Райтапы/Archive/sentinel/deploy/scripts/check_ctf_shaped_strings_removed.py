#!/usr/bin/env python3
"""Fail if exact CTF-shaped strings remain in the player artifact."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path


ARCHIVE_ROOT = "sentinel-aml-player-source"
TEXT_SUFFIXES = (".go", ".md", ".json", ".sql", ".js", ".ts", ".tsx", ".css", ".html", ".yml", ".yaml", ".mod", ".sum")
TOKENS = (
    "flag_value",
    "secret_for_checker",
    "checker_private",
    "flag_store",
    "putflag",
    "getflag",
    "attack_info",
    "public_attack_data",
    "aml1",
    "aml2",
    "aml3",
    "aml4",
    "aml5",
    "AML-1",
    "AML-2",
    "AML-3",
    "AML-4",
    "AML-5",
    "vulnerable",
    "exploit",
    "sploit",
    "reference_fix",
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    token: str


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = check_ctf_shaped_strings_removed(args.artifact)
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


def check_ctf_shaped_strings_removed(artifact: Path) -> dict[str, object]:
    findings: list[Finding] = []
    if not artifact.is_file():
        findings.append(Finding(artifact.as_posix(), 0, "artifact"))
        return report(artifact, findings, 0)
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        for member in members:
            path = strip_root(member.name)
            if path.startswith("vendor/") or not path.lower().endswith(TEXT_SUFFIXES):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            text = handle.read().decode("utf-8", errors="ignore")
            for line_no, line in enumerate(text.splitlines(), 1):
                lowered = line.lower()
                for token in TOKENS:
                    if token.lower() in lowered:
                        findings.append(Finding(path, line_no, token))
    return report(artifact, findings, len(members))


def report(artifact: Path, findings: list[Finding], file_count: int) -> dict[str, object]:
    return {
        "status": "fail" if findings else "pass",
        "artifact": artifact.as_posix(),
        "file_count": file_count,
        "findings": [asdict(finding) for finding in findings],
    }


def strip_root(path: str) -> str:
    prefix = f"{ARCHIVE_ROOT}/"
    return path[len(prefix) :] if path.startswith(prefix) else path


if __name__ == "__main__":
    raise SystemExit(main())
