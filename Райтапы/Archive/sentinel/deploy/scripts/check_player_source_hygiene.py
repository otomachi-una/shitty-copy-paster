#!/usr/bin/env python3
"""Strict anti-spoiler hygiene scanner for the player source artifact."""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import re
import sys
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path


ARCHIVE_ROOT = "sentinel-aml-player-source"
TEXT_SUFFIXES = (".go", ".md", ".json", ".sql", ".js", ".ts", ".tsx", ".css", ".html", ".yml", ".yaml", ".mod", ".sum")
REQUIRED_FILES = {
    "README.md",
    "TROUBLESHOOTING.md",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "go.mod",
    "go.sum",
    "cmd/aml-api/main.go",
    "cmd/aml-worker/main.go",
    "cmd/aml-migrate/main.go",
    "internal/httpapi/server.go",
    "migrations/000001_create_users_sessions.sql",
    "web/dist/index.html",
    "web/dist/runtime-config.js",
    "deploy/player.env.example",
}
REQUIRED_DIRS = {"vendor/", "cmd/", "internal/", "migrations/", "web/dist/"}
FORBIDDEN_PREFIXES = (
    "checkers/",
    "sploits/",
    "exploits/",
    "fixes/",
    "docs/",
    "validation/",
    "out/",
    "tmp/",
    ".git/",
    "frontend/",
    "node_modules/",
)
FORBIDDEN_SCRIPT_PATTERNS = (
    re.compile(r"^scripts/check_.*"),
    re.compile(r"^scripts/run_.*"),
)
GENERATED_SUFFIXES = (".pyc", ".pyo", ".map", ".tsbuildinfo", ".tar", ".tgz", ".zip")
FORBIDDEN_BASENAME_PATTERNS = (
    re.compile(r".*_secure\.[^.]+$"),
    re.compile(r".*_vulnerable\.[^.]+$"),
    re.compile(r".*_profile_.*\.[^.]+$"),
    re.compile(r"profile_.*\.[^.]+$"),
)
PAIR_SUFFIX_RE = re.compile(r"^(?P<stem>.+)_(?P<kind>default|detail)\.go$")
POLICY_SWITCH_RE = re.compile(r".*_policy_.*\.[^.]+$")
FORBIDDEN_TOKENS = (
    "flag_value",
    "secret_for_checker",
    "checker_private",
    "public_attack_data",
    "vulnerable_profile",
    "secure_profile",
    "reference_fix",
    "must_not_leak",
    "flag_store",
    "attack_info",
    "leak_target",
    "putflag",
    "getflag",
    "AML-1",
    "AML-2",
    "AML-3",
    "AML-4",
    "AML-5",
    "aml1",
    "aml2",
    "aml3",
    "aml4",
    "aml5",
    "vulnerable",
    "exploit",
    "sploit",
    "checker",
    "flag",
)
COMMENT_TOKENS = (
    "intended behavior",
    "challenge",
    "ctf",
    "exploitability",
    "exploitable",
    "checker",
    "reference fix",
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    token: str
    severity: str
    allowlisted: bool
    reason: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--json-report", type=Path, help="write the full JSON report to this path")
    parser.add_argument("--csv-report", type=Path, help="write findings as CSV to this path")
    args = parser.parse_args(argv)
    result = check_player_source_hygiene(args.artifact)
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.csv_report:
        write_csv_report(args.csv_report, result["findings"])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def check_player_source_hygiene(artifact: Path) -> dict[str, object]:
    findings: list[Finding] = []
    if not artifact.is_file():
        findings.append(Finding(artifact.as_posix(), 0, "artifact", "critical", False, "artifact is missing"))
        return report(artifact, 0, findings)
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        paths = sorted(strip_root(member.name) for member in members)
        findings.extend(required_findings(paths))
        findings.extend(path_findings(paths))
        findings.extend(dual_policy_findings(paths))
        findings.extend(content_findings(archive, members))
        findings.extend(compose_findings(read_member(archive, f"{ARCHIVE_ROOT}/docker-compose.yml"), read_member(archive, f"{ARCHIVE_ROOT}/Dockerfile")))
    return report(artifact, len(members), findings)


def report(artifact: Path, file_count: int, findings: list[Finding]) -> dict[str, object]:
    blocking = [finding for finding in findings if not finding.allowlisted]
    return {
        "status": "pass" if not blocking else "fail",
        "artifact": artifact.as_posix(),
        "file_count": file_count,
        "hit_count": len(findings),
        "blocking_hit_count": len(blocking),
        "allowlisted_hit_count": len(findings) - len(blocking),
        "allowlists": allowlist_summary(),
        "findings": [asdict(finding) for finding in findings],
        "checks": [
            {
                "name": "player-source-anti-spoiler-hygiene",
                "status": "pass" if not blocking else "fail",
                "message": "" if not blocking else f"blocking findings={len(blocking)}",
            }
        ],
    }


def required_findings(paths: list[str]) -> list[Finding]:
    present = set(paths)
    findings = [
        Finding(path, 0, "required-file", "high", False, "required player source file is missing")
        for path in sorted(REQUIRED_FILES - present)
    ]
    for dirname in sorted(REQUIRED_DIRS):
        if not any(path.startswith(dirname) for path in paths):
            findings.append(Finding(dirname, 0, "required-dir", "high", False, "required player source directory is missing"))
    return findings


def path_findings(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        if path.startswith(ARCHIVE_ROOT + "/"):
            findings.append(Finding(path, 0, "archive-root", "critical", False, "nested or unexpected archive root"))
        if path.startswith(FORBIDDEN_PREFIXES):
            findings.append(Finding(path, 0, path.split("/", 1)[0], "critical", False, "organizer-only or generated path is forbidden"))
        if any(pattern.match(path) for pattern in FORBIDDEN_SCRIPT_PATTERNS):
            findings.append(Finding(path, 0, Path(path).name, "critical", False, "internal checker/runner script is forbidden"))
        if path.lower().endswith(GENERATED_SUFFIXES):
            findings.append(Finding(path, 0, Path(path).suffix, "medium", False, "generated/cache/archive file is forbidden"))
        if path.startswith("vendor/"):
            continue
        name = Path(path).name
        for pattern in FORBIDDEN_BASENAME_PATTERNS:
            if pattern.fullmatch(name):
                findings.append(Finding(path, 0, name, "high", False, "filename reveals alternate policy or vulnerability role"))
        if POLICY_SWITCH_RE.fullmatch(name):
            findings.append(Finding(path, 0, name, "high", False, "filename exposes policy switch naming"))
    return findings


def dual_policy_findings(paths: list[str]) -> list[Finding]:
    by_dir_stem: dict[tuple[str, str], set[str]] = {}
    findings: list[Finding] = []
    for path in paths:
        if path.startswith("vendor/"):
            continue
        name = Path(path).name
        match = PAIR_SUFFIX_RE.fullmatch(name)
        if not match:
            continue
        key = (Path(path).parent.as_posix(), match.group("stem"))
        by_dir_stem.setdefault(key, set()).add(match.group("kind"))
        findings.append(Finding(path, 0, name, "high", False, "filename suggests default/detail policy split"))
    for (directory, stem), kinds in sorted(by_dir_stem.items()):
        if {"default", "detail"} <= kinds:
            findings.append(Finding(f"{directory}/{stem}_*.go", 0, "default/detail", "critical", False, "dual policy source pair is forbidden"))
    return findings


def content_findings(archive: tarfile.TarFile, members: list[tarfile.TarInfo]) -> list[Finding]:
    findings: list[Finding] = []
    for member in members:
        path = strip_root(member.name)
        if not path.lower().endswith(TEXT_SUFFIXES):
            continue
        text = read_member(archive, member.name)
        for line_no, line in enumerate(text.splitlines(), start=1):
            for token in forbidden_tokens_in_line(line):
                allowlisted, reason = allowlist_token(path, token, line)
                findings.append(Finding(path, line_no, token, severity_for_token(token), allowlisted, reason))
            comment = comment_text(line, path)
            if comment:
                lowered = comment.lower()
                for token in COMMENT_TOKENS:
                    if token in lowered:
                        allowlisted, reason = allowlist_token(path, token, line)
                        findings.append(Finding(path, line_no, token, "high", allowlisted, reason or "comment contains challenge/internal wording"))
    return findings


def forbidden_tokens_in_line(line: str) -> list[str]:
    hits: list[str] = []
    lowered = line.lower()
    for token in FORBIDDEN_TOKENS:
        if token.lower() in lowered:
            hits.append(token)
    return hits


def allowlist_token(path: str, token: str, line: str) -> tuple[bool, str]:
    lowered = token.lower()
    line_lower = line.lower()
    if path.startswith("vendor/"):
        return True, "vendored third-party dependency text; not Sentinel challenge metadata"
    if path.startswith("web/dist/assets/") and lowered == "flag" and re.search(r"\bflags?\b", line_lower):
        return True, "compiled frontend library internals use generic render flag fields"
    if path in {"cmd/aml-api/main.go", "cmd/aml-worker/main.go"} and lowered == "flag":
        return True, "Go standard library CLI flag parsing for service runtime options"
    if path in {"Makefile", "Dockerfile", "TROUBLESHOOTING.md"} and lowered == "flag" and "goflags" in line_lower:
        return True, "Go build environment variable GOFLAGS is operational build guidance"
    return False, ""


def severity_for_token(token: str) -> str:
    lowered = token.lower()
    if lowered in {"aml1", "aml2", "aml3", "aml4", "aml5", "aml-1", "aml-2", "aml-3", "aml-4", "aml-5"}:
        return "critical"
    if lowered in {"exploit", "sploit", "checker", "putflag", "getflag", "reference_fix", "vulnerable_profile", "secure_profile"}:
        return "critical"
    if lowered in {"vulnerable", "flag", "flag_store", "attack_info", "public_attack_data"}:
        return "high"
    return "medium"


def compose_findings(compose: str, dockerfile: str) -> list[Finding]:
    findings: list[Finding] = []
    if "context: ." not in compose:
        findings.append(Finding("docker-compose.yml", 0, "context", "high", False, "docker-compose.yml must build from package source context"))
    if "../" in compose or "../" in dockerfile:
        findings.append(Finding("docker-compose.yml", 0, "../", "critical", False, "Docker files must not reference organizer parent paths"))
    if "COPY bin/" in dockerfile:
        findings.append(Finding("Dockerfile", 0, "COPY bin/", "critical", False, "Dockerfile must build from source, not copy prebuilt binaries"))
    if "go build" not in dockerfile:
        findings.append(Finding("Dockerfile", 0, "go build", "high", False, "Dockerfile must build Go services from source"))
    npm_markers = ("npm ci", "npm install", "npm run build", "node:20")
    if any(marker in dockerfile for marker in npm_markers):
        findings.append(Finding("Dockerfile", 0, "npm", "high", False, "player Dockerfile must use prebuilt static UI without npm"))
    if "COPY web/dist /usr/share/nginx/html" not in dockerfile:
        findings.append(Finding("Dockerfile", 0, "web/dist", "high", False, "Dockerfile must copy the prebuilt static UI bundle"))
    return findings


def comment_text(line: str, path: str) -> str:
    stripped = line.strip()
    if path.endswith((".go", ".ts", ".tsx", ".js")) and stripped.startswith("//"):
        return stripped[2:].strip()
    if path.endswith(".md"):
        return stripped
    if path.endswith((".yml", ".yaml")) and "#" in stripped:
        return stripped.split("#", 1)[1].strip()
    return ""


def strip_root(path: str) -> str:
    prefix = f"{ARCHIVE_ROOT}/"
    return path[len(prefix) :] if path.startswith(prefix) else path


def read_member(archive: tarfile.TarFile, name: str) -> str:
    try:
        handle = archive.extractfile(name)
    except KeyError:
        return ""
    if handle is None:
        return ""
    return handle.read().decode("utf-8", errors="ignore")


def allowlist_summary() -> list[dict[str, str]]:
    return [
        {"scope": "vendor/**", "reason": "third-party dependency vocabulary and build constraints are not Sentinel spoiler metadata"},
        {"scope": "cmd/aml-api/main.go, cmd/aml-worker/main.go", "reason": "standard library flag package is used only for runtime CLI options"},
        {"scope": "Makefile, Dockerfile, TROUBLESHOOTING.md", "reason": "GOFLAGS mentions are operational build instructions"},
    ]


def write_csv_report(path: Path, findings: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path", "line", "token", "severity", "allowlisted", "reason"])
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)


if __name__ == "__main__":
    raise SystemExit(main())
