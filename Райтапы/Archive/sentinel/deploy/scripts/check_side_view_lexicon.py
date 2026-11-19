#!/usr/bin/env python3
"""Check side-view source paths for spoiler-shaped visibility vocabulary."""

from __future__ import annotations

import argparse
import json
import re
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT = ROOT / "out" / "artifacts" / "sentinel-aml-player-source.tar.gz"
ARCHIVE_ROOT = "sentinel-aml-player-source"

FORBIDDEN = (
    "private",
    "confidential",
    "sensitive",
    "secret",
    "flag",
    "checker",
    "exploit",
    "sploit",
    "vulnerable",
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
)
TOKEN_RE = re.compile("|".join(re.escape(token) for token in sorted(FORBIDDEN, key=len, reverse=True)), re.IGNORECASE)

PLAYER_SIDE_PATHS = {
    "internal/httpapi/dedup_merge_preview.go",
    "internal/httpapi/activity_views.go",
    "internal/httpapi/entity_review_summaries.go",
    "internal/httpapi/export_linked_cases.go",
    "internal/httpapi/network_room_context.go",
    "internal/graph/repository_entity_summaries.go",
    "internal/exporting/export_linked_evidence.go",
    "internal/networkroom/dossier_context.go",
    "internal/networkroom/repository_context.go",
    "frontend/src/pages/CasePage.tsx",
    "frontend/src/pages/ExportDetailPage.tsx",
    "frontend/src/pages/GraphEntityPage.tsx",
    "frontend/src/pages/NetworkRoomsPage.tsx",
    "frontend/src/shared/api/contracts.ts",
}

REPO_SIDE_PATHS = {
    "internal/httpapi/dedup_profile_case_match.go",
    "internal/httpapi/audit_profile_detail.go",
    "internal/httpapi/graph_profile_entity_review.go",
    "internal/httpapi/export_profile_linked_case.go",
    "internal/httpapi/network_room_profile_detail.go",
    "internal/graph/repository_entity_review.go",
    "internal/exporting/export_profile_linked_case.go",
    "internal/networkroom/dossier_profile_room_detail.go",
    "internal/networkroom/repository_room_detail.go",
    "frontend/src/pages/CasePage.tsx",
    "frontend/src/pages/ExportDetailPage.tsx",
    "frontend/src/pages/GraphEntityPage.tsx",
    "frontend/src/pages/NetworkRoomsPage.tsx",
    "frontend/src/shared/api/contracts.ts",
}


@dataclass
class Finding:
    source: str
    path: str
    line: int
    token: str
    allowlisted: bool
    reason: str


def main() -> int:
    args = parse_args()
    findings = scan_repository()
    if args.artifact.is_file():
        findings.extend(scan_artifact(args.artifact))
    elif args.require_artifact:
        findings.append(Finding("artifact", str(args.artifact), 0, "artifact", False, "player source artifact is missing"))

    blocking = [finding for finding in findings if not finding.allowlisted]
    result = {
        "status": "fail" if blocking else "pass",
        "repo_root": str(ROOT),
        "artifact": str(args.artifact),
        "hit_count": len(findings),
        "blocking_hit_count": len(blocking),
        "allowlisted_hit_count": len(findings) - len(blocking),
        "findings": [asdict(finding) for finding in findings],
    }
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if blocking else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", nargs="?", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--json-report", type=Path)
    parser.add_argument("--require-artifact", action="store_true")
    return parser.parse_args()


def scan_repository() -> list[Finding]:
    findings: list[Finding] = []
    paths = set(REPO_SIDE_PATHS)
    adapters = ROOT / "frontend" / "src" / "shared" / "api" / "adapters"
    if adapters.is_dir():
        for path in adapters.glob("*"):
            if path.is_file():
                paths.add(path.relative_to(ROOT).as_posix())
    for rel in sorted(paths):
        path = ROOT / rel
        if not path.is_file():
            continue
        findings.extend(scan_text("repository", rel, path.read_text(encoding="utf-8", errors="ignore")))
    return findings


def scan_artifact(artifact: Path) -> list[Finding]:
    findings: list[Finding] = []
    with tarfile.open(artifact, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers() if member.isfile()}
        wanted = set(PLAYER_SIDE_PATHS)
        for name in members:
            stripped = strip_archive_root(name)
            if stripped.startswith("frontend/src/shared/api/adapters/"):
                wanted.add(stripped)
        for rel in sorted(wanted):
            member = members.get(f"{ARCHIVE_ROOT}/{rel}")
            if member is None:
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            findings.extend(scan_text("artifact", rel, handle.read().decode("utf-8", errors="ignore")))
    return findings


def scan_text(source: str, path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    owner_allowed_lines = owner_view_allowlisted_lines(path, text)
    for line_no, line in enumerate(text.splitlines(), 1):
        for match in TOKEN_RE.finditer(line):
            token = match.group(0)
            allowlisted, reason = allowlist_hit(source, path, line_no, token, line, owner_allowed_lines)
            findings.append(Finding(source, path, line_no, token, allowlisted, reason))
    return findings


def allowlist_hit(source: str, path: str, line_no: int, token: str, line: str, owner_allowed_lines: set[int] | None = None) -> tuple[bool, str]:
    lowered = token.lower()
    stripped = line.strip()
    if source == "repository" and line_no == 1 and stripped.startswith("//go:build"):
        return True, "repository-only build selector preserves configured competition variants; player artifact removes build directives"
    if path.endswith("frontend/src/pages/CasePage.tsx") and "note" in line.lower() and lowered in {"private", "secret"}:
        return True, "owner-only case-note editor is an allowed owner-view surface"
    if owner_allowed_lines and line_no in owner_allowed_lines and "confidential_comment" in line:
        return True, "owner EDD contract/adapter block is an allowed owner-view surface"
    return False, ""


def owner_view_allowlisted_lines(path: str, text: str) -> set[int]:
    if path.endswith("frontend/src/shared/api/contracts.ts"):
        return type_block_lines(
            text,
            {
                "export interface EDDOwnerView",
                "export interface CreateEDDRequest",
                "export interface UpdateEDDRequest",
            },
        )
    if path.endswith("frontend/src/shared/api/adapters/customer.ts"):
        return function_block_lines(text, "export function adaptEDDOwnerView")
    return set()


def type_block_lines(text: str, starts: set[str]) -> set[int]:
    allowed: set[int] = set()
    active = False
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if any(stripped.startswith(start) for start in starts):
            active = True
        if active:
            allowed.add(line_no)
            if stripped == "}":
                active = False
    return allowed


def function_block_lines(text: str, start: str) -> set[int]:
    allowed: set[int] = set()
    active = False
    brace_depth = 0
    saw_open = False
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(start):
            active = True
        if not active:
            continue
        allowed.add(line_no)
        brace_depth += line.count("{") - line.count("}")
        saw_open = saw_open or "{" in line
        if saw_open and brace_depth <= 0:
            active = False
            brace_depth = 0
            saw_open = False
    return allowed


def strip_archive_root(path: str) -> str:
    prefix = f"{ARCHIVE_ROOT}/"
    return path[len(prefix):] if path.startswith(prefix) else path


if __name__ == "__main__":
    raise SystemExit(main())
