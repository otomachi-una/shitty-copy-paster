#!/usr/bin/env python3
"""Validate that the classification catalog is product-natural and live."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MIN_ENTRIES = 80
CATALOG_PATH = Path("internal/classification/catalog.go")
PROFILE_RE = re.compile(
    r'profile\(\s*"(?P<name>[^"]+)"\s*,\s*'
    r"(?P<domain>DataClass\w+)\s*,\s*"
    r"(?P<audience>Audience\w+)\s*,\s*"
    r"(?P<export>Disposition\w+)\s*,\s*"
    r"(?P<audit>Disposition\w+)\s*,\s*"
    r"(?P<projection>Disposition\w+)\s*,\s*"
    r'"(?P<label>[^"]+)"\s*\)',
    re.MULTILINE,
)
FORBIDDEN_RE = re.compile(
    r"flag_value|secret_for_checker|checker_private|public_attack_data|attack_info|flag_store|"
    r"putflag|getflag|reference_fix|checker|flag|exploit|sploit|vulnerable|AML-[1-5]|aml[1-5]",
    re.IGNORECASE,
)
REAL_GO_PACKAGE_RE = re.compile(r'\b"sentinel-aml/internal/classification"\b|\bclassification\.')


@dataclass(frozen=True)
class Profile:
    name: str
    domain: str
    audience: str
    export: str
    audit: str
    projection: str
    label: str


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    token: str
    message: str


def main() -> int:
    args = parse_args()
    result = check_semantic_red_herrings(args.repo_root, min_entries=args.min_entries)
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "artifact",
        nargs="?",
        type=Path,
        help="Optional player-source artifact path accepted for release-gate compatibility.",
    )
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--min-entries", type=int, default=DEFAULT_MIN_ENTRIES)
    parser.add_argument("--json-report", type=Path)
    return parser.parse_args()


def check_semantic_red_herrings(repo_root: Path, *, min_entries: int = DEFAULT_MIN_ENTRIES) -> dict[str, object]:
    repo_root = repo_root.resolve()
    catalog = repo_root / CATALOG_PATH
    findings: list[Finding] = []
    if not catalog.is_file():
        findings.append(Finding(CATALOG_PATH.as_posix(), 0, "missing", "classification catalog is missing"))
        return result(repo_root, [], [], findings, min_entries)

    text = catalog.read_text(encoding="utf-8")
    profiles = parse_profiles(text)
    if len(profiles) < min_entries:
        findings.append(Finding(CATALOG_PATH.as_posix(), 0, "entry_count", f"catalog has {len(profiles)} entries; expected at least {min_entries}"))

    seen: dict[str, int] = {}
    line_by_name = line_index_by_profile_name(text)
    for profile in profiles:
        line_no = line_by_name.get(profile.name, 0)
        if profile.name in seen:
            findings.append(Finding(CATALOG_PATH.as_posix(), line_no, profile.name, "duplicate classification catalog entry"))
        seen[profile.name] = line_no
        for field_name, value in asdict(profile).items():
            if not str(value).strip():
                findings.append(Finding(CATALOG_PATH.as_posix(), line_no, field_name, "catalog entry field is empty"))
            match = FORBIDDEN_RE.search(str(value))
            if match:
                findings.append(Finding(CATALOG_PATH.as_posix(), line_no, match.group(0), f"CTF-shaped vocabulary in catalog {field_name}"))

    usage_packages = find_usage_packages(repo_root)
    if len(usage_packages) < 2:
        findings.append(Finding(CATALOG_PATH.as_posix(), 0, "usage", f"classification catalog is used by {len(usage_packages)} real package(s); expected at least 2"))

    return result(repo_root, profiles, usage_packages, findings, min_entries)


def parse_profiles(text: str) -> list[Profile]:
    return [
        Profile(
            name=match.group("name"),
            domain=match.group("domain"),
            audience=match.group("audience"),
            export=match.group("export"),
            audit=match.group("audit"),
            projection=match.group("projection"),
            label=match.group("label"),
        )
        for match in PROFILE_RE.finditer(text)
    ]


def line_index_by_profile_name(text: str) -> dict[str, int]:
    index: dict[str, int] = {}
    for line_no, line in enumerate(text.splitlines(), 1):
        match = re.search(r'profile\(\s*"([^"]+)"', line)
        if match:
            index[match.group(1)] = line_no
    return index


def find_usage_packages(repo_root: Path) -> list[str]:
    packages: set[str] = set()
    internal = repo_root / "internal"
    if not internal.is_dir():
        return []
    for path in internal.rglob("*.go"):
        relative = path.relative_to(repo_root)
        if "vendor" in relative.parts or path.name.endswith("_test.go"):
            continue
        if relative.parts[:2] == ("internal", "classification"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if REAL_GO_PACKAGE_RE.search(text):
            packages.add(relative.parent.as_posix())
    return sorted(packages)


def result(repo_root: Path, profiles: list[Profile], usage_packages: list[str], findings: list[Finding], min_entries: int) -> dict[str, object]:
    return {
        "status": "fail" if findings else "pass",
        "repo_root": str(repo_root),
        "catalog": CATALOG_PATH.as_posix(),
        "min_entries": min_entries,
        "entry_count": len(profiles),
        "usage_package_count": len(usage_packages),
        "usage_packages": usage_packages,
        "findings": [asdict(finding) for finding in findings],
    }


if __name__ == "__main__":
    raise SystemExit(main())
