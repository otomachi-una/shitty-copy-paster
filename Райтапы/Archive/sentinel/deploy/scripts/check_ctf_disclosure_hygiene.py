#!/usr/bin/env python3
"""CTF disclosure hygiene gate for Sentinel AML player artifacts."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import check_player_bundle_hygiene

ORGANIZER_ONLY_TERMS = (
    "aml1_vulnerable",
    "aml2_vulnerable",
    "aml3_vulnerable",
    "aml4_vulnerable",
    "aml5_vulnerable",
    "case_match_preview",
    "audit_detail_view",
    "entity_review_summary",
    "linked_case_export_detail",
    "network_room_detail",
    "FindDuplicatePrivateNotesForPreview",
    "LinkedPrivateNotes",
    "ForeignPrivateNotes",
    "ForeignEDDComments",
    "DossierPrivateNote",
    "DossierEDDComment",
    "dedup_profile_",
    "audit_profile_",
    "graph_profile_",
    "export_profile_",
    "network_room_profile_",
    "dossier_profile_",
    "must not appear",
    "Private material omitted",
    "Explicit omissions",
    "linked_private_notes",
    "foreign_private_notes",
    "foreign_edd_comments",
    "sensitive_marker_value",
    "private_service_marker",
    "source_scope_materialized",
    "collaboration_context_detail",
)

BINARY_NAMES = ("aml-api", "aml-worker", "aml-migrate")
BINARY_STRING_ALLOWLIST = {
    "go-runtime": (
        "runtime.",
        "go1.",
        "GODEBUG",
        "panic",
    ),
    "product-api": (
        "/api/",
        "healthz",
        "readyz",
        "DATABASE_URL",
        "candidate",
        "duplicate",
        "network_room",
        "redaction_policy",
        "private_data_policy",
    ),
    "packaged-runtime": (
        "aml-api",
        "aml-worker",
        "aml-migrate",
        "sentinel_aml",
    ),
}


def validate_ctf_disclosure_hygiene(candidate: Path, allowlist: Path | None = None) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    base = check_player_bundle_hygiene.validate_player_bundle(candidate, allowlist)
    checks.extend(base.get("checks", []))
    if base.get("status") != "pass":
        return {"status": "fail", "checks": checks}

    checks.append(check_archive_paths(candidate))
    for binary in iter_candidate_binaries(candidate):
        checks.append(check_go_version_metadata(binary, candidate))
        checks.append(check_binary_strings(binary, candidate))

    return {"status": "fail" if any(check["status"] == "fail" for check in checks) else "pass", "checks": checks}


def check_archive_paths(candidate: Path) -> dict[str, str]:
    failures: list[str] = []
    for path in candidate.rglob("*") if candidate.is_dir() else []:
        relative = path.relative_to(candidate).as_posix()
        matched = find_terms(relative)
        for term in matched:
            failures.append(f"{relative}: {term}")
    return {
        "name": "ctf-disclosure-paths",
        "status": "fail" if failures else "pass",
        "message": "; ".join(failures[:20]) if failures else "archive paths are neutral",
    }


def iter_candidate_binaries(candidate: Path) -> Iterable[Path]:
    if not candidate.is_dir():
        return []
    return [candidate / "bin" / name for name in BINARY_NAMES if (candidate / "bin" / name).is_file()]


def check_go_version_metadata(binary: Path, candidate: Path) -> dict[str, str]:
    completed = subprocess.run(["go", "version", "-m", str(binary)], cwd=ROOT, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"go version -m exited {completed.returncode}"
        return {
            "name": "ctf-disclosure-go-version",
            "status": "fail",
            "message": f"{display_path(binary, candidate)}: {detail}",
        }
    return term_check("ctf-disclosure-go-version", display_path(binary, candidate), completed.stdout)


def check_binary_strings(binary: Path, candidate: Path) -> dict[str, str]:
    strings_exe = shutil.which("strings")
    text = ""
    if strings_exe:
        completed = subprocess.run([strings_exe, "-a", str(binary)], cwd=ROOT, capture_output=True, text=True, check=False)
        if completed.returncode == 0:
            text = completed.stdout

    if not text:
        data = binary.read_bytes()
        text = data.decode("utf-8", errors="ignore")
    found = find_terms(text)
    allowlist_report = binary_string_allowlist_report(text)
    label = display_path(binary, candidate)
    return {
        "name": "ctf-disclosure-strings",
        "status": "fail" if found else "pass",
        "message": (
            f"{label}: {', '.join(found[:20])}; allowlist={allowlist_report}"
            if found
            else f"{label}: no organizer-only vocabulary; allowlist={allowlist_report}"
        ),
    }


def term_check(name: str, label: str, text: str) -> dict[str, str]:
    found = find_terms(text)
    return {
        "name": name,
        "status": "fail" if found else "pass",
        "message": f"{label}: {', '.join(found[:20])}" if found else f"{label}: no organizer-only vocabulary",
    }


def find_terms(text: str) -> list[str]:
    lowered = text.lower()
    found: list[str] = []
    for term in ORGANIZER_ONLY_TERMS:
        if term.lower() in lowered:
            found.append(term)
    return found


def binary_string_allowlist_report(text: str) -> dict[str, list[str]]:
    return {
        category: sorted(term for term in terms if term in text)
        for category, terms in BINARY_STRING_ALLOWLIST.items()
    }


def display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--allowlist", type=Path)
    args = parser.parse_args(argv)

    result = validate_ctf_disclosure_hygiene(args.candidate, args.allowlist)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
