#!/usr/bin/env python3
"""Validate required contents of the admin/organizer artifact."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import tarfile
from pathlib import Path
from typing import Any


ARCHIVE_ROOT = "sentinel-aml-admin-organizer"
REQUIRED_SPLOITS = (
    "aml_dedup_preview.py",
    "aml_audit_timeline.py",
    "aml_related_graph.py",
    "aml_export_redaction.py",
    "aml_network_room.py",
)
REQUIRED_FIXES = (
    "aml_dedup_preview.patch",
    "aml_audit_timeline.patch",
    "aml_related_graph.patch",
    "aml_export_redaction.patch",
    "aml_network_room.patch",
)
REQUIRED_FILES = {
    "README_ADMIN.md",
    "ADMIN_MANIFEST.json",
    "SHA256SUMS",
    "Makefile",
    "config.yml",
    "checkers/sentinel_aml/checker.py",
    "checkers/sentinel_aml/checker_lib.py",
    "checkers/sentinel_aml/requirements.txt",
    "scripts/check_competition_matrix_gate.py",
    "scripts/check_live_competition_matrix.py",
    "scripts/check_exact_artifact_live_acceptance.py",
    "scripts/check_player_source_runtime.py",
    "scripts/check_player_source_artifact.py",
    "tests/test_checker_check_workflow.py",
    "tests/test_checker_put_workflow.py",
    "tests/test_checker_get_workflow.py",
    "tests/test_live_competition_matrix.py",
    "docs/source_of_truth_map.md",
    "docs/13_roadmap.md",
    "docs/wave_reports/w34_p04_source_based_docker_compose_runtime.md",
    "docs/wave_reports/w34_p05_admin_organizer_artifact.md",
    "validation/README.md",
    *(f"sploits/sentinel_aml/{name}" for name in REQUIRED_SPLOITS),
    *(f"fixes/sentinel_aml/{name}" for name in REQUIRED_FIXES),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--manifest", type=Path, help="external ADMIN_MANIFEST.json with exact archive SHA")
    args = parser.parse_args(argv)
    result = check_admin_artifact_contents(args.artifact, args.manifest)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def check_admin_artifact_contents(artifact: Path, manifest: Path | None = None) -> dict[str, Any]:
    findings: list[dict[str, object]] = []
    if not artifact.is_file():
        findings.append(finding(artifact.as_posix(), "artifact", "artifact is missing"))
        return report(artifact, 0, findings)
    files, content = load_archive(artifact)
    file_set = set(files)
    missing = sorted(REQUIRED_FILES - file_set)
    for path in missing:
        findings.append(finding(path, "required-file", "required organizer material is missing"))
    if not any(path.startswith("docs/wave_reports/") for path in files):
        findings.append(finding("docs/wave_reports/", "evidence", "docs evidence is missing"))
    if not any(path.startswith("scripts/check_wave") for path in files):
        findings.append(finding("scripts/", "wave-gates", "validation matrix scripts are missing"))

    internal_manifest = parse_json(content.get("ADMIN_MANIFEST.json"), findings, "ADMIN_MANIFEST.json")
    if internal_manifest:
        check_manifest_shape(internal_manifest, findings, exact_sha_required=False)
    external_path = manifest or artifact.parent / "ADMIN_MANIFEST.json"
    if external_path.is_file():
        external_manifest = json.loads(external_path.read_text(encoding="utf-8"))
        check_manifest_shape(external_manifest, findings, exact_sha_required=True)
        if external_manifest.get("artifact", {}).get("sha256") != sha256_file(artifact):
            findings.append(finding(external_path.as_posix(), "sha256", "external manifest does not match artifact bytes"))
    else:
        findings.append(finding(external_path.as_posix(), "manifest", "external exact-SHA admin manifest is missing"))

    readme = content.get("README_ADMIN.md", b"").decode("utf-8", errors="ignore")
    for phrase in ("organizer-only", "checker", "reference exploit", "reference patches", "check_player_source_runtime.py"):
        if phrase.lower() not in readme.lower():
            findings.append(finding("README_ADMIN.md", phrase, "admin runbook is missing required operating guidance"))
    return report(artifact, len(files), findings)


def check_manifest_shape(manifest: dict[str, Any], findings: list[dict[str, object]], *, exact_sha_required: bool) -> None:
    artifact = manifest.get("artifact", {})
    if artifact.get("artifact_class") != "admin-organizer":
        findings.append(finding("ADMIN_MANIFEST.json", "artifact_class", "manifest must mark admin-organizer artifact class"))
    if artifact.get("player_facing") is not False:
        findings.append(finding("ADMIN_MANIFEST.json", "player_facing", "admin artifact must not be player-facing"))
    if artifact.get("organizer_only") is not True:
        findings.append(finding("ADMIN_MANIFEST.json", "organizer_only", "manifest must label archive organizer-only"))
    if exact_sha_required and not artifact.get("sha256"):
        findings.append(finding("ADMIN_MANIFEST.json", "sha256", "external manifest must record exact artifact SHA"))
    if not manifest.get("checker", {}).get("version"):
        findings.append(finding("ADMIN_MANIFEST.json", "checker.version", "checker version is missing"))
    if sorted(manifest.get("sploits", [])) != sorted(f"sploits/sentinel_aml/{name}" for name in REQUIRED_SPLOITS):
        findings.append(finding("ADMIN_MANIFEST.json", "sploits", "manifest must list all five sploits"))
    if sorted(manifest.get("fixes", [])) != sorted(f"fixes/sentinel_aml/{name}" for name in REQUIRED_FIXES):
        findings.append(finding("ADMIN_MANIFEST.json", "fixes", "manifest must list all five fixes"))
    if manifest.get("matrix_gate_command") != "python -B scripts/check_competition_matrix_gate.py":
        findings.append(finding("ADMIN_MANIFEST.json", "matrix_gate_command", "matrix gate command is missing or unexpected"))
    if not manifest.get("generated_timestamp"):
        findings.append(finding("ADMIN_MANIFEST.json", "generated_timestamp", "generated timestamp is missing"))


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


def parse_json(raw: bytes | None, findings: list[dict[str, object]], path: str) -> dict[str, Any] | None:
    if raw is None:
        findings.append(finding(path, "json", "JSON file is missing"))
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(finding(path, "json", str(exc)))
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
                "name": "admin-artifact-contents",
                "status": "pass" if not findings else "fail",
                "message": "" if not findings else f"findings={len(findings)}",
            }
        ],
    }


def finding(path: str, token: str, reason: str) -> dict[str, object]:
    return {"path": path, "line": 0, "token": token, "severity": "critical", "allowlisted": False, "reason": reason}


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
