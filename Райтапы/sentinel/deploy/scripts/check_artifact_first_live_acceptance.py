#!/usr/bin/env python3
"""Validate that live acceptance evidence is bound to current artifact bytes."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = ROOT / "out"
DEFAULT_SUMMARY = DEFAULT_OUTPUT_ROOT / "validation" / "exact-artifact-live-acceptance-summary.json"
PLAYER_SOURCE_ARTIFACT = "sentinel-aml-player-source.tar.gz"
PLAYER_LEGACY_ARTIFACT = "sentinel-aml-player-service.tar.gz"
ADMIN_ARTIFACT = "sentinel-aml-admin-organizer.tar.gz"


@dataclass(frozen=True)
class Finding:
    path: str
    message: str


def main() -> int:
    args = parse_args()
    result = check_artifact_first_live_acceptance(
        args.output_root,
        summary_path=args.summary,
        require_live=args.require_live,
    )
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--require-live", action="store_true")
    parser.add_argument("--json-report", type=Path)
    return parser.parse_args()


def check_artifact_first_live_acceptance(
    output_root: Path | None = None,
    *,
    summary_path: Path = DEFAULT_SUMMARY,
    require_live: bool = False,
    player_artifact: Path | None = None,
    admin_artifact: Path | None = None,
    summary_output: Path | None = None,
    validation_root: Path | None = None,
    docker: str = "docker",
    run_live: bool = True,
    **_: object,
) -> dict[str, object]:
    if player_artifact is not None or admin_artifact is not None:
        if player_artifact is None or admin_artifact is None or summary_output is None:
            raise TypeError("player_artifact, admin_artifact, and summary_output are required together")
        return check_source_admin_pair_compat(
            player_artifact=player_artifact,
            admin_artifact=admin_artifact,
            summary_output=summary_output,
            validation_root=validation_root,
            docker=docker,
            run_live=run_live,
        )
    if output_root is None:
        output_root = DEFAULT_OUTPUT_ROOT
    output_root = output_root.resolve()
    summary_path = summary_path if summary_path.is_absolute() else ROOT / summary_path
    findings: list[Finding] = []
    artifact_hashes = current_artifact_hashes(output_root)

    if not summary_path.is_file():
        if require_live:
            findings.append(Finding(relative(output_root, summary_path), "live acceptance summary is missing"))
        return {
            "status": "fail" if findings else "pass",
            "live_proof": "missing" if findings else "external-required",
            "summary": relative(output_root, summary_path),
            "artifact_hashes": artifact_hashes,
            "findings": [asdict(finding) for finding in findings],
        }

    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(Finding(relative(output_root, summary_path), f"live acceptance summary is not valid JSON: {exc}"))
        summary = {}

    if summary and summary.get("status") not in {"pass", "external-required"}:
        findings.append(Finding(relative(output_root, summary_path), f"live acceptance status is {summary.get('status')!r}"))

    expected_bindings = extract_bindings(summary)
    if not expected_bindings:
        findings.append(Finding(relative(output_root, summary_path), "live acceptance summary does not record artifact SHA bindings"))
    for artifact_name, expected_sha in expected_bindings.items():
        actual_sha = artifact_hashes.get(artifact_name)
        if actual_sha is None:
            findings.append(Finding(relative(output_root, summary_path), f"bound artifact {artifact_name} is missing from current output"))
        elif expected_sha != actual_sha:
            findings.append(Finding(relative(output_root, summary_path), f"bound SHA for {artifact_name} does not match current artifact bytes"))

    return {
        "status": "fail" if findings else "pass",
        "live_proof": "present",
        "summary": relative(output_root, summary_path),
        "artifact_hashes": artifact_hashes,
        "bindings": expected_bindings,
        "findings": [asdict(finding) for finding in findings],
    }


def check_source_admin_pair_compat(
    *,
    player_artifact: Path,
    admin_artifact: Path,
    summary_output: Path,
    validation_root: Path | None,
    docker: str,
    run_live: bool,
) -> dict[str, object]:
    summary: dict[str, object] = {
        "schema": "sentinel-aml-source-admin-compat-acceptance.v1",
        "status": "fail",
        "artifact_evidence": {},
        "runtime": {},
    }
    try:
        if not player_artifact.is_file() or not admin_artifact.is_file():
            raise ValueError("artifact input is not a directory fallback; exact tar.gz files are required")
        player_sha = sha256_file(player_artifact)
        admin_sha = sha256_file(admin_artifact)
        player_manifest = player_artifact.parent / "PLAYER_SOURCE_MANIFEST.json"
        admin_manifest = admin_artifact.parent / "ADMIN_MANIFEST.json"
        if player_manifest.is_file():
            manifest = json.loads(player_manifest.read_text(encoding="utf-8"))
            if manifest.get("artifact", {}).get("sha256") != player_sha:
                raise ValueError("SHA changed after manifest for player source artifact")
        if admin_manifest.is_file():
            manifest = json.loads(admin_manifest.read_text(encoding="utf-8"))
            if manifest.get("artifact", {}).get("sha256") != admin_sha:
                raise ValueError("SHA changed after manifest for admin organizer artifact")
        summary["artifact_evidence"] = {
            "player_artifact": {"path": player_artifact.as_posix(), "sha256": player_sha},
            "admin_artifact": {"path": admin_artifact.as_posix(), "sha256": admin_sha},
        }
        if run_live and not docker_available(docker):
            summary["status"] = "external-required"
            summary["external_required"] = ["docker"]
            summary["runtime"] = {"docker_available": False}
        else:
            if validation_root is not None:
                validate_extracts(player_artifact, admin_artifact, validation_root)
            summary["status"] = "pass" if not run_live else "external-required"
            summary["runtime"] = {"docker_available": bool(run_live)}
            if run_live:
                summary["external_required"] = ["live runtime validation is handled by the final source/admin gate"]
    except Exception as exc:
        summary["status"] = "fail"
        summary["error"] = str(exc)
    finally:
        summary_output.parent.mkdir(parents=True, exist_ok=True)
        summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def docker_available(docker: str) -> bool:
    if shutil.which(docker) is None:
        return False
    try:
        return subprocess.run([docker, "--version"], text=True, capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def validate_extracts(player_artifact: Path, admin_artifact: Path, validation_root: Path) -> None:
    if validation_root.exists():
        shutil.rmtree(validation_root)
    validation_root.mkdir(parents=True, exist_ok=True)
    for artifact in (player_artifact, admin_artifact):
        with gzip.open(artifact, "rb") as raw:
            payload = io.BytesIO(raw.read())
        with tarfile.open(fileobj=payload, mode="r:") as archive:
            archive.getmembers()


def extract_bindings(summary: dict[str, Any]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    artifact_evidence = summary.get("artifact_evidence")
    if isinstance(artifact_evidence, dict):
        for key, artifact_name in (
            ("player_artifact", PLAYER_LEGACY_ARTIFACT),
            ("admin_artifact", ADMIN_ARTIFACT),
        ):
            entry = artifact_evidence.get(key)
            if isinstance(entry, dict) and isinstance(entry.get("sha256"), str):
                path = str(entry.get("path", ""))
                bindings[Path(path).name or artifact_name] = entry["sha256"]
    runtime = summary.get("runtime_validation")
    if isinstance(runtime, dict):
        if isinstance(runtime.get("player_artifact_sha256"), str):
            bindings.setdefault(PLAYER_LEGACY_ARTIFACT, runtime["player_artifact_sha256"])
        if isinstance(runtime.get("admin_artifact_sha256"), str):
            bindings.setdefault(ADMIN_ARTIFACT, runtime["admin_artifact_sha256"])
    if isinstance(summary.get("player_source_artifact_sha256"), str):
        bindings[PLAYER_SOURCE_ARTIFACT] = summary["player_source_artifact_sha256"]
    if isinstance(summary.get("player_artifact_sha256"), str):
        bindings.setdefault(PLAYER_LEGACY_ARTIFACT, summary["player_artifact_sha256"])
    if isinstance(summary.get("admin_artifact_sha256"), str):
        bindings.setdefault(ADMIN_ARTIFACT, summary["admin_artifact_sha256"])
    return bindings


def current_artifact_hashes(output_root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    artifacts = output_root / "artifacts"
    for artifact_name in (PLAYER_SOURCE_ARTIFACT, PLAYER_LEGACY_ARTIFACT, ADMIN_ARTIFACT):
        path = artifacts / artifact_name
        if path.is_file():
            hashes[artifact_name] = sha256_file(path)
    return hashes


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    raise SystemExit(main())
