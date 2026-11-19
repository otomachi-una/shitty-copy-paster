#!/usr/bin/env python3
"""Build deterministic player and admin/organizer transfer artifacts."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_player_bundle
import build_player_source_artifact


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = ROOT / "out"
PLAYER_SOURCE_ARTIFACT_NAME = "sentinel-aml-player-source.tar.gz"
PLAYER_BINARY_ARTIFACT_NAME = "sentinel-aml-player-binary.tar.gz"
PLAYER_LEGACY_BINARY_ARTIFACT_NAME = "sentinel-aml-player-service.tar.gz"
PLAYER_ARTIFACT_NAME = PLAYER_LEGACY_BINARY_ARTIFACT_NAME
ADMIN_ARTIFACT_NAME = "sentinel-aml-admin-organizer.tar.gz"
PLAYER_SOURCE_MANIFEST_NAME = "player_source_manifest.json"
PLAYER_BINARY_MANIFEST_NAME = "player_binary_manifest.json"
PLAYER_MANIFEST_NAME = "player_manifest.json"
ADMIN_MANIFEST_NAME = "admin_manifest.json"
CHECKSUM_FILE_NAME = "SHA256SUMS"
SCHEMA = "sentinel-aml-artifact-manifest.v1"
FIXED_MTIME = 0

ADMIN_REQUIRED_FILES = {
    "checkers/sentinel_aml/checker.py",
    "checkers/sentinel_aml/checker_lib.py",
    "sploits/sentinel_aml/aml_dedup_preview.py",
    "sploits/sentinel_aml/aml_audit_timeline.py",
    "sploits/sentinel_aml/aml_related_graph.py",
    "sploits/sentinel_aml/aml_export_redaction.py",
    "sploits/sentinel_aml/aml_network_room.py",
    "fixes/sentinel_aml/aml_dedup_preview.patch",
    "fixes/sentinel_aml/aml_audit_timeline.patch",
    "fixes/sentinel_aml/aml_related_graph.patch",
    "fixes/sentinel_aml/aml_export_redaction.patch",
    "fixes/sentinel_aml/aml_network_room.patch",
    "config.yml",
    "Makefile",
}
ADMIN_EXCLUDED_DIR_NAMES = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vscode",
    "__pycache__",
    "bin",
    "node_modules",
    "out",
    "temp",
    "tmp",
    "validation",
    "work",
}
ADMIN_EXCLUDED_DIR_PREFIXES = (".appdata", ".gocache")
ADMIN_EXCLUDED_FILE_NAMES = {".coverage", ".DS_Store", "Thumbs.db", "coverage.out"}
ADMIN_EXCLUDED_FILE_PREFIXES = (".env.",)
ADMIN_EXCLUDED_FILE_SUFFIXES = {
    ".coverprofile",
    ".exe",
    ".pyc",
    ".pyo",
    ".tar",
    ".test",
    ".tgz",
    ".tsbuildinfo",
    ".zip",
}
ADMIN_EXCLUDED_FILE_SUFFIX_CHAINS = (".tar.gz",)
ADMIN_EXCLUDED_PREFIXES = (
    ("docs", "archive"),
    ("frontend", "dist"),
)
PLAYER_SOURCE_REQUIRED_FILES = {
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
    "migrations/000001_create_users_sessions.sql",
    "web/dist/index.html",
    "web/dist/runtime-config.js",
    "deploy/player.env.example",
    "PACKAGE_MANIFEST.json",
}
PLAYER_SOURCE_FORBIDDEN_PREFIXES = (
    "checkers/",
    "sploits/",
    "fixes/",
    "docs/",
    "tests/",
    "validation/",
    "out/",
    "tmp/",
    ".git/",
)
PLAYER_SOURCE_FORBIDDEN_PATH_PARTS = {
    "__pycache__",
    "node_modules",
    "playwright-report",
    "test-results",
}
PLAYER_SOURCE_FORBIDDEN_SUFFIXES = (".pyc", ".pyo", ".tar", ".tgz", ".zip", ".map")
PLAYER_SOURCE_FORBIDDEN_TEXT_MARKERS = (
    "aml1_vulnerable",
    "aml2_vulnerable",
    "aml3_vulnerable",
    "aml4_vulnerable",
    "aml5_vulnerable",
    "reference sploit",
    "reference exploit",
    "reference fix",
    "checker place",
    "promotion_blocker",
    "binary-only primary",
)


@dataclass(frozen=True)
class ArtifactSpec:
    key: str
    archive_name: str
    archive_root: str
    manifest_name: str
    artifact_class: str
    audience: str
    primary: bool
    player_facing: bool
    distribution_model: str
    compatibility_alias: bool = False


PLAYER_SOURCE_SPEC = ArtifactSpec(
    key="player_source",
    archive_name=PLAYER_SOURCE_ARTIFACT_NAME,
    archive_root="sentinel-aml-player-source",
    manifest_name=PLAYER_SOURCE_MANIFEST_NAME,
    artifact_class="player-source",
    audience="players/teams",
    primary=True,
    player_facing=True,
    distribution_model="source-based-player",
)
PLAYER_BINARY_SPEC = ArtifactSpec(
    key="player_binary",
    archive_name=PLAYER_BINARY_ARTIFACT_NAME,
    archive_root="sentinel-aml-player-service",
    manifest_name=PLAYER_BINARY_MANIFEST_NAME,
    artifact_class="player-binary",
    audience="players/teams, non-primary runtime convenience",
    primary=False,
    player_facing=True,
    distribution_model="non-primary-binary-runtime",
)
PLAYER_SPEC = ArtifactSpec(
    key="player_legacy_binary",
    archive_name=PLAYER_LEGACY_BINARY_ARTIFACT_NAME,
    archive_root="sentinel-aml-player-service",
    manifest_name=PLAYER_MANIFEST_NAME,
    artifact_class="player-service",
    audience="players/teams, legacy runtime-profile compatibility",
    primary=False,
    player_facing=True,
    distribution_model="legacy-non-primary-binary-runtime",
    compatibility_alias=True,
)
ADMIN_SPEC = ArtifactSpec(
    key="admin",
    archive_name=ADMIN_ARTIFACT_NAME,
    archive_root="sentinel-aml-admin-organizer",
    manifest_name=ADMIN_MANIFEST_NAME,
    artifact_class="admin-organizer",
    audience="competition operators/organizers",
    primary=True,
    player_facing=False,
    distribution_model="organizer-only",
)
ALL_SPECS = (PLAYER_SOURCE_SPEC, PLAYER_BINARY_SPEC, PLAYER_SPEC, ADMIN_SPEC)
EXPECTED_OUTPUT_RELATIVES = {
    f"artifacts/{PLAYER_SOURCE_ARTIFACT_NAME}",
    f"artifacts/{PLAYER_BINARY_ARTIFACT_NAME}",
    f"artifacts/{PLAYER_LEGACY_BINARY_ARTIFACT_NAME}",
    f"artifacts/{ADMIN_ARTIFACT_NAME}",
    f"manifests/{PLAYER_SOURCE_MANIFEST_NAME}",
    f"manifests/{PLAYER_BINARY_MANIFEST_NAME}",
    f"manifests/{PLAYER_MANIFEST_NAME}",
    f"manifests/{ADMIN_MANIFEST_NAME}",
    f"checksums/{CHECKSUM_FILE_NAME}",
}


def build_artifacts(output_root: Path, *, frontend_dist_dir: Path | None = build_player_bundle.DEFAULT_FRONTEND_DIST_DIR) -> dict[str, Any]:
    output_root = output_root.resolve()
    artifacts_dir = output_root / "artifacts"
    manifests_dir = output_root / "manifests"
    checksums_dir = output_root / "checksums"
    clean_output_dirs(artifacts_dir, manifests_dir, checksums_dir)

    with tempfile.TemporaryDirectory(prefix="sentinel-aml-artifacts-") as tmp:
        staging_root = Path(tmp)
        player_source_tree = staging_root / "player-source"
        player_source_result = build_player_source_candidate(player_source_tree, frontend_dist_dir)
        player_source_files = [Path(path) for path in player_source_result["files"]]

        player_binary_tree = staging_root / "player-binary"
        player_allowlist = staging_root / "player-binary.hygiene-allowlist.json"
        player_binary_result = build_player_bundle.build_player_candidate(player_binary_tree, player_allowlist, frontend_dist_dir)
        player_binary_files = [Path(path) for path in player_binary_result["files"]]

        admin_files = list(iter_admin_organizer_files(ROOT))
        validate_admin_required_files(admin_files)

        player_source_archive = artifacts_dir / PLAYER_SOURCE_SPEC.archive_name
        player_binary_archive = artifacts_dir / PLAYER_BINARY_SPEC.archive_name
        player_legacy_archive = artifacts_dir / PLAYER_SPEC.archive_name
        admin_archive = artifacts_dir / ADMIN_SPEC.archive_name
        player_source_entries = write_archive(player_source_tree, player_source_files, player_source_archive, PLAYER_SOURCE_SPEC.archive_root)
        player_binary_entries = write_archive(player_binary_tree, player_binary_files, player_binary_archive, PLAYER_BINARY_SPEC.archive_root)
        player_legacy_entries = write_archive(player_binary_tree, player_binary_files, player_legacy_archive, PLAYER_SPEC.archive_root)
        admin_entries = write_archive(ROOT, admin_files, admin_archive, ADMIN_SPEC.archive_root)

    player_source_manifest = write_manifest(
        output_root,
        PLAYER_SOURCE_SPEC,
        player_source_archive,
        manifests_dir / PLAYER_SOURCE_SPEC.manifest_name,
        player_source_entries,
    )
    player_binary_manifest = write_manifest(
        output_root,
        PLAYER_BINARY_SPEC,
        player_binary_archive,
        manifests_dir / PLAYER_BINARY_SPEC.manifest_name,
        player_binary_entries,
    )
    player_manifest = write_manifest(output_root, PLAYER_SPEC, player_legacy_archive, manifests_dir / PLAYER_SPEC.manifest_name, player_legacy_entries)
    admin_manifest = write_manifest(output_root, ADMIN_SPEC, admin_archive, manifests_dir / ADMIN_SPEC.manifest_name, admin_entries)
    checksum_file = write_checksum_file(
        output_root,
        [
            player_source_archive,
            player_binary_archive,
            player_legacy_archive,
            admin_archive,
            player_source_manifest,
            player_binary_manifest,
            player_manifest,
            admin_manifest,
        ],
        checksums_dir / CHECKSUM_FILE_NAME,
    )

    validation = validate_outputs(output_root)
    result = {
        "status": validation["status"],
        "artifacts": {
            "player": relative_output_path(output_root, player_source_archive),
            "player_source": relative_output_path(output_root, player_source_archive),
            "player_binary": relative_output_path(output_root, player_binary_archive),
            "player_legacy_binary": relative_output_path(output_root, player_legacy_archive),
            "admin": relative_output_path(output_root, admin_archive),
        },
        "manifests": {
            "player_source": relative_output_path(output_root, player_source_manifest),
            "player_binary": relative_output_path(output_root, player_binary_manifest),
            "player": relative_output_path(output_root, player_manifest),
            "admin": relative_output_path(output_root, admin_manifest),
        },
        "checksums": relative_output_path(output_root, checksum_file),
        "sha256": {
            "player": sha256_file(player_source_archive),
            "player_source": sha256_file(player_source_archive),
            "player_binary": sha256_file(player_binary_archive),
            "player_legacy_binary": sha256_file(player_legacy_archive),
            "admin": sha256_file(admin_archive),
        },
        "distribution_contract": distribution_contract_summary(),
        "checks": validation["checks"],
    }
    return result


def clean_output_dirs(*dirs: Path) -> None:
    for directory in dirs:
        ensure_output_directory_allowed(directory)
        if directory.exists():
            try:
                shutil.rmtree(directory)
            except PermissionError:
                clean_directory_contents(directory)
        directory.mkdir(parents=True, exist_ok=True)


def clean_directory_contents(directory: Path) -> None:
    for child in sorted(directory.iterdir(), key=lambda item: item.name):
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def ensure_output_directory_allowed(directory: Path) -> None:
    resolved = directory.resolve()
    if resolved == ROOT:
        raise ValueError("artifact output must not be the repository root")
    try:
        relative = resolved.relative_to(ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] != "out":
        raise ValueError("repo-local artifact output must be under out/")


def build_player_source_candidate(output_dir: Path, frontend_dist_dir: Path | None) -> dict[str, Any]:
    build_player_source_artifact.copy_player_sources(output_dir)
    frontend_static = build_player_source_artifact.copy_frontend_static_bundle(output_dir)
    build_player_source_artifact.write_generated_player_docs(output_dir)
    files = build_player_source_artifact.inventory(output_dir)
    validate_player_source_tree(output_dir, files)
    return {
        "artifact_class": "source-based-player",
        "materialized_source": {
            "source": str(ROOT),
            "destination": str(output_dir),
            "file_count": len(files),
        },
        "frontend_source": {
            "included": False,
            "delivery_path": None,
        },
        "frontend_static": {
            "included": True,
            "delivery_path": frontend_static["delivery_path"],
            "file_count": frontend_static["file_count"],
            "sha256": frontend_static["sha256"],
        },
        "files": [path.as_posix() for path in files],
    }


def write_player_source_docs(output_dir: Path, frontend_result: dict[str, object] | None) -> None:
    manifest = {
        "artifact_class": PLAYER_SOURCE_SPEC.artifact_class,
        "artifact_contract": "source-based-player-distribution.v1",
        "primary_player_artifact": True,
        "distribution_model": PLAYER_SOURCE_SPEC.distribution_model,
        "archive_name": PLAYER_SOURCE_SPEC.archive_name,
        "admin_organizer_artifact": ADMIN_SPEC.archive_name,
        "admin_organizer_separate": True,
        "binary_artifact_role": "non-primary runtime convenience",
        "runtime_requirements": {
            "go": "1.22+",
            "postgres": "16 compatible",
            "ui_runtime_included": frontend_result is not None,
        },
        "build_commands": [
            "go test ./...",
            "go build ./cmd/aml-api ./cmd/aml-worker ./scripts/migrate",
        ],
    }
    readme = (
        "# Sentinel AML Player Source\n\n"
        "This is the primary participant artifact for source-based service delivery. "
        "Teams receive the service source needed to inspect, patch, test, and rebuild the runtime.\n\n"
        "Build and test with Go 1.22 or newer:\n\n"
        "```sh\n"
        "go test ./...\n"
        "go build ./cmd/aml-api ./cmd/aml-worker ./scripts/migrate\n"
        "```\n\n"
        "Run the service with a PostgreSQL-compatible `DATABASE_URL`. If `ui/` is present, it contains "
        "the participant UI runtime assets that should be served beside the API.\n\n"
        "Organizer-only materials are distributed separately and are intentionally absent from this package.\n"
    )
    (output_dir / "PACKAGE_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (output_dir / "README.md").write_text(readme, encoding="utf-8", newline="\n")


def validate_player_source_tree(output_dir: Path, files: Iterable[Path]) -> None:
    file_list = list(files)
    present = {path.as_posix() for path in file_list}
    missing = sorted(PLAYER_SOURCE_REQUIRED_FILES - present)
    if missing:
        raise FileNotFoundError(f"player source artifact is missing required files: {', '.join(missing)}")
    for relative in file_list:
        path = relative.as_posix()
        if path.startswith(PLAYER_SOURCE_FORBIDDEN_PREFIXES):
            raise ValueError(f"player source artifact contains organizer-only path: {path}")
        if any(part in PLAYER_SOURCE_FORBIDDEN_PATH_PARTS for part in relative.parts):
            raise ValueError(f"player source artifact contains generated/cache path: {path}")
        if path.lower().endswith(PLAYER_SOURCE_FORBIDDEN_SUFFIXES):
            raise ValueError(f"player source artifact contains generated/archive file: {path}")
        source = output_dir / relative
        if is_text_file(source):
            text = source.read_text(encoding="utf-8", errors="ignore").lower()
            marker = next((item for item in PLAYER_SOURCE_FORBIDDEN_TEXT_MARKERS if item in text), None)
            if marker is not None:
                raise ValueError(f"player source artifact contains forbidden marker {marker!r} in {path}")


def is_text_file(path: Path) -> bool:
    return path.suffix.lower() in {".go", ".mod", ".sum", ".sql", ".md", ".json", ".js", ".html", ".css", ".conf", ".yaml", ".yml", ".env"}


def iter_admin_organizer_files(repo_root: Path) -> Iterable[Path]:
    for path in sorted((entry for entry in repo_root.rglob("*") if entry.is_file()), key=lambda item: item.relative_to(repo_root).as_posix()):
        relative = path.relative_to(repo_root)
        if should_exclude_admin_file(relative):
            continue
        yield relative


def should_exclude_admin_file(relative: Path) -> bool:
    parts = relative.parts
    if any(parts[: len(prefix)] == prefix for prefix in ADMIN_EXCLUDED_PREFIXES):
        return True
    if any(part in ADMIN_EXCLUDED_DIR_NAMES or part.startswith(ADMIN_EXCLUDED_DIR_PREFIXES) for part in parts[:-1]):
        return True
    name = relative.name
    lowered = name.lower()
    return (
        name in ADMIN_EXCLUDED_FILE_NAMES
        or name.startswith(ADMIN_EXCLUDED_FILE_PREFIXES)
        or relative.suffix.lower() in ADMIN_EXCLUDED_FILE_SUFFIXES
        or any(lowered.endswith(suffix) for suffix in ADMIN_EXCLUDED_FILE_SUFFIX_CHAINS)
    )


def validate_admin_required_files(files: Iterable[Path]) -> None:
    present = {path.as_posix() for path in files}
    missing = sorted(ADMIN_REQUIRED_FILES - present)
    if missing:
        raise FileNotFoundError(f"admin/organizer artifact is missing required evidence files: {', '.join(missing)}")


def write_archive(source_root: Path, files: Iterable[Path], archive_path: Path, archive_root: str) -> list[dict[str, Any]]:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for relative in sorted(files, key=lambda item: item.as_posix()):
            source = source_root / relative
            if not source.is_file():
                raise FileNotFoundError(f"required archive input is missing: {source}")
            archive_member = f"{archive_root}/{relative.as_posix()}"
            info = archive.gettarinfo(str(source), arcname=archive_member)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = FIXED_MTIME
            info.mode = archive_mode(relative, source)
            digest = sha256_file(source)
            size = source.stat().st_size
            with source.open("rb") as handle:
                archive.addfile(info, handle)
            entries.append({"path": archive_member, "sha256": digest, "size_bytes": size})
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=FIXED_MTIME) as gz:
            gz.write(payload.getvalue())
    return entries


def archive_mode(relative: Path, source: Path) -> int:
    path = relative.as_posix()
    if path in {"sentinel_aml/checker.py", "checkers/sentinel_aml/checker.py"}:
        return 0o755
    if path.startswith("bin/"):
        return 0o755
    if path.startswith("scripts/") and path.endswith(".py"):
        return 0o755
    if path.startswith("sploits/") and path.endswith(".py"):
        return 0o755
    return 0o644


def write_manifest(
    output_root: Path,
    spec: ArtifactSpec,
    archive_path: Path,
    manifest_path: Path,
    entries: list[dict[str, Any]],
) -> Path:
    if not archive_path.is_file():
        raise FileNotFoundError(f"required artifact missing before manifest generation: {archive_path}")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": SCHEMA,
        "artifact": {
            "artifact_class": spec.artifact_class,
            "archive_root": spec.archive_root,
            "audience": spec.audience,
            "compatibility_alias": spec.compatibility_alias,
            "distribution_model": spec.distribution_model,
            "name": spec.archive_name,
            "path": relative_output_path(output_root, archive_path),
            "player_facing": spec.player_facing,
            "primary": spec.primary,
            "sha256": sha256_file(archive_path),
            "size_bytes": archive_path.stat().st_size,
        },
        "build": {
            "deterministic_mtime": FIXED_MTIME,
            "generated_by": "scripts/build_artifacts.py",
            "repo_root_name": ROOT.name,
        },
        "artifact_contract": artifact_contract_metadata(spec, entries),
        "delivered_components": delivered_components_metadata(spec, entries),
        "runtime_profile": runtime_profile_metadata(spec, entries),
        "files": entries,
        "file_count": len(entries),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return manifest_path


def artifact_contract_metadata(spec: ArtifactSpec, entries: list[dict[str, Any]]) -> dict[str, Any]:
    if spec.key == "player_source":
        return {
            "name": "source-based-player-distribution",
            "version": 1,
            "description": "primary participant artifact containing service source for patching and rebuilding",
            "primary_player_artifact": True,
            "distribution_model": spec.distribution_model,
            "binary_only_sufficient_for_classic_ad": False,
            "admin_organizer_artifact": ADMIN_SPEC.archive_name,
        }
    if spec.key in {"player_binary", "player_legacy_binary"}:
        return {
            "name": "player-service-with-ui",
            "version": 1,
            "description": "non-primary binary runtime artifact containing backend binaries and participant UI runtime files",
            "primary_player_artifact": False,
            "binary_only_sufficient_for_classic_ad": False,
        }
    return {
        "name": "admin-organizer-evidence",
        "version": 1,
        "description": "organizer transfer artifact preserving checker, sploit, fix, test, docs, and gate evidence",
    }


def delivered_components_metadata(spec: ArtifactSpec, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths = {entry["path"] for entry in entries}
    root = spec.archive_root
    if spec.key == "player_source":
        source_files = sorted(
            path
            for path in paths
            if path.startswith((f"{root}/cmd/", f"{root}/internal/", f"{root}/migrations/", f"{root}/scripts/migrate/"))
            or path in {f"{root}/go.mod", f"{root}/go.sum"}
        )
        ui_files = sorted(path for path in paths if path.startswith(f"{root}/ui/"))
        return [
            {
                "key": "service-source",
                "delivery_path": f"{root}/",
                "included": bool(source_files),
                "required": True,
                "file_count": len(source_files),
            },
            {
                "key": "participant-ui-runtime",
                "delivery_path": f"{root}/ui/",
                "included": bool(ui_files),
                "required": False,
                "file_count": len(ui_files),
            },
        ]
    if spec.key in {"player_binary", "player_legacy_binary"}:
        backend_targets = sorted(
            path
            for path in paths
            if path in {f"{root}/bin/aml-api", f"{root}/bin/aml-worker", f"{root}/bin/aml-migrate"}
        )
        ui_files = sorted(path for path in paths if path.startswith(f"{root}/ui/"))
        return [
            {
                "key": "backend-runtime",
                "delivery_path": f"{root}/bin/",
                "included": len(backend_targets) == 3,
                "required": True,
                "file_count": len(backend_targets),
            },
            {
                "key": "participant-ui",
                "delivery_path": f"{root}/ui/",
                "included": bool(ui_files),
                "required": True,
                "file_count": len(ui_files),
            },
        ]
    return [
        {
            "key": "organizer-evidence",
            "delivery_path": f"{root}/",
            "included": True,
            "required": True,
            "file_count": len(paths),
        }
    ]


def runtime_profile_metadata(spec: ArtifactSpec, entries: list[dict[str, Any]]) -> dict[str, Any]:
    if spec.key == "admin":
        return {
            "delivery_mode": "admin-organizer",
            "runtime_evidence_required": False,
        }
    if spec.key == "player_source":
        return {
            "delivery_mode": "source",
            "player_default_mode": True,
            "build_required_by_team": True,
            "binary_artifact_role": "non-primary runtime convenience",
            "runtime_evidence_required": True,
            "runtime_evidence": [],
            "artifact_local_runtime_proof": {
                "status": "external-required",
                "summary_path": "out/artifact-first-validation-summary.json",
                "artifact_bindings": [
                    "player_source_artifact_sha256",
                    "admin_artifact_sha256",
                ],
                "summary": "Source-based player readiness must be bound to exact artifact bytes during artifact-first validation.",
            },
        }
    paths = {entry["path"] for entry in entries}
    return {
        "delivery_mode": "binary-image",
        "player_default_mode": False,
        "built_runtime": {
            "platform": "linux/amd64",
            "targets": sorted(
                path
                for path in paths
                if path
                in {
                    f"{spec.archive_root}/bin/aml-api",
                    f"{spec.archive_root}/bin/aml-worker",
                    f"{spec.archive_root}/bin/aml-migrate",
                }
            ),
        },
        "build_profile_evidence": {
            "profile": "competition-runtime",
            "source": "scripts/build_player_bundle.py",
            "command": "go build -tags <internal competition policy set> -trimpath -ldflags '-s -w'",
            "labels_exposed_in_player_artifact": False,
        },
        "runtime_evidence_required": True,
        "runtime_evidence": [],
        "artifact_local_runtime_proof": {
            "status": "external-required",
            "summary_path": "out/artifact-first-validation-summary.json",
            "artifact_bindings": [
                "player_artifact_sha256",
                "admin_artifact_sha256",
            ],
            "required_summary_fields": [
                "player_artifact_sha256",
                "admin_artifact_sha256",
                "runtime_validation.runtime_smoke.status",
                "runtime_validation.checker_check_havoc.status",
                "runtime_validation.sploit_matrix.status",
                "runtime_validation.fix_workflow.status",
                "runtime_validation.matrix_status.status",
            ],
            "summary": "Exact-artifact runtime readiness is stamped by the artifact-first validation summary, not by historical candidate-tree reports.",
        },
    }


def write_checksum_file(output_root: Path, outputs: Iterable[Path], checksum_path: Path) -> Path:
    checksum_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{sha256_file(path)}  {relative_output_path(output_root, path)}" for path in sorted(outputs, key=lambda item: relative_output_path(output_root, item))]
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return checksum_path


def distribution_contract_summary() -> dict[str, Any]:
    return {
        "primary_player_artifact": f"artifacts/{PLAYER_SOURCE_ARTIFACT_NAME}",
        "admin_organizer_artifact": f"artifacts/{ADMIN_ARTIFACT_NAME}",
        "non_primary_binary_artifact": f"artifacts/{PLAYER_BINARY_ARTIFACT_NAME}",
        "legacy_binary_compatibility_artifact": f"artifacts/{PLAYER_LEGACY_BINARY_ARTIFACT_NAME}",
        "full_repository_zip_player_facing": False,
        "binary_only_primary": False,
    }


def validate_outputs(output_root: Path) -> dict[str, Any]:
    checks = [
        check_required_outputs(output_root),
        check_no_unexpected_outputs(output_root),
        check_distribution_contract(output_root),
        check_manifest_inventory(output_root, PLAYER_SOURCE_SPEC),
        check_player_source_component_contract(output_root),
        check_manifest_inventory(output_root, PLAYER_BINARY_SPEC),
        check_manifest_inventory(output_root, PLAYER_SPEC),
        check_player_component_contract(output_root),
        check_manifest_inventory(output_root, ADMIN_SPEC),
        check_checksum_file(output_root),
    ]
    return {"status": "fail" if any(check["status"] == "fail" for check in checks) else "pass", "checks": checks}


def check_required_outputs(output_root: Path) -> dict[str, str]:
    required = [
        output_root / "artifacts" / spec.archive_name for spec in ALL_SPECS
    ] + [
        output_root / "manifests" / spec.manifest_name for spec in ALL_SPECS
    ] + [
        output_root / "checksums" / CHECKSUM_FILE_NAME,
    ]
    missing = [relative_output_path(output_root, path) for path in required if not path.is_file()]
    return {
        "name": "artifact-required-outputs-present",
        "path": str(output_root),
        "status": "pass" if not missing else "fail",
        "message": "" if not missing else f"missing={missing}",
    }


def check_no_unexpected_outputs(output_root: Path) -> dict[str, str]:
    unexpected: list[str] = []
    for dirname in ("artifacts", "manifests", "checksums"):
        directory = output_root / dirname
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                relative = relative_output_path(output_root, path)
                if relative not in EXPECTED_OUTPUT_RELATIVES:
                    unexpected.append(relative)
    return {
        "name": "artifact-output-root-has-no-stale-files",
        "path": str(output_root),
        "status": "pass" if not unexpected else "fail",
        "message": "" if not unexpected else f"unexpected={unexpected}",
    }


def check_manifest_inventory(output_root: Path, spec: ArtifactSpec) -> dict[str, str]:
    archive_path = output_root / "artifacts" / spec.archive_name
    manifest_path = output_root / "manifests" / spec.manifest_name
    if not archive_path.is_file() or not manifest_path.is_file():
        return {
            "name": f"{spec.key}-manifest-matches-archive",
            "path": relative_output_path(output_root, manifest_path),
            "status": "fail",
            "message": "artifact or manifest is missing",
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_files = sorted(file_entry["path"] for file_entry in manifest.get("files", []))
    archive_files = archive_inventory(archive_path)
    digest_ok = manifest.get("artifact", {}).get("sha256") == sha256_file(archive_path)
    count_ok = manifest.get("file_count") == len(archive_files)
    ok = manifest_files == archive_files and digest_ok and count_ok
    return {
        "name": f"{spec.key}-manifest-matches-archive",
        "path": relative_output_path(output_root, manifest_path),
        "status": "pass" if ok else "fail",
        "message": "" if ok else f"manifest_files_match={manifest_files == archive_files} digest_ok={digest_ok} count_ok={count_ok}",
    }


def check_distribution_contract(output_root: Path) -> dict[str, str]:
    source_manifest_path = output_root / "manifests" / PLAYER_SOURCE_SPEC.manifest_name
    binary_manifest_path = output_root / "manifests" / PLAYER_BINARY_SPEC.manifest_name
    admin_manifest_path = output_root / "manifests" / ADMIN_SPEC.manifest_name
    missing = [
        relative_output_path(output_root, path)
        for path in (source_manifest_path, binary_manifest_path, admin_manifest_path)
        if not path.is_file()
    ]
    if missing:
        return {
            "name": "artifact-distribution-contract",
            "path": str(output_root),
            "status": "fail",
            "message": f"missing={missing}",
        }
    source = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    binary = json.loads(binary_manifest_path.read_text(encoding="utf-8"))
    admin = json.loads(admin_manifest_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    if source.get("artifact", {}).get("name") != PLAYER_SOURCE_ARTIFACT_NAME:
        failures.append("player-source artifact name mismatch")
    if source.get("artifact", {}).get("primary") is not True:
        failures.append("player-source must be primary")
    if source.get("artifact", {}).get("artifact_class") != "player-source":
        failures.append("player-source artifact_class mismatch")
    if binary.get("artifact", {}).get("primary") is not False:
        failures.append("player-binary must be non-primary")
    if admin.get("artifact", {}).get("player_facing") is not False:
        failures.append("admin-organizer must not be player-facing")
    return {
        "name": "artifact-distribution-contract",
        "path": relative_output_path(output_root, source_manifest_path),
        "status": "pass" if not failures else "fail",
        "message": "" if not failures else "; ".join(failures),
    }


def check_player_source_component_contract(output_root: Path) -> dict[str, str]:
    archive_path = output_root / "artifacts" / PLAYER_SOURCE_SPEC.archive_name
    manifest_path = output_root / "manifests" / PLAYER_SOURCE_SPEC.manifest_name
    if not archive_path.is_file() or not manifest_path.is_file():
        return {
            "name": "player-source-component-contract",
            "path": relative_output_path(output_root, manifest_path),
            "status": "fail",
            "message": "player source artifact or manifest is missing",
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    archive_files = set(archive_inventory(archive_path))
    required_files = {f"{PLAYER_SOURCE_SPEC.archive_root}/{path}" for path in PLAYER_SOURCE_REQUIRED_FILES}
    missing_files = sorted(required_files - archive_files)
    forbidden_files = sorted(
        path
        for path in archive_files
        if archive_member_has_forbidden_player_source_path(path, PLAYER_SOURCE_SPEC.archive_root)
    )
    components = {
        component.get("key"): component
        for component in manifest.get("delivered_components", [])
        if isinstance(component, dict)
    }
    source_component = components.get("service-source")
    contract = manifest.get("artifact_contract", {})
    contract_ok = (
        isinstance(contract, dict)
        and contract.get("name") == "source-based-player-distribution"
        and contract.get("primary_player_artifact") is True
        and contract.get("binary_only_sufficient_for_classic_ad") is False
    )
    source_ok = isinstance(source_component, dict) and source_component.get("included") is True and source_component.get("required") is True
    content_failures = player_source_archive_content_failures(archive_path)
    ok = not missing_files and not forbidden_files and source_ok and contract_ok and not content_failures
    return {
        "name": "player-source-component-contract",
        "path": relative_output_path(output_root, manifest_path),
        "status": "pass" if ok else "fail",
        "message": ""
        if ok
        else (
            f"missing_files={missing_files} forbidden_files={forbidden_files} "
            f"source_ok={source_ok} contract_ok={contract_ok} content_failures={content_failures}"
        ),
    }


def archive_member_has_forbidden_player_source_path(member_path: str, archive_root: str) -> bool:
    prefix = f"{archive_root}/"
    if not member_path.startswith(prefix):
        return True
    relative = member_path[len(prefix) :]
    parts = relative.split("/")
    return (
        relative.startswith(PLAYER_SOURCE_FORBIDDEN_PREFIXES)
        or any(part in PLAYER_SOURCE_FORBIDDEN_PATH_PARTS for part in parts)
        or relative.lower().endswith(PLAYER_SOURCE_FORBIDDEN_SUFFIXES)
    )


def player_source_archive_content_failures(archive_path: Path) -> list[str]:
    failures: list[str] = []
    with gzip.open(archive_path, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            relative = Path(member.name)
            if not is_text_file(relative):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                failures.append(f"{member.name}: unreadable")
                continue
            text = handle.read().decode("utf-8", errors="ignore").lower()
            marker = next((item for item in PLAYER_SOURCE_FORBIDDEN_TEXT_MARKERS if item in text), None)
            if marker is not None:
                failures.append(f"{member.name}: {marker}")
    return failures


def check_player_component_contract(output_root: Path) -> dict[str, str]:
    archive_path = output_root / "artifacts" / PLAYER_SPEC.archive_name
    manifest_path = output_root / "manifests" / PLAYER_SPEC.manifest_name
    if not archive_path.is_file() or not manifest_path.is_file():
        return {
            "name": "player-component-contract",
            "path": relative_output_path(output_root, manifest_path),
            "status": "fail",
            "message": "player artifact or manifest is missing",
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    archive_files = set(archive_inventory(archive_path))
    required_files = {
        f"{PLAYER_SPEC.archive_root}/bin/aml-api",
        f"{PLAYER_SPEC.archive_root}/bin/aml-worker",
        f"{PLAYER_SPEC.archive_root}/bin/aml-migrate",
        f"{PLAYER_SPEC.archive_root}/ui/index.html",
        f"{PLAYER_SPEC.archive_root}/ui/runtime-config.js",
        f"{PLAYER_SPEC.archive_root}/PACKAGING_STATUS.json",
    }
    missing_files = sorted(required_files - archive_files)
    components = {
        component.get("key"): component
        for component in manifest.get("delivered_components", [])
        if isinstance(component, dict)
    }
    missing_components = [
        key
        for key in ("backend-runtime", "participant-ui")
        if key not in components or components[key].get("included") is not True or components[key].get("required") is not True
    ]
    contract = manifest.get("artifact_contract", {})
    contract_ok = isinstance(contract, dict) and contract.get("name") == "player-service-with-ui"
    status_failures = packaging_status_contract_failures(archive_path)
    ok = not missing_files and not missing_components and contract_ok and not status_failures
    return {
        "name": "player-component-contract",
        "path": relative_output_path(output_root, manifest_path),
        "status": "pass" if ok else "fail",
        "message": ""
        if ok
        else f"missing_files={missing_files} missing_components={missing_components} contract_ok={contract_ok} status_failures={status_failures}",
    }


def packaging_status_contract_failures(archive_path: Path) -> list[str]:
    status_path = f"{PLAYER_SPEC.archive_root}/PACKAGING_STATUS.json"
    with gzip.open(archive_path, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        try:
            member = archive.getmember(status_path)
        except KeyError:
            return ["PACKAGING_STATUS.json missing"]
        handle = archive.extractfile(member)
        if handle is None:
            return ["PACKAGING_STATUS.json unreadable"]
        try:
            status = json.loads(handle.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [f"PACKAGING_STATUS.json invalid: {exc}"]
    failures: list[str] = []
    if status.get("artifact_contract") != "player-service-with-ui.v1":
        failures.append("artifact_contract must be player-service-with-ui.v1")
    participant_ui = status.get("participant_ui")
    if not isinstance(participant_ui, dict) or participant_ui.get("required") is not True or participant_ui.get("included") is not True:
        failures.append("participant_ui must be required and included")
    delivered_components = status.get("delivered_components")
    if not isinstance(delivered_components, list):
        failures.append("delivered_components missing")
    else:
        by_key = {component.get("key"): component for component in delivered_components if isinstance(component, dict)}
        for key in ("backend-runtime", "participant-ui"):
            component = by_key.get(key)
            if not isinstance(component, dict) or component.get("required") is not True or component.get("included") is not True:
                failures.append(f"{key} component must be required and included")
    return failures


def check_checksum_file(output_root: Path) -> dict[str, str]:
    checksum_path = output_root / "checksums" / CHECKSUM_FILE_NAME
    if not checksum_path.is_file():
        return {
            "name": "artifact-checksums-match-bytes",
            "path": relative_output_path(output_root, checksum_path),
            "status": "fail",
            "message": "checksum file missing",
        }
    mismatches: list[str] = []
    seen: set[str] = set()
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, relative = line.split(None, 1)
        relative = relative.strip()
        seen.add(relative)
        path = output_root / relative
        if not path.is_file():
            mismatches.append(f"{relative}: missing")
            continue
        actual = sha256_file(path)
        if actual != digest:
            mismatches.append(f"{relative}: expected {digest} actual {actual}")
    expected_checksum_entries = EXPECTED_OUTPUT_RELATIVES - {f"checksums/{CHECKSUM_FILE_NAME}"}
    missing = sorted(expected_checksum_entries - seen)
    if missing:
        mismatches.append(f"missing checksum entries: {missing}")
    return {
        "name": "artifact-checksums-match-bytes",
        "path": relative_output_path(output_root, checksum_path),
        "status": "pass" if not mismatches else "fail",
        "message": "" if not mismatches else "; ".join(mismatches),
    }


def archive_inventory(archive_path: Path) -> list[str]:
    with gzip.open(archive_path, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        return sorted(member.name for member in archive.getmembers() if member.isfile())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_output_path(output_root: Path, path: Path) -> str:
    return path.resolve().relative_to(output_root.resolve()).as_posix()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=Path(os.environ.get("SENTINEL_AML_ARTIFACT_OUTPUT_ROOT", DEFAULT_OUTPUT_ROOT)))
    parser.add_argument(
        "--frontend-dist-dir",
        type=Path,
        default=Path(os.environ.get("SENTINEL_AML_FRONTEND_DIST", build_player_bundle.DEFAULT_FRONTEND_DIST_DIR)),
    )
    parser.add_argument("--verify-only", action="store_true", help="validate existing artifacts, manifests, and checksums without rebuilding")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.verify_only:
            result = validate_outputs(args.output_root.resolve())
        else:
            result = build_artifacts(args.output_root, frontend_dist_dir=args.frontend_dist_dir)
    except Exception as exc:
        result = {
            "status": "fail",
            "checks": [
                {
                    "name": "artifact-build",
                    "path": str(args.output_root),
                    "status": "fail",
                    "message": str(exc),
                }
            ],
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
