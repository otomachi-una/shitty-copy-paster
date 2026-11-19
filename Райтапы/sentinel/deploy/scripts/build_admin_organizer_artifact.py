#!/usr/bin/env python3
"""Build the Sentinel AML admin/organizer artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ROOT = "sentinel-aml-admin-organizer"
DEFAULT_OUTPUT = ROOT / "out" / "artifacts" / "sentinel-aml-admin-organizer.tar.gz"
FIXED_MTIME = 0
GENERATED_TIMESTAMP = "1970-01-01T00:00:00Z"
BUILDER_VERSION = "w34-p05-admin-organizer.v1"

CHECKER_ROOT = Path("checkers") / "sentinel_aml"
SPLOIT_ROOT = Path("sploits") / "sentinel_aml"
FIX_ROOT = Path("fixes") / "sentinel_aml"
REQUIRED_ROOT_FILES = (Path("Makefile"), Path("config.yml"))
INCLUDED_ROOTS = (CHECKER_ROOT, SPLOIT_ROOT, FIX_ROOT, Path("scripts"), Path("tests"), Path("docs"), Path("validation"))
SPLIT_OUTPUTS = (
    "sentinel-aml-player-source.tar.gz",
    "sentinel-aml-admin-organizer.tar.gz",
    "sentinel-aml-player-binary.tar.gz",
    "sentinel-aml-player-service.tar.gz",
)
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
REQUIRED_VALIDATION_SCRIPTS = (
    "build_admin_organizer_artifact.py",
    "check_admin_artifact_contents.py",
    "check_admin_artifact_hygiene.py",
    "check_competition_matrix_gate.py",
    "check_live_competition_matrix.py",
    "check_exact_artifact_live_acceptance.py",
    "check_player_source_runtime.py",
    "check_player_source_artifact.py",
    "check_player_source_hygiene.py",
    "check_player_source_manifest.py",
    "check_player_source_no_dual_policy.py",
    "run_go_release_tests.py",
    "run_vulnerable_profile_tests.py",
    "runtime_smoke.py",
    "validate_forcad_config.py",
)
EXCLUDED_DIR_NAMES = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vscode",
    "__pycache__",
    "node_modules",
    "out",
    "temp",
    "tmp",
    "dist",
    "playwright-report",
    "test-results",
}
EXCLUDED_DIR_PREFIXES = (".appdata", ".gocache")
EXCLUDED_FILE_SUFFIXES = {
    ".coverprofile",
    ".exe",
    ".map",
    ".pyc",
    ".pyo",
    ".tar",
    ".test",
    ".tgz",
    ".tsbuildinfo",
    ".zip",
}
EXCLUDED_FILE_SUFFIX_CHAINS = (".tar.gz",)
EXCLUDED_PATH_PREFIXES = (
    ("docs", "archive"),
    ("validation", "admin-extracted"),
    ("validation", "exact-artifact-live"),
    ("validation", "organizer-extracted"),
    ("validation", "player-extracted"),
    ("validation", "unit-live-acceptance"),
    ("validation", "unit-live-acceptance-bad"),
)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = build_admin_organizer_artifact(args.output)
    except Exception as exc:
        result = {"status": "fail", "message": str(exc), "artifact": args.output.as_posix()}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args(argv)


def build_admin_organizer_artifact(output: Path) -> dict[str, Any]:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sentinel-aml-admin-organizer-") as tmp:
        stage = Path(tmp) / ARCHIVE_ROOT
        stage.mkdir(parents=True)
        copy_admin_material(stage)
        write_admin_readme(stage)
        write_validation_boundary_note(stage)
        write_internal_manifest(stage)
        write_internal_checksums(stage)
        validate_required_inputs(stage)
        entries = inventory(stage)
        archive_entries = write_archive(stage, output, entries)

    artifact_sha = sha256_file(output)
    external_manifest = final_manifest(output, archive_entries, artifact_sha)
    external_manifest_path = output.parent / "ADMIN_MANIFEST.json"
    external_manifest_path.write_text(json.dumps(external_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    checksum_text = f"{artifact_sha}  {output.name}\n{sha256_file(external_manifest_path)}  {external_manifest_path.name}\n"
    admin_sums_path = output.parent / "ADMIN_SHA256SUMS"
    admin_sums_path.write_text(checksum_text, encoding="utf-8", newline="\n")
    if not (output.parent / "PLAYER_SOURCE_MANIFEST.json").exists():
        (output.parent / "SHA256SUMS").write_text(checksum_text, encoding="utf-8", newline="\n")
    return {
        "status": "pass",
        "artifact": output.as_posix(),
        "sha256": artifact_sha,
        "file_count": len(archive_entries),
        "manifest": external_manifest_path.as_posix(),
        "checksums": admin_sums_path.as_posix(),
        "sploit_count": len(REQUIRED_SPLOITS),
        "fix_count": len(REQUIRED_FIXES),
    }


def copy_admin_material(stage: Path) -> None:
    for relative in REQUIRED_ROOT_FILES:
        copy_file(ROOT / relative, stage / relative)
    for root in INCLUDED_ROOTS:
        source_root = ROOT / root
        if root == Path("validation"):
            (stage / "validation").mkdir(parents=True, exist_ok=True)
        if not source_root.exists():
            continue
        for source in iter_included_files(source_root):
            relative = source.relative_to(ROOT)
            copy_file(source, stage / relative)


def iter_included_files(source_root: Path) -> Iterable[Path]:
    for source in sorted(source_root.rglob("*"), key=lambda item: item.relative_to(ROOT).as_posix()):
        if not source.is_file():
            continue
        relative = source.relative_to(ROOT)
        if should_exclude(relative):
            continue
        yield source


def should_exclude(relative: Path) -> bool:
    path = relative.as_posix()
    parts = relative.parts
    lowered_name = relative.name.lower()
    if any(parts[: len(prefix)] == prefix for prefix in EXCLUDED_PATH_PREFIXES):
        return True
    if any(part in EXCLUDED_DIR_NAMES or part.startswith(EXCLUDED_DIR_PREFIXES) for part in parts[:-1]):
        return True
    if path.startswith("docs/archive/"):
        return True
    if lowered_name in {".ds_store", "thumbs.db", ".coverage"}:
        return True
    if any(lowered_name.endswith(suffix) for suffix in EXCLUDED_FILE_SUFFIX_CHAINS):
        return True
    if relative.suffix.lower() in EXCLUDED_FILE_SUFFIXES:
        return True
    if relative.name in SPLIT_OUTPUTS:
        return True
    return False


def validate_required_inputs(stage: Path) -> None:
    required = {
        "README_ADMIN.md",
        "ADMIN_MANIFEST.json",
        "SHA256SUMS",
        "Makefile",
        "config.yml",
        "checkers/sentinel_aml/checker.py",
        "checkers/sentinel_aml/checker_lib.py",
        "checkers/sentinel_aml/requirements.txt",
        "validation/README.md",
        *(f"sploits/sentinel_aml/{name}" for name in REQUIRED_SPLOITS),
        *(f"fixes/sentinel_aml/{name}" for name in REQUIRED_FIXES),
        *(f"scripts/{name}" for name in REQUIRED_VALIDATION_SCRIPTS),
    }
    present = {path.as_posix() for path in inventory(stage)}
    missing = sorted(required - present)
    if missing:
        raise FileNotFoundError(f"admin organizer artifact is missing required files: {', '.join(missing)}")


def write_admin_readme(stage: Path) -> None:
    readme = """# Sentinel AML Admin Organizer Package

This package is organizer-only. It contains checker, reference exploit, reference fix, validation, and evidence materials that must not be distributed to participant teams.

## Checker

Set the service address and checker secret in the execution environment used by the gameserver. The checker entrypoint is:

```sh
python -B checkers/sentinel_aml/checker.py check <host>
python -B checkers/sentinel_aml/checker.py havoc <host>
python -B checkers/sentinel_aml/checker.py put <host> <flag_id> <flag> <vuln>
python -B checkers/sentinel_aml/checker.py get <host> <flag_id> <flag> <vuln>
```

ForcAD registration metadata is in `config.yml`.

## Reference Exploits

Run the five reference exploit scripts from `sploits/sentinel_aml/` against a live player-source deployment when validating the competition matrix:

```sh
python -B sploits/sentinel_aml/aml_dedup_preview.py
python -B sploits/sentinel_aml/aml_audit_timeline.py
python -B sploits/sentinel_aml/aml_related_graph.py
python -B sploits/sentinel_aml/aml_export_redaction.py
python -B sploits/sentinel_aml/aml_network_room.py
```

## Reference Fixes

The five reference patches live under `fixes/sentinel_aml/`. Apply each patch to an extracted player source tree, then rerun checker CHECK plus the relevant exploit-blocked validation.

## Exact Artifact Acceptance

Use this package together with the exact player source artifact:

```sh
python -B scripts/check_player_source_runtime.py out/artifacts/sentinel-aml-player-source.tar.gz
python -B scripts/check_exact_artifact_live_acceptance.py --player-artifact out/artifacts/sentinel-aml-player-source.tar.gz --admin-artifact out/artifacts/sentinel-aml-admin-organizer.tar.gz
python -B scripts/check_competition_matrix_gate.py
```

Do not copy this package into player source distributions.
"""
    (stage / "README_ADMIN.md").write_text(readme, encoding="utf-8", newline="\n")


def write_validation_boundary_note(stage: Path) -> None:
    note = """# Validation Evidence Boundary

Generated local extraction trees, caches, and transfer artifacts are intentionally excluded from this archive. Organizer evidence that is safe to preserve is carried in `docs/wave_reports/`; exact live runtime output should be regenerated with the scripts in this package against the exact player source artifact under review.
"""
    path = stage / "validation" / "README.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(note, encoding="utf-8", newline="\n")


def write_internal_manifest(stage: Path) -> None:
    entries = manifest_entries(stage, exclude={"ADMIN_MANIFEST.json", "SHA256SUMS"})
    manifest = base_manifest(
        artifact_sha=sha256_entries(entries),
        artifact_path=f"{ARCHIVE_ROOT}/",
        archive_entries=entries,
        hash_scope="package-tree",
    )
    (stage / "ADMIN_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_internal_checksums(stage: Path) -> None:
    files = [path for path in inventory(stage) if path.as_posix() != "SHA256SUMS"]
    lines = [f"{sha256_file(stage / relative)}  {relative.as_posix()}" for relative in files]
    (stage / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def base_manifest(
    artifact_sha: str | None,
    artifact_path: str | None,
    archive_entries: list[dict[str, Any]] | None,
    *,
    hash_scope: str,
) -> dict[str, Any]:
    sploits = [f"sploits/sentinel_aml/{name}" for name in REQUIRED_SPLOITS]
    fixes = [f"fixes/sentinel_aml/{name}" for name in REQUIRED_FIXES]
    return {
        "package_name": "sentinel-aml-admin-organizer",
        "package_version": BUILDER_VERSION,
        "schema": "sentinel-aml-admin-organizer-manifest.v1",
        "artifact": {
            "name": DEFAULT_OUTPUT.name,
            "path": artifact_path,
            "sha256": artifact_sha,
            "hash_scope": hash_scope,
            "archive_root": ARCHIVE_ROOT,
            "artifact_class": "admin-organizer",
            "audience": "competition operators/organizers",
            "player_facing": False,
            "organizer_only": True,
        },
        "builder": {
            "name": "scripts/build_admin_organizer_artifact.py",
            "version": BUILDER_VERSION,
        },
        "generated_at": GENERATED_TIMESTAMP,
        "generated_timestamp": GENERATED_TIMESTAMP,
        "checker": {
            "path": "checkers/sentinel_aml/checker.py",
            "version": checker_version(),
            "config": "config.yml",
        },
        "sploits": sploits,
        "fixes": fixes,
        "matrix_gate_command": "python -B scripts/check_competition_matrix_gate.py",
        "exact_artifact_acceptance_command": (
            "python -B scripts/check_exact_artifact_live_acceptance.py "
            "--player-artifact out/artifacts/sentinel-aml-player-source.tar.gz "
            "--admin-artifact out/artifacts/sentinel-aml-admin-organizer.tar.gz"
        ),
        "source_runtime_command": "python -B scripts/check_player_source_runtime.py out/artifacts/sentinel-aml-player-source.tar.gz",
        "included_roots": [path.as_posix() for path in INCLUDED_ROOTS],
        "excluded_generated_categories": [
            "__pycache__",
            "node_modules",
            "frontend/dist",
            "out",
            "tmp",
            "nested transfer archives",
            "local validation extraction trees",
            "docs/archive",
        ],
        "files": archive_entries or [],
        "file_count": len(archive_entries or []),
    }


def final_manifest(output: Path, archive_entries: list[dict[str, Any]], artifact_sha: str) -> dict[str, Any]:
    return base_manifest(
        artifact_sha=artifact_sha,
        artifact_path=output.as_posix(),
        archive_entries=archive_entries,
        hash_scope="archive",
    )


def checker_version() -> str:
    checker_lib = ROOT / CHECKER_ROOT / "checker_lib.py"
    text = checker_lib.read_text(encoding="utf-8")
    private_schema = search_constant(text, "PRIVATE_STATE_SCHEMA_VERSION") or "unknown"
    noise_schema = search_constant(text, "NOISE_STATE_SCHEMA_VERSION") or "unknown"
    timeout = search_constant(text, "CHECKER_TIMEOUT_SECONDS") or "unknown"
    return f"pfr.private-state-v{private_schema}.noise-v{noise_schema}.timeout-{timeout}s"


def search_constant(text: str, name: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(name)}\s*=\s*([0-9]+)", text)
    return match.group(1) if match else None


def inventory(root: Path) -> list[Path]:
    return sorted((path.relative_to(root) for path in root.rglob("*") if path.is_file()), key=lambda item: item.as_posix())


def write_archive(stage: Path, output: Path, files: Iterable[Path]) -> list[dict[str, Any]]:
    payload = io.BytesIO()
    entries: list[dict[str, Any]] = []
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for relative in sorted(files, key=lambda item: item.as_posix()):
            source = stage / relative
            member_name = f"{ARCHIVE_ROOT}/{relative.as_posix()}"
            info = archive.gettarinfo(str(source), arcname=member_name)
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
            entries.append(
                {
                    "path": member_name,
                    "size": size,
                    "size_bytes": size,
                    "sha256": digest,
                    "category": manifest_category(relative),
                }
            )
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=FIXED_MTIME) as gz:
            gz.write(payload.getvalue())
    return entries


def archive_mode(relative: Path, source: Path) -> int:
    path = relative.as_posix()
    if path in {"sentinel_aml/checker.py", "checkers/sentinel_aml/checker.py"}:
        return 0o755
    if path.startswith("scripts/") and path.endswith(".py"):
        return 0o755
    if path.startswith("sploits/") and path.endswith(".py"):
        return 0o755
    return 0o644


def copy_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(source.as_posix())
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def manifest_entries(root: Path, *, exclude: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = exclude or set()
    entries: list[dict[str, Any]] = []
    for relative in inventory(root):
        if relative.as_posix() in excluded:
            continue
        source = root / relative
        size = source.stat().st_size
        entries.append(
            {
                "path": relative.as_posix(),
                "size": size,
                "size_bytes": size,
                "sha256": sha256_file(source),
                "category": manifest_category(relative),
            }
        )
    return entries


def sha256_entries(entries: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: str(item["path"])):
        digest.update(str(entry["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry["size"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def manifest_category(relative: Path) -> str:
    path = relative.as_posix()
    if path.startswith(f"{ARCHIVE_ROOT}/"):
        path = path[len(ARCHIVE_ROOT) + 1 :]
    if path.startswith("sploits/"):
        return "sploit"
    if path.startswith("fixes/"):
        return "fix"
    if path.startswith("checkers/"):
        return "checker-copy"
    if path.startswith("scripts/") or path.startswith("tests/") or path.startswith("validation/"):
        return "validation"
    if path.startswith("docs/") or path in {"README_ADMIN.md", "Makefile", "config.yml"}:
        return "docs"
    if path in {"ADMIN_MANIFEST.json", "SHA256SUMS"} or path.endswith("MANIFEST.json") or path.endswith("SHA256SUMS"):
        return "manifest"
    return "validation"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
