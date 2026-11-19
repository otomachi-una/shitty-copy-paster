#!/usr/bin/env python3
"""Validate the canonical competition runtime profile and player delivery mode."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = "Makefile"
PLAYER_BUILDER = "scripts/build_player_bundle.py"
TEST_FILE = "tests/test_competition_runtime_profile.py"
DEFAULT_PLAYER_MANIFEST = "out/manifests/player_manifest.json"
DEFAULT_PLAYER_ARTIFACT = "out/artifacts/sentinel-aml-player-service.tar.gz"
DEFAULT_ARTIFACT_FIRST_SUMMARY = "out/artifact-first-validation-summary.json"

REQUIRED_COMPETITION_TAGS = (
    "case_match_preview",
    "audit_detail_view",
    "entity_review_summary",
    "linked_case_export_detail",
    "network_room_detail",
)
LEGACY_COMPATIBILITY_TAGS = (
    "aml1_vulnerable",
    "aml2_vulnerable",
    "aml3_vulnerable",
    "aml4_vulnerable",
    "aml5_vulnerable",
)
REQUIRED_RUNTIME_TARGETS = (
    "./cmd/aml-api",
    "./cmd/aml-worker",
    "./scripts/migrate",
)
REQUIRED_BINARY_MEMBERS = (
    "bin/aml-api",
    "bin/aml-worker",
    "bin/aml-migrate",
)
SOURCE_DUAL_POLICY_PATTERNS = (
    re.compile(r"(^|/)[^/]*_default\.go$", re.IGNORECASE),
    re.compile(r"(^|/)[^/]*_detail\.go$", re.IGNORECASE),
    re.compile(r"(^|/)[^/]*case_match[^/]*\.go$", re.IGNORECASE),
    re.compile(r"(^|/)[^/]*linked_case_export[^/]*\.go$", re.IGNORECASE),
    re.compile(r"(^|/)[^/]*_profile_[^/]*\.go$", re.IGNORECASE),
)


def validate_competition_runtime_profile(
    repo_root: Path,
    *,
    mode: str = "binary",
    player_manifest: Path | None = None,
    player_artifact: Path | None = None,
) -> dict[str, Any]:
    checks = [
        check_makefile_competition_tags(repo_root),
        check_makefile_runtime_build_target(repo_root),
    ]
    if mode == "binary":
        manifest = player_manifest if player_manifest is not None else repo_root / DEFAULT_PLAYER_MANIFEST
        artifact = player_artifact if player_artifact is not None else repo_root / DEFAULT_PLAYER_ARTIFACT
        checks.append(check_binary_player_artifact_strategy(repo_root, manifest, artifact))
    elif mode == "source":
        manifest = player_manifest if player_manifest is not None else repo_root / DEFAULT_PLAYER_MANIFEST
        artifact = player_artifact if player_artifact is not None else repo_root / DEFAULT_PLAYER_ARTIFACT
        checks.append(check_source_player_artifact_strategy(repo_root, manifest, artifact))
    else:
        checks.append(check("competition-runtime-profile-mode", "mode", False, f"unsupported mode={mode!r}"))
    checks.append(check_focused_test_coverage(repo_root))
    return {"status": aggregate_status(checks), "checks": checks, "mode": mode}


def check_makefile_competition_tags(repo_root: Path) -> dict[str, str]:
    text = read(repo_root, MAKEFILE)
    tags = variable_words(text, "COMPETITION_TAGS")
    missing = [tag for tag in REQUIRED_COMPETITION_TAGS if tag not in tags]
    extra_legacy = [tag for tag in LEGACY_COMPATIBILITY_TAGS if tag in tags]
    ok = not missing and not extra_legacy and len(tags) == len(REQUIRED_COMPETITION_TAGS)
    return check(
        "competition-tags-complete-and-neutral",
        MAKEFILE,
        ok,
        f"tags={tags} missing={missing} legacy={extra_legacy}",
    )


def check_makefile_runtime_build_target(repo_root: Path) -> dict[str, str]:
    text = read(repo_root, MAKEFILE)
    target = make_target_block(text, "competition-runtime-build")
    required_markers = (
        "$(GO_RELEASE_ENV) $(GO) build -tags \"$(COMPETITION_TAGS)\" $(COMPETITION_RUNTIME_TARGETS)",
        *REQUIRED_RUNTIME_TARGETS,
    )
    missing = [marker for marker in required_markers if marker not in text and marker not in target]
    ok = bool(target) and not missing
    return check(
        "competition-runtime-build-uses-canonical-tags",
        MAKEFILE,
        ok,
        f"target_present={bool(target)} missing={missing}",
    )


def check_binary_player_artifact_strategy(repo_root: Path, manifest_path: Path, artifact_path: Path) -> dict[str, str]:
    manifest, error = load_manifest(manifest_path)
    if error:
        return check("binary-player-artifact-runtime-profile", manifest_label(repo_root, manifest_path), False, error)
    archive_members, error = archive_members_with_root_stripped(artifact_path)
    if error:
        return check("binary-player-artifact-runtime-profile", artifact_label(repo_root, artifact_path), False, error)

    runtime = manifest.get("runtime_profile", {})
    artifact = manifest.get("artifact", {})
    manifest_files = [strip_archive_root(str(entry.get("path", "")), str(artifact.get("archive_root", ""))) for entry in manifest.get("files", [])]
    member_set = set(archive_members)
    manifest_set = set(manifest_files)
    missing_binaries = [member for member in REQUIRED_BINARY_MEMBERS if member not in member_set or member not in manifest_set]
    source_leaks = sorted(
        member
        for member in member_set
        if member in {"go.mod", "go.sum"} or member.endswith(".go") or member.startswith(("cmd/", "internal/", "vendor/"))
    )
    runtime_targets = set(strip_archive_root(str(path), str(artifact.get("archive_root", ""))) for path in runtime.get("built_runtime", {}).get("targets", []))
    missing_runtime_targets = [member for member in REQUIRED_BINARY_MEMBERS if member not in runtime_targets]
    evidence = runtime.get("runtime_evidence", [])
    artifact_digest = sha256_path(artifact_path) if artifact_path.is_file() else ""
    passing_evidence = [
        entry
        for entry in evidence
        if isinstance(entry, dict)
        and entry.get("status") == "pass"
        and entry.get("path")
        and entry.get("player_artifact_sha256") == artifact_digest
    ]
    runtime_proof_policy = runtime.get("artifact_local_runtime_proof", {})
    runtime_proof_policy_ok = artifact_local_runtime_proof_policy_ok(runtime_proof_policy)
    labels_exposed = runtime.get("build_profile_evidence", {}).get("labels_exposed_in_player_artifact")
    mode_ok = runtime.get("delivery_mode") in {"binary-image", "oci-image"}
    ok = (
        artifact.get("artifact_class") == "player-service"
        and mode_ok
        and not missing_binaries
        and not missing_runtime_targets
        and not source_leaks
        and (bool(passing_evidence) or runtime_proof_policy_ok)
        and labels_exposed is False
    )
    return check(
        "binary-player-artifact-runtime-profile",
        manifest_label(repo_root, manifest_path),
        ok,
        (
            f"artifact_class={artifact.get('artifact_class')!r} delivery_mode={runtime.get('delivery_mode')!r} "
            f"missing_binaries={missing_binaries} missing_runtime_targets={missing_runtime_targets} "
            f"source_leaks={source_leaks[:10]} exact_artifact_runtime_evidence_count={len(passing_evidence)} "
            f"artifact_local_runtime_proof_policy={runtime_proof_policy_ok} "
            f"labels_exposed_in_player_artifact={labels_exposed!r}"
        ),
    )


def check_source_player_artifact_strategy(repo_root: Path, manifest_path: Path, artifact_path: Path) -> dict[str, str]:
    manifest, error = load_manifest(manifest_path)
    if error:
        return check("source-player-artifact-runtime-profile", manifest_label(repo_root, manifest_path), False, error)
    members, error = archive_members_with_root_stripped(artifact_path)
    if error:
        return check("source-player-artifact-runtime-profile", artifact_label(repo_root, artifact_path), False, error)
    runtime = manifest.get("runtime_profile", {})
    evidence = runtime.get("runtime_evidence", [])
    passing_evidence = [entry for entry in evidence if isinstance(entry, dict) and entry.get("status") == "pass" and entry.get("path")]
    member_set = set(members)
    dual_policy = sorted(member for member in member_set if any(pattern.search(member) for pattern in SOURCE_DUAL_POLICY_PATTERNS))
    dockerfile_text = archive_text(artifact_path, "Dockerfile")
    dockerfile_uses_tags = "go build -tags" in dockerfile_text or "${COMPETITION_TAGS}" in dockerfile_text
    required_source = {"go.mod", "go.sum", "Dockerfile", "deploy/compose.yaml"}
    missing_source = sorted(required_source - member_set)
    ok = (
        runtime.get("delivery_mode") == "source"
        and not missing_source
        and not dual_policy
        and dockerfile_uses_tags
        and bool(passing_evidence)
    )
    return check(
        "source-player-artifact-runtime-profile",
        manifest_label(repo_root, manifest_path),
        ok,
        (
            f"delivery_mode={runtime.get('delivery_mode')!r} missing_source={missing_source} "
            f"dual_policy={dual_policy[:20]} dockerfile_uses_tags={dockerfile_uses_tags} "
            f"runtime_evidence_count={len(passing_evidence)}"
        ),
    )


def check_focused_test_coverage(repo_root: Path) -> dict[str, str]:
    text = read(repo_root, TEST_FILE)
    required = (
        "test_stale_secure_default_source_dockerfile_is_rejected",
        "test_binary_player_artifact_with_artifact_local_runtime_proof_policy_passes",
        "test_source_artifact_containing_dual_policy_files_fails",
        "test_missing_runtime_proof_policy_fails",
    )
    missing = [marker for marker in required if marker not in text]
    return check("competition-runtime-profile-focused-tests-present", TEST_FILE, not missing, f"missing={missing}")


def artifact_local_runtime_proof_policy_ok(policy: Any) -> bool:
    if not isinstance(policy, dict):
        return False
    required_fields = {
        "player_artifact_sha256",
        "admin_artifact_sha256",
        "runtime_validation.runtime_smoke.status",
        "runtime_validation.checker_check_havoc.status",
        "runtime_validation.sploit_matrix.status",
        "runtime_validation.fix_workflow.status",
        "runtime_validation.matrix_status.status",
    }
    bindings = set(str(item) for item in policy.get("artifact_bindings", []) if isinstance(item, str))
    fields = set(str(item) for item in policy.get("required_summary_fields", []) if isinstance(item, str))
    return (
        policy.get("status") in {"external-required", "pass"}
        and policy.get("summary_path") == DEFAULT_ARTIFACT_FIRST_SUMMARY
        and {"player_artifact_sha256", "admin_artifact_sha256"}.issubset(bindings)
        and required_fields.issubset(fields)
    )


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return {}, f"manifest unreadable: {exc}"
    except json.JSONDecodeError as exc:
        return {}, f"manifest is not valid JSON: {exc}"
    if not isinstance(data, dict):
        return {}, "manifest root must be a JSON object"
    return data, ""


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def archive_members_with_root_stripped(path: Path) -> tuple[list[str], str]:
    try:
        with tarfile.open(path, "r:*") as archive:
            names = sorted(member.name for member in archive.getmembers() if member.isfile())
    except (OSError, tarfile.TarError) as exc:
        return [], f"artifact archive unreadable: {exc}"
    return strip_common_root(names), ""


def archive_text(path: Path, member_name: str) -> str:
    try:
        with tarfile.open(path, "r:*") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            names = strip_common_root([member.name for member in members])
            by_name = dict(zip(names, members))
            member = by_name.get(member_name)
            if member is None:
                return ""
            handle = archive.extractfile(member)
            if handle is None:
                return ""
            return handle.read(1024 * 1024).decode("utf-8", errors="ignore")
    except (OSError, tarfile.TarError):
        return ""


def strip_common_root(names: list[str]) -> list[str]:
    normalized = [normalize_member_path(name) for name in names if normalize_member_path(name)]
    if not normalized:
        return normalized
    roots = [name.split("/", 1)[0] for name in normalized]
    if roots and all(root == roots[0] for root in roots):
        return [name.split("/", 1)[1] if "/" in name else "" for name in normalized if "/" in name]
    return normalized


def strip_archive_root(path: str, archive_root: str) -> str:
    normalized = normalize_member_path(path)
    root = normalize_member_path(archive_root).rstrip("/")
    if root and normalized.startswith(root + "/"):
        return normalized[len(root) + 1 :]
    return normalized


def normalize_member_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized


def variable_words(makefile: str, name: str) -> list[str]:
    match = re.search(rf"(?m)^{re.escape(name)}\s*=\s*(.+)$", makefile)
    if not match:
        return []
    return match.group(1).split()


def make_target_block(text: str, target_name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target_name)}:\s*(?:#.*)?$", text)
    if not match:
        return ""
    next_target = re.search(r"(?m)^[A-Za-z0-9_.-]+:\s*(?:#.*)?$", text[match.end() :])
    end = match.end() + next_target.start() if next_target else len(text)
    return text[match.start() : end]


def read(repo_root: Path, relative: str) -> str:
    path = repo_root / relative
    return path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else ""


def manifest_label(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path)


def artifact_label(repo_root: Path, path: Path) -> str:
    return manifest_label(repo_root, path)


def check(name: str, path: str, ok: bool, message: str) -> dict[str, str]:
    return {"name": name, "path": path, "status": "pass" if ok else "fail", "message": "" if ok else message}


def aggregate_status(checks: list[dict[str, Any]]) -> str:
    return "fail" if any(item["status"] == "fail" for item in checks) else "pass"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("binary", "source"), default="binary")
    parser.add_argument("--player-manifest", type=Path, default=ROOT / DEFAULT_PLAYER_MANIFEST)
    parser.add_argument("--player-artifact", type=Path, default=ROOT / DEFAULT_PLAYER_ARTIFACT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = validate_competition_runtime_profile(
        ROOT,
        mode=args.mode,
        player_manifest=args.player_manifest,
        player_artifact=args.player_artifact,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
