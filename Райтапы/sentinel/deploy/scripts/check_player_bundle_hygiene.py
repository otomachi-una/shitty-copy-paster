#!/usr/bin/env python3
"""Validate that a candidate player bundle does not disclose organizer-only material."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable, NamedTuple


ROOT = Path(__file__).resolve().parents[1]
MAX_CONTENT_BYTES = 4 * 1024 * 1024

class ArtifactPolicy(NamedTuple):
    name: str
    source_delivery: bool
    binary_delivery: bool
    ignored_content_prefixes: tuple[str, ...]
    forbidden_prefixes: tuple[str, ...]


DENY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("vulnerable", re.compile(r"(?<![A-Za-z0-9])vulnerable(?![A-Za-z0-9])", re.IGNORECASE)),
    ("aml1", re.compile(r"(?<![A-Za-z0-9])aml1(?![A-Za-z0-9])", re.IGNORECASE)),
    ("aml2", re.compile(r"(?<![A-Za-z0-9])aml2(?![A-Za-z0-9])", re.IGNORECASE)),
    ("aml3", re.compile(r"(?<![A-Za-z0-9])aml3(?![A-Za-z0-9])", re.IGNORECASE)),
    ("aml4", re.compile(r"(?<![A-Za-z0-9])aml4(?![A-Za-z0-9])", re.IGNORECASE)),
    ("aml5", re.compile(r"(?<![A-Za-z0-9])aml5(?![A-Za-z0-9])", re.IGNORECASE)),
    ("AML-1", re.compile(r"(?<![A-Za-z0-9])AML-1(?![A-Za-z0-9])", re.IGNORECASE)),
    ("AML-2", re.compile(r"(?<![A-Za-z0-9])AML-2(?![A-Za-z0-9])", re.IGNORECASE)),
    ("AML-3", re.compile(r"(?<![A-Za-z0-9])AML-3(?![A-Za-z0-9])", re.IGNORECASE)),
    ("AML-4", re.compile(r"(?<![A-Za-z0-9])AML-4(?![A-Za-z0-9])", re.IGNORECASE)),
    ("AML-5", re.compile(r"(?<![A-Za-z0-9])AML-5(?![A-Za-z0-9])", re.IGNORECASE)),
    ("exploit", re.compile(r"(?<![A-Za-z0-9])exploits?(?![A-Za-z0-9])", re.IGNORECASE)),
    ("sploit", re.compile(r"(?<![A-Za-z0-9])sploits?(?![A-Za-z0-9])", re.IGNORECASE)),
    ("fixes", re.compile(r"(?<![A-Za-z0-9])fixes(?![A-Za-z0-9])", re.IGNORECASE)),
    ("checker", re.compile(r"(?<![A-Za-z0-9])checkers?(?![A-Za-z0-9])", re.IGNORECASE)),
    ("flag", re.compile(r"(?<![A-Za-z0-9])flag(?![A-Za-z0-9])", re.IGNORECASE)),
    ("flag_value", re.compile(r"(?<![A-Za-z0-9])flag_value(?![A-Za-z0-9])", re.IGNORECASE)),
    ("flag_id", re.compile(r"(?<![A-Za-z0-9])flag_id(?![A-Za-z0-9])", re.IGNORECASE)),
    ("putflag", re.compile(r"(?<![A-Za-z0-9])putflag(?![A-Za-z0-9])", re.IGNORECASE)),
    ("getflag", re.compile(r"(?<![A-Za-z0-9])getflag(?![A-Za-z0-9])", re.IGNORECASE)),
    ("attack_info", re.compile(r"(?<![A-Za-z0-9])attack_info(?![A-Za-z0-9])", re.IGNORECASE)),
    ("public_attack_data", re.compile(r"(?<![A-Za-z0-9])public_attack_data(?![A-Za-z0-9])", re.IGNORECASE)),
    ("LEAK_TARGET", re.compile(r"(?<![A-Za-z0-9])LEAK_TARGET(?![A-Za-z0-9])")),
    ("MUST_NOT_LEAK", re.compile(r"(?<![A-Za-z0-9])MUST_NOT_LEAK(?![A-Za-z0-9])")),
    ("checker_secret", re.compile(r"(?<![A-Za-z0-9])checker_secret(?![A-Za-z0-9])", re.IGNORECASE)),
    ("checker_private", re.compile(r"(?<![A-Za-z0-9])checker_private(?![A-Za-z0-9])", re.IGNORECASE)),
    ("secret_for_checker", re.compile(r"(?<![A-Za-z0-9])secret_for_checker(?![A-Za-z0-9])", re.IGNORECASE)),
    (
        "build-profile-token",
        re.compile(
            r"(?<![A-Za-z0-9])(?:COMPETITION_TAGS|case_match_preview|audit_detail_view|entity_review_summary|linked_case_export_detail|network_room_detail|aml[1-5]_vulnerable)(?![A-Za-z0-9])",
            re.IGNORECASE,
        ),
    ),
    ("go-build-constraint", re.compile(r"//go:build|// \+build")),
)
NON_ALLOWLISTABLE_TOKENS = {
    "vulnerable",
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
    "exploit",
    "sploit",
    "fixes",
    "checker",
    "flag_value",
    "flag_id",
    "putflag",
    "getflag",
    "attack_info",
    "public_attack_data",
    "LEAK_TARGET",
    "MUST_NOT_LEAK",
    "checker_secret",
    "checker_private",
    "secret_for_checker",
    "build-profile-token",
    "go-build-constraint",
}
GO_CLI_FLAG_ENTRYPOINTS = {
    "cmd/aml-api/main.go",
    "cmd/aml-worker/main.go",
}

SOURCE_VARIANT_PATH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("build-profile-path", re.compile(r"(^|/)(audit|dedup|export|graph|network_room|dossier)_profile(_|\.)", re.IGNORECASE)),
    ("dual-policy-source-file", re.compile(r"(^|/)[^/]*(?:_default\.go|_detail\.go|case_match|linked_case_export)[^/]*$", re.IGNORECASE)),
)

SOURCE_VARIANT_CONTENT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("build-profile-identifier", re.compile(r"(ProfileEnabled|ForProfile|ExportProfileData|ExportProfileMaps|LinkedCaseProfileData)")),
    (
        "build-profile-switch",
        re.compile(
            r"(COMPETITION_TAGS|case_match_preview|audit_detail_view|entity_review_summary|linked_case_export_detail|network_room_detail|aml[1-5]_vulnerable|//go:build|// \+build)",
            re.IGNORECASE,
        ),
    ),
)

ORGANIZER_ONLY_PREFIXES: tuple[str, ...] = (
    "checkers/",
    "e2e/",
    "frontend/",
    "sploits/",
    "exploits/",
    "fixes/",
    "tests/",
    "scripts/",
    "docs/",
)


THIRD_PARTY_CONTENT_PREFIXES: tuple[str, ...] = (
    "vendor/",
)
BINARY_CONTENT_PREFIXES: tuple[str, ...] = (
    "bin/",
)
BINARY_IMAGE_POLICY = ArtifactPolicy(
    name="binary-image",
    source_delivery=False,
    binary_delivery=True,
    ignored_content_prefixes=BINARY_CONTENT_PREFIXES,
    forbidden_prefixes=ORGANIZER_ONLY_PREFIXES,
)
SOURCE_POLICY = ArtifactPolicy(
    name="source",
    source_delivery=True,
    binary_delivery=False,
    ignored_content_prefixes=THIRD_PARTY_CONTENT_PREFIXES,
    forbidden_prefixes=ORGANIZER_ONLY_PREFIXES,
)
UNKNOWN_POLICY = ArtifactPolicy(
    name="unknown",
    source_delivery=False,
    binary_delivery=False,
    ignored_content_prefixes=THIRD_PARTY_CONTENT_PREFIXES + BINARY_CONTENT_PREFIXES,
    forbidden_prefixes=ORGANIZER_ONLY_PREFIXES,
)
PARTICIPANT_UI_PREFIX = "ui/"
PARTICIPANT_UI_REQUIRED_FILES = {
    "ui/index.html",
    "ui/runtime-config.js",
}
PARTICIPANT_UI_FORBIDDEN_SEGMENTS = {
    ".cache",
    ".playwright",
    ".vite",
    "blob-report",
    "e2e",
    "node_modules",
    "playwright-report",
    "scripts",
    "src",
    "test-results",
    "tests",
}
PARTICIPANT_UI_FORBIDDEN_FILE_NAMES = {
    "AGENTS.md",
    "SKILL.md",
    "package-lock.json",
    "package.json",
    "playwright.config.ts",
    "README.md",
    "tsconfig.app.json",
    "tsconfig.json",
    "tsconfig.node.json",
    "vite.config.ts",
}
PARTICIPANT_UI_FORBIDDEN_SUFFIXES = {
    ".map",
    ".ts",
    ".tsx",
    ".tsbuildinfo",
}
LOCAL_GENERATED_FORBIDDEN_SEGMENTS = {
    ".cache",
    ".pytest_cache",
    ".ruff_cache",
    ".vite",
    "__pycache__",
    "node_modules",
    "out",
    "temp",
    "tmp",
    "validation",
}
LOCAL_GENERATED_FORBIDDEN_SUFFIXES = {
    ".map",
    ".pyc",
    ".pyo",
    ".tar",
    ".test",
    ".tgz",
    ".tsbuildinfo",
    ".zip",
}
LOCAL_GENERATED_FORBIDDEN_SUFFIX_CHAINS = (
    ".tar.gz",
)
LOCAL_GENERATED_FORBIDDEN_PREFIXES = (
    ".appdata",
    ".gocache",
)
PARTICIPANT_UI_CONTENT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("source-map-reference", re.compile(r"sourceMappingURL|//# sourceMappingURL=", re.IGNORECASE)),
    ("ui-test-framework", re.compile(r"\b(?:playwright|vitest|testing-library)\b", re.IGNORECASE)),
    ("ui-scanner-rule", re.compile(r"\b(?:security-scan|package-source|playerForbidden|DENY_PATTERNS)\b", re.IGNORECASE)),
    ("agent-workflow-hint", re.compile(r"\b(?:AGENTS\.md|SKILL\.md|sentinel-aml-ui-director|agent workflow)\b", re.IGNORECASE)),
    ("developer-ui-vocabulary", re.compile(r"\b(?:DTO|serializer|projection|adapter|backend|API contract)\b", re.IGNORECASE)),
)


class BundleMember(NamedTuple):
    path: str
    data: bytes | None
    is_dir: bool = False


def normalize_member_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized


def is_unsafe_member_path(path: str) -> bool:
    raw = path.replace("\\", "/")
    parts = raw.split("/")
    return raw.startswith("/") or re.match(r"^[A-Za-z]:", raw) is not None or any(part == ".." for part in parts)


def load_allowlist(path: Path | None) -> list[dict[str, object]]:
    if path is None:
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("allowlist must be a JSON object")
    entries = data.get("allow", [])
    if not isinstance(entries, list):
        raise ValueError("allowlist 'allow' must be a list")
    normalized = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("allowlist entries must be objects")
        normalized.append(entry)
    return normalized


def is_allowed(issue_type: str, path: str, token: str, allowlist: list[dict[str, object]]) -> bool:
    if token in NON_ALLOWLISTABLE_TOKENS:
        return False
    for entry in allowlist:
        entry_type = entry.get("type", "*")
        if entry_type not in ("*", issue_type):
            continue
        path_glob = str(entry.get("path", "*"))
        if not fnmatch.fnmatch(path, path_glob):
            continue
        tokens = entry.get("tokens", "*")
        if tokens == "*":
            return True
        if isinstance(tokens, list) and token in {str(item) for item in tokens}:
            return True
    return False


def artifact_policy(member_data: dict[str, bytes | None]) -> ArtifactPolicy:
    status = load_packaging_status(member_data)
    mode = str(status.get("delivery_mode", "")) if status is not None else ""
    if mode == "binary-image":
        return BINARY_IMAGE_POLICY
    if mode in {"source", "staged-source-candidate", "flattened-source-candidate"}:
        return SOURCE_POLICY
    if any(path in {"go.mod", "go.sum"} or path.endswith(".go") or path.startswith(("cmd/", "internal/")) for path in member_data):
        return SOURCE_POLICY
    return UNKNOWN_POLICY


def iter_directory_members(root: Path) -> Iterable[BundleMember]:
    for path in sorted(root.rglob("*")):
        relative = normalize_member_path(path.relative_to(root).as_posix())
        if path.is_dir():
            yield BundleMember(relative + "/", None, is_dir=True)
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            yield BundleMember(relative, f"READ_ERROR: {exc}".encode("utf-8"))
            continue
        yield BundleMember(relative, data[:MAX_CONTENT_BYTES], is_dir=False)


def iter_tar_members(path: Path) -> Iterable[BundleMember]:
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            name = normalize_member_path(member.name)
            if is_unsafe_member_path(member.name):
                yield BundleMember(member.name, b"UNSAFE_MEMBER_PATH", is_dir=member.isdir())
                continue
            if member.isdir():
                yield BundleMember(name.rstrip("/") + "/", None, is_dir=True)
                continue
            extracted = archive.extractfile(member)
            data = extracted.read(MAX_CONTENT_BYTES) if extracted is not None else b""
            yield BundleMember(name, data, is_dir=False)


def iter_zip_members(path: Path) -> Iterable[BundleMember]:
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = normalize_member_path(info.filename)
            if is_unsafe_member_path(info.filename):
                yield BundleMember(info.filename, b"UNSAFE_MEMBER_PATH", is_dir=info.is_dir())
                continue
            if info.is_dir():
                yield BundleMember(name.rstrip("/") + "/", None, is_dir=True)
                continue
            yield BundleMember(name, archive.read(info, pwd=None)[:MAX_CONTENT_BYTES], is_dir=False)


def iter_bundle_members(candidate: Path) -> Iterable[BundleMember]:
    if candidate.is_dir():
        yield from iter_directory_members(candidate)
        return
    suffixes = [suffix.lower() for suffix in candidate.suffixes]
    if candidate.suffix.lower() == ".zip":
        yield from iter_zip_members(candidate)
        return
    if ".tar" in suffixes or candidate.suffix.lower() in {".tgz", ".tbz2", ".txz"}:
        yield from iter_tar_members(candidate)
        return
    raise ValueError(f"unsupported candidate type: {candidate}")


def check_candidate_not_repo(candidate: Path) -> dict[str, str]:
    try:
        resolved = candidate.resolve()
    except OSError:
        resolved = candidate.absolute()
    if resolved == ROOT:
        return {
            "name": "candidate-boundary",
            "status": "fail",
            "message": "candidate path is the organizer repository root; build a player candidate first",
        }
    return {"name": "candidate-boundary", "status": "pass", "message": str(resolved)}


def check_member(member: BundleMember, allowlist: list[dict[str, object]], policy: ArtifactPolicy) -> list[str]:
    failures: list[str] = []
    path = normalize_member_path(member.path)
    path_for_prefix = path.rstrip("/") + "/"
    if is_unsafe_member_path(path):
        failures.append(f"{path}: unsafe archive member path")
        return failures
    generated = generated_artifact_path_reason(path)
    if generated:
        failures.append(f"{path}: local/generated/cache artifact: {generated}")

    for prefix in policy.forbidden_prefixes:
        token = prefix.rstrip("/")
        if path_for_prefix == prefix or path_for_prefix.startswith(prefix):
            if not is_allowed("forbidden-path", path, token, allowlist):
                failures.append(f"{path}: forbidden player bundle path prefix {prefix}")
            break

    for token, pattern in DENY_PATTERNS:
        if pattern.search(path) and not is_allowed("path-token", path, token, allowlist):
            failures.append(f"{path}: denied token in path: {token}")
    if should_apply_project_source_rules(path, policy):
        for token, pattern in SOURCE_VARIANT_PATH_PATTERNS:
            if pattern.search(path) and not is_allowed("source-vocabulary", path, token, allowlist):
                failures.append(f"{path}: player source exposes internal build-profile vocabulary: {token}")

    if member.data is None:
        return failures
    if path.startswith(policy.ignored_content_prefixes):
        return failures
    text = member.data.decode("utf-8", errors="ignore")
    for token, pattern in DENY_PATTERNS:
        if token == "flag" and is_allowed_go_cli_flag_context(path, text, policy):
            continue
        if pattern.search(text) and not is_allowed("content-token", path, token, allowlist):
            failures.append(f"{path}: denied token in content: {token}")
    if should_apply_project_source_rules(path, policy):
        for token, pattern in SOURCE_VARIANT_CONTENT_PATTERNS:
            if pattern.search(text) and not is_allowed("source-vocabulary", path, token, allowlist):
                failures.append(f"{path}: player source exposes internal build-profile vocabulary: {token}")
    return failures


def strip_transfer_archive_root(members: list[BundleMember]) -> list[BundleMember]:
    paths = [normalize_member_path(member.path).rstrip("/") for member in members if normalize_member_path(member.path).rstrip("/")]
    if not paths:
        return members
    first_parts = [path.split("/", 1)[0] for path in paths]
    root = first_parts[0]
    if not root.startswith("sentinel-aml-") or any(part != root for part in first_parts):
        return members
    stripped: list[BundleMember] = []
    for member in members:
        path = normalize_member_path(member.path)
        suffix = path[len(root) :].lstrip("/")
        stripped.append(BundleMember(suffix, member.data, member.is_dir))
    return stripped


def generated_artifact_path_reason(path: str) -> str:
    normalized = normalize_member_path(path).rstrip("/")
    if not normalized:
        return ""
    segments = [segment for segment in normalized.split("/") if segment]
    lowered_segments = [segment.lower() for segment in segments]
    lowered_name = lowered_segments[-1]
    for segment in lowered_segments:
        if segment in LOCAL_GENERATED_FORBIDDEN_SEGMENTS:
            return f"forbidden segment {segment}"
        if segment.startswith(LOCAL_GENERATED_FORBIDDEN_PREFIXES):
            return f"forbidden cache segment {segment}"
    if lowered_name.endswith(LOCAL_GENERATED_FORBIDDEN_SUFFIX_CHAINS):
        return f"forbidden suffix {lowered_name}"
    if Path(lowered_name).suffix in LOCAL_GENERATED_FORBIDDEN_SUFFIXES:
        return f"forbidden suffix {Path(lowered_name).suffix}"
    return ""


def should_apply_project_source_rules(path: str, policy: ArtifactPolicy) -> bool:
    return policy.source_delivery and path.endswith(".go") and path.startswith(("cmd/", "internal/"))


def is_allowed_go_cli_flag_context(path: str, text: str, policy: ArtifactPolicy) -> bool:
    if not policy.source_delivery or path not in GO_CLI_FLAG_ENTRYPOINTS:
        return False
    if '"flag"' not in text and "`flag`" not in text:
        return False
    return "flag.Parse()" in text and re.search(r"\bflag\.(?:String|Bool|Duration)\(", text) is not None


def validate_player_bundle(
    candidate: Path,
    allowlist_path: Path | None = None,
    *,
    require_runtime_ready: bool = False,
) -> dict[str, object]:
    allowlist = load_allowlist(allowlist_path)
    checks: list[dict[str, str]] = [check_candidate_not_repo(candidate)]
    if checks[0]["status"] == "fail":
        return {"status": "fail", "checks": checks}

    if not candidate.exists():
        return {
            "status": "fail",
            "checks": checks
            + [{"name": "candidate-exists", "status": "fail", "message": f"missing candidate: {candidate}"}],
        }

    failures: list[str] = []
    member_count = 0
    member_data: dict[str, bytes | None] = {}
    members: list[BundleMember] = []
    try:
        for member in iter_bundle_members(candidate):
            members.append(member)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
        failures.append(str(exc))
    members = strip_transfer_archive_root(members)
    member_count = len(members)
    for member in members:
        member_data[normalize_member_path(member.path)] = member.data

    policy = artifact_policy(member_data)
    if not failures:
        for member in members:
            failures.extend(check_member(member, allowlist, policy))
    failures.extend(check_delivery_boundary(member_data))
    failures.extend(check_participant_ui_artifact(member_data, allowlist))

    checks.append(
        {
            "name": "player-bundle-leak-scan",
            "status": "fail" if failures else "pass",
            "message": "; ".join(failures[:40]) if failures else f"scanned {member_count} candidate members",
        }
    )
    if require_runtime_ready:
        readiness_failures = check_runtime_readiness(member_data)
        checks.append(
            {
                "name": "player-bundle-runtime-readiness",
                "status": "fail" if readiness_failures else "pass",
                "message": "; ".join(readiness_failures[:20]) if readiness_failures else "runtime delivery proof present",
            }
        )
    return {"status": "fail" if any(check["status"] == "fail" for check in checks) else "pass", "checks": checks}


def check_delivery_boundary(member_data: dict[str, bytes | None]) -> list[str]:
    status = load_packaging_status(member_data)
    if status is None or status.get("delivery_mode") != "binary-image":
        return []

    paths = set(member_data)
    failures: list[str] = []
    required = {"deploy/compose.yaml"}
    if not status.get("image_reference"):
        required.update({"bin/aml-api", "bin/aml-worker", "bin/aml-migrate", "Dockerfile"})
    missing = sorted(required - paths)
    if missing:
        failures.append(f"binary/image delivery missing runtime artifacts: {', '.join(missing)}")

    participant_ui = status.get("participant_ui")
    if isinstance(participant_ui, dict) and participant_ui.get("required") is True:
        if participant_ui.get("included") is not True:
            failures.append("canonical binary/image delivery requires participant_ui.included=true")
        ui_missing = sorted(path for path in PARTICIPANT_UI_REQUIRED_FILES if path not in paths)
        if ui_missing:
            failures.append(f"canonical binary/image delivery missing participant UI files: {', '.join(ui_missing)}")
    delivered_components = status.get("delivered_components")
    if isinstance(delivered_components, list):
        by_key = {component.get("key"): component for component in delivered_components if isinstance(component, dict)}
        ui_component = by_key.get("participant-ui")
        if isinstance(ui_component, dict) and ui_component.get("required") is True:
            if ui_component.get("included") is not True:
                failures.append("canonical binary/image delivery requires delivered_components participant-ui included=true")
            if not any(path.startswith("ui/") for path in paths):
                failures.append("canonical binary/image delivery has no ui/ members")

    source_leaks = sorted(
        path
        for path in paths
        if path in {"go.mod", "go.sum"}
        or path.endswith(".go")
        or path.startswith(("cmd/", "internal/", "vendor/"))
    )
    if source_leaks:
        failures.append(f"binary/image delivery contains source material: {', '.join(source_leaks[:20])}")
    return failures


def check_participant_ui_artifact(member_data: dict[str, bytes | None], allowlist: list[dict[str, object]]) -> list[str]:
    ui_paths = sorted(path for path in member_data if path == "ui" or path.startswith(PARTICIPANT_UI_PREFIX))
    if not ui_paths:
        return []

    failures: list[str] = []
    missing = sorted(path for path in PARTICIPANT_UI_REQUIRED_FILES if path not in member_data)
    if missing:
        failures.append(f"participant UI artifact missing runtime files: {', '.join(missing)}")

    for path in ui_paths:
        normalized = normalize_member_path(path).rstrip("/")
        relative = normalized[len(PARTICIPANT_UI_PREFIX) :] if normalized.startswith(PARTICIPANT_UI_PREFIX) else normalized
        segments = [segment for segment in relative.split("/") if segment]
        lowered_segments = {segment.lower() for segment in segments}
        file_name = segments[-1] if segments else ""
        lowered_file = file_name.lower()

        if lowered_segments & PARTICIPANT_UI_FORBIDDEN_SEGMENTS:
            failures.append(f"{path}: participant UI includes development-only directory")
        if file_name in PARTICIPANT_UI_FORBIDDEN_FILE_NAMES:
            failures.append(f"{path}: participant UI includes development-only file")
        if any(lowered_file.endswith(suffix) for suffix in PARTICIPANT_UI_FORBIDDEN_SUFFIXES):
            failures.append(f"{path}: participant UI includes forbidden source/build artifact")

        data = member_data[path]
        if data is None:
            continue
        text = data.decode("utf-8", errors="ignore")
        for token, pattern in PARTICIPANT_UI_CONTENT_PATTERNS:
            if pattern.search(text) and not is_allowed("participant-ui-content", path, token, allowlist):
                failures.append(f"{path}: participant UI exposes {token}")

    runtime_config = member_data.get("ui/runtime-config.js")
    if runtime_config is not None:
        text = runtime_config.decode("utf-8", errors="ignore")
        if re.search(r"(?i)(bearer|password|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]+", text):
            failures.append("ui/runtime-config.js: runtime config appears to contain secret-bearing material")
    return failures


def check_runtime_readiness(member_data: dict[str, bytes | None]) -> list[str]:
    failures: list[str] = []
    paths = set(member_data)
    status = load_packaging_status(member_data)
    if status is None:
        return ["missing PACKAGING_STATUS.json runtime-readiness marker"]

    if status.get("final_package") is not True:
        failures.append("candidate is staged/not final; runtime readiness has not been proven")
    proof = status.get("runtime_proof")
    if not isinstance(proof, dict) or not proof.get("command") or proof.get("exit_code") != 0:
        failures.append("missing successful runtime_proof command record")

    mode = str(status.get("delivery_mode", ""))
    if mode == "source":
        required = {"go.mod", "go.sum", "vendor/modules.txt", "Dockerfile", "deploy/compose.yaml"}
        missing = sorted(required - paths)
        if missing:
            failures.append(f"source delivery missing runtime files: {', '.join(missing)}")
    elif mode == "binary-image":
        source_leaks = sorted(
            path
            for path in paths
            if path in {"go.mod", "go.sum"} or path.endswith(".go") or path.startswith(("cmd/", "internal/", "vendor/"))
        )
        if source_leaks:
            failures.append(f"binary/image delivery contains source files: {', '.join(source_leaks[:10])}")
        if "deploy/compose.yaml" not in paths and not status.get("image_reference"):
            failures.append("binary/image delivery missing deploy/compose.yaml or image_reference")
    else:
        failures.append(f"unsupported final delivery_mode: {mode}")
    return failures


def load_packaging_status(member_data: dict[str, bytes | None]) -> dict[str, object] | None:
    data = member_data.get("PACKAGING_STATUS.json")
    if data is None:
        return None
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="candidate player tree, tar archive, or zip archive")
    parser.add_argument("--allowlist", type=Path, help="JSON allowlist for intentional neutral contexts")
    parser.add_argument(
        "--require-runtime-ready",
        action="store_true",
        help="fail unless the candidate proves final runnable source or binary/image delivery",
    )
    args = parser.parse_args(argv)

    result = validate_player_bundle(args.candidate, args.allowlist, require_runtime_ready=args.require_runtime_ready)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
