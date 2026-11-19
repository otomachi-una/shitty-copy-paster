#!/usr/bin/env python3
"""Build and validate final Sentinel AML release artifacts.

The final release validator is intentionally artifact-first: it builds transfer
archives, extracts those exact bytes into fresh validation directories, deploys
the extracted player runtime, runs the extracted checker, and uses only public
attack data from real checker PUT calls for the reference sploit proofs.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_admin_bundle
import build_artifacts
import build_player_bundle
import check_admin_bundle_hygiene
import check_ctf_disclosure_hygiene
import check_player_bundle_hygiene
import check_wave29_regression


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATE_ROOT = ROOT / "out" / "final-candidate"
DEFAULT_FINAL_ROOT = ROOT / "out" / "final"
DEFAULT_VALIDATION_ROOT = ROOT / "validation"
PLAYER_ARCHIVE_NAME = "sentinel-aml-player-service.tar.gz"
ADMIN_ARCHIVE_NAME = "sentinel-aml-admin-checker.tar.gz"
EVIDENCE_ARCHIVE_NAME = "sentinel-aml-organizer-evidence.tar.gz"
PLAYER_ROOT = "sentinel-aml-player-service"
ADMIN_ROOT = "sentinel-aml-admin-checker"
EVIDENCE_ROOT = "sentinel-aml-organizer-evidence"
CHECKER_OK = 101
FIXED_MTIME = 0
STATUS_NAME = "PACKAGING_STATUS.json"
SUMMARY_NAME = "final_release_validation_summary.json"
REPORT_NAME = "final_release_report.md"

EVIDENCE_FILES = (
    "Makefile",
    "config.yml",
    "checkers/sentinel_aml/checker.py",
    "checkers/sentinel_aml/checker_lib.py",
    "checkers/sentinel_aml/requirements.txt",
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
    "scripts/check_wave29_regression.py",
    "scripts/check_live_competition_matrix.py",
    "scripts/run_go_release_tests.py",
    "scripts/run_vulnerable_profile_tests.py",
    "scripts/check_competition_matrix_gate.py",
    "scripts/check_wave29_gate.py",
    "tests/test_checker_check_workflow.py",
    "tests/test_checker_put_workflow.py",
    "tests/test_checker_get_workflow.py",
    "tests/test_competition_matrix_gate.py",
    "tests/test_wave29_regression.py",
    "docs/wave_reports/wave_32_sploit_fix_matrix.md",
    "docs/wave_reports/wave_34_final_split_package_gate.md",
)


@dataclass(frozen=True)
class AMLCase:
    aml_id: str
    place: int
    sploit: str
    fix_patch: str


AML_CASES = (
    AMLCase("AML-1", 1, "sploits/sentinel_aml/aml_dedup_preview.py", "fixes/sentinel_aml/aml_dedup_preview.patch"),
    AMLCase("AML-2", 1, "sploits/sentinel_aml/aml_audit_timeline.py", "fixes/sentinel_aml/aml_audit_timeline.patch"),
    AMLCase("AML-3", 2, "sploits/sentinel_aml/aml_related_graph.py", "fixes/sentinel_aml/aml_related_graph.patch"),
    AMLCase("AML-4", 1, "sploits/sentinel_aml/aml_export_redaction.py", "fixes/sentinel_aml/aml_export_redaction.patch"),
    AMLCase("AML-5", 2, "sploits/sentinel_aml/aml_network_room.py", "fixes/sentinel_aml/aml_network_room.patch"),
)


class FinalReleaseFailure(RuntimeError):
    pass


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float


def build_and_validate(
    *,
    candidate_root: Path,
    final_root: Path,
    validation_root: Path,
    python: str,
    docker: str,
    go: str,
    skip_runtime: bool,
) -> dict[str, Any]:
    started = time.monotonic()
    candidate_root = candidate_root.resolve()
    final_root = final_root.resolve()
    validation_root = validation_root.resolve()
    ensure_repo_local(candidate_root, "out")
    ensure_repo_local(final_root, "out")
    ensure_repo_local(validation_root, "validation")

    summary: dict[str, Any] = {
        "schema": "sentinel-aml-final-release-validation.v1",
        "status": "fail",
        "competition_ready": False,
        "final_package": False,
        "started_at_unix": int(time.time()),
        "paths": {
            "candidate_root": rel(candidate_root),
            "final_root": rel(final_root),
            "validation_root": rel(validation_root),
        },
        "checks": [],
        "artifacts": {},
        "runtime_validation": {},
        "fix_validation": {},
    }
    clean_dir(candidate_root)
    clean_dir(validation_root / "player-extracted")
    clean_dir(validation_root / "admin-extracted")
    clean_dir(validation_root / "organizer-extracted")

    try:
        artifacts = build_archives(candidate_root)
        summary["artifacts"] = artifacts
        add_check(summary, "archives-built", "pass", "final candidate archives created")

        extracted = extract_validation_archives(candidate_root, validation_root)
        summary["extracted"] = {key: rel(path) for key, path in extracted.items()}
        add_check(summary, "archives-extracted-to-fresh-dirs", "pass", "player/admin/evidence archives extracted")

        hygiene = run_hygiene_checks(candidate_root, artifacts)
        summary["hygiene"] = hygiene
        add_check(summary, "artifact-hygiene", aggregate(hygiene.values()), "player/admin/evidence hygiene")

        if skip_runtime:
            raise FinalReleaseFailure("runtime validation was explicitly skipped")

        runtime = run_exact_runtime_validation(extracted, python=python, docker=docker)
        summary["runtime_validation"] = runtime
        add_check(summary, "exact-artifact-runtime-validation", runtime["status"], runtime.get("message", ""))

        fixes = run_reference_fix_validation(validation_root, python=python, go=go)
        summary["fix_validation"] = fixes
        add_check(summary, "reference-fix-validation", fixes["status"], fixes.get("message", ""))

        if aggregate([runtime["status"], fixes["status"], *hygiene.values()]) != "pass":
            raise FinalReleaseFailure("one or more mandatory final release checks failed")

        summary["status"] = "pass"
        summary["competition_ready"] = True
        summary["final_package"] = True
        summary["promoted_to"] = rel(final_root)
        clean_dir(final_root)
        copy_tree(candidate_root, final_root)
        write_status(final_root, summary, final=True)
        write_report(final_root, summary, verdict="competition-ready")
    except Exception as exc:
        summary["status"] = "fail"
        summary["competition_ready"] = False
        summary["final_package"] = False
        summary["blocker"] = str(exc)
        write_status(candidate_root, summary, final=False)
        write_report(candidate_root, summary, verdict="not-competition-ready")
    finally:
        summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
        summary_path = (final_root if summary.get("status") == "pass" else candidate_root) / SUMMARY_NAME
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return summary


def build_archives(candidate_root: Path) -> dict[str, Any]:
    staging = ROOT / "tmp" / "final-release-staging"
    artifacts_dir = candidate_root / "artifacts"
    manifests_dir = candidate_root / "manifests"
    checksums_dir = candidate_root / "checksums"
    clean_dir(staging)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    manifests_dir.mkdir(parents=True, exist_ok=True)
    checksums_dir.mkdir(parents=True, exist_ok=True)

    player_tree = staging / "player"
    player_allowlist = staging / "player.hygiene-allowlist.json"
    player_result = build_player_bundle.build_player_candidate(player_tree, player_allowlist)
    admin_tree = staging / "admin"
    admin_result = build_admin_bundle.build_admin_candidate(admin_tree)
    evidence_tree = staging / "evidence"
    evidence_result = build_evidence_tree(evidence_tree)

    player_archive = artifacts_dir / PLAYER_ARCHIVE_NAME
    admin_archive = artifacts_dir / ADMIN_ARCHIVE_NAME
    evidence_archive = artifacts_dir / EVIDENCE_ARCHIVE_NAME
    player_entries = build_artifacts.write_archive(player_tree, [Path(path) for path in player_result["files"]], player_archive, PLAYER_ROOT)
    admin_entries = build_artifacts.write_archive(admin_tree, [Path(path) for path in admin_result["files"]], admin_archive, ADMIN_ROOT)
    evidence_entries = build_artifacts.write_archive(evidence_tree, [Path(path) for path in evidence_result["files"]], evidence_archive, EVIDENCE_ROOT)

    player_manifest = write_manifest(candidate_root, manifests_dir / "player_manifest.json", "player-service", PLAYER_ROOT, player_archive, player_entries)
    admin_manifest = write_manifest(candidate_root, manifests_dir / "admin_manifest.json", "admin-checker", ADMIN_ROOT, admin_archive, admin_entries)
    evidence_manifest = write_manifest(candidate_root, manifests_dir / "organizer_evidence_manifest.json", "organizer-evidence", EVIDENCE_ROOT, evidence_archive, evidence_entries)
    checksum_file = build_artifacts.write_checksum_file(
        candidate_root,
        [player_archive, admin_archive, evidence_archive, player_manifest, admin_manifest, evidence_manifest],
        checksums_dir / "SHA256SUMS",
    )
    return {
        "player": artifact_record(candidate_root, player_archive, player_manifest),
        "admin": artifact_record(candidate_root, admin_archive, admin_manifest),
        "organizer_evidence": artifact_record(candidate_root, evidence_archive, evidence_manifest),
        "checksums": rel_to(candidate_root, checksum_file),
    }


def build_evidence_tree(dest: Path) -> dict[str, Any]:
    clean_dir(dest)
    for relative in EVIDENCE_FILES:
        source = ROOT / relative
        if not source.is_file():
            raise FileNotFoundError(f"required organizer evidence file missing: {relative}")
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    files = inventory(dest)
    return {"status": "pass", "files": files, "file_count": len(files)}


def write_manifest(candidate_root: Path, path: Path, artifact_class: str, archive_root: str, archive_path: Path, entries: list[dict[str, Any]]) -> Path:
    manifest = {
        "schema": "sentinel-aml-final-artifact-manifest.v1",
        "artifact": {
            "artifact_class": artifact_class,
            "archive_root": archive_root,
            "name": archive_path.name,
            "path": rel_to(candidate_root, archive_path),
            "sha256": sha256_file(archive_path),
            "size_bytes": archive_path.stat().st_size,
        },
        "build": {
            "deterministic_mtime": FIXED_MTIME,
            "generated_by": "scripts/final_release_validate.py",
        },
        "files": entries,
        "file_count": len(entries),
    }
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def artifact_record(candidate_root: Path, archive: Path, manifest: Path) -> dict[str, Any]:
    return {
        "archive": rel_to(candidate_root, archive),
        "manifest": rel_to(candidate_root, manifest),
        "sha256": sha256_file(archive),
        "size_bytes": archive.stat().st_size,
    }


def extract_validation_archives(candidate_root: Path, validation_root: Path) -> dict[str, Path]:
    player_root = validation_root / "player-extracted"
    admin_root = validation_root / "admin-extracted"
    evidence_root = validation_root / "organizer-extracted"
    safe_extract(candidate_root / "artifacts" / PLAYER_ARCHIVE_NAME, player_root)
    safe_extract(candidate_root / "artifacts" / ADMIN_ARCHIVE_NAME, admin_root)
    safe_extract(candidate_root / "artifacts" / EVIDENCE_ARCHIVE_NAME, evidence_root)
    return {
        "player": player_root / PLAYER_ROOT,
        "admin": admin_root / ADMIN_ROOT,
        "organizer_evidence": evidence_root / EVIDENCE_ROOT,
    }


def run_hygiene_checks(candidate_root: Path, artifacts: dict[str, Any]) -> dict[str, str]:
    player = candidate_root / artifacts["player"]["archive"]
    admin = candidate_root / artifacts["admin"]["archive"]
    evidence = candidate_root / artifacts["organizer_evidence"]["archive"]
    player_result = check_player_bundle_hygiene.validate_player_bundle(player)
    admin_result = check_admin_bundle_hygiene.validate_admin_bundle(admin)
    disclosure_result = disclosure_archive_scan(player)
    evidence_result = validate_evidence_archive(evidence)
    return {
        "player_bundle_hygiene": str(player_result["status"]),
        "admin_checker_hygiene": str(admin_result["status"]),
        "player_disclosure_hygiene": str(disclosure_result["status"]),
        "organizer_evidence_inventory": str(evidence_result["status"]),
    }


def disclosure_archive_scan(player_archive: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sentinel-aml-final-player-scan.") as tmp:
        extracted = Path(tmp)
        safe_extract(player_archive, extracted)
        return check_ctf_disclosure_hygiene.validate_ctf_disclosure_hygiene(extracted / PLAYER_ROOT, None)


def validate_evidence_archive(evidence_archive: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sentinel-aml-final-evidence-scan.") as tmp:
        extracted = Path(tmp)
        safe_extract(evidence_archive, extracted)
        root = extracted / EVIDENCE_ROOT
        missing = [relative for relative in EVIDENCE_FILES if not (root / relative).is_file()]
    return {"status": "pass" if not missing else "fail", "missing": missing}


def run_exact_runtime_validation(extracted: dict[str, Path], *, python: str, docker: str) -> dict[str, Any]:
    player = extracted["player"]
    admin = extracted["admin"]
    evidence = extracted["organizer_evidence"]
    port = free_port()
    base_url = f"http://127.0.0.1:{port}"
    project = f"sentinel-aml-final-{int(time.time())}-{port}"
    env = os.environ.copy()
    env["SENTINEL_AML_CHECKER_SECRET"] = f"final-release-secret-{time.time_ns()}"
    write_player_env(player, port)
    rows: list[dict[str, Any]] = []
    states: list[dict[str, Any]] = []
    try:
        run_required([docker, "--version"], cwd=player, env=env, timeout=20)
        compose(player, docker, project, "config", env=env)
        compose(player, docker, project, "up", "--build", "-d", env=env, timeout=180)
        wait_ready(base_url)
        checker(admin, python, "check", base_url, env=env)
        checker(admin, python, "havoc", base_url, env=env)

        for item in AML_CASES:
            flag = f"SENTINEL{{FINAL_{item.aml_id.replace('-', '_')}_{int(time.time() * 1000)}}}"
            put_result = checker(admin, python, "put", base_url, flag, str(item.place), env=env)
            private_state = put_result.stderr.strip()
            attack_data = json.loads(put_result.stdout)
            assert_public_attack_data_safe(attack_data)
            sploit_result = run_sploit(evidence, python, item, port, attack_data)
            if sploit_result.returncode != 0 or flag not in sploit_result.stdout:
                raise FinalReleaseFailure(f"{item.aml_id} sploit did not recover the checker PUT flag from public attack data")
            checker(admin, python, "get", base_url, private_state, flag, str(item.place), env=env)
            checker(admin, python, "check", base_url, env=env)
            checker(admin, python, "havoc", base_url, env=env)
            rows.append(
                {
                    "aml": item.aml_id,
                    "place": item.place,
                    "status": "pass",
                    "flag_sha256": sha256_text(flag),
                    "public_attack_data_keys": sorted(attack_data),
                    "sploit": item.sploit,
                }
            )
            states.append({"aml": item.aml_id, "place": item.place, "flag": flag, "private_state": private_state})

        compose(player, docker, project, "down", "--remove-orphans", env=env, timeout=90)
        compose(player, docker, project, "up", "-d", env=env, timeout=120)
        wait_ready(base_url)
        for state in states:
            checker(admin, python, "get", base_url, state["private_state"], state["flag"], str(state["place"]), env=env)
        checker(admin, python, "check", base_url, env=env)
        checker(admin, python, "havoc", base_url, env=env)
        return {
            "status": "pass",
            "base_url": base_url,
            "compose_project": project,
            "rows": rows,
            "persistence_restart": "pass",
            "message": "exact extracted player/admin/evidence artifacts passed runtime validation",
        }
    finally:
        compose(player, docker, project, "down", "--remove-orphans", env=env, timeout=90, check=False)


def run_reference_fix_validation(validation_root: Path, *, python: str, go: str) -> dict[str, Any]:
    evidence_root = validation_root / "organizer-extracted" / EVIDENCE_ROOT
    for item in AML_CASES:
        if not (evidence_root / item.fix_patch).is_file():
            return {"status": "fail", "message": f"missing extracted reference fix: {item.fix_patch}"}
    result = check_wave29_regression.validate_wave29_regression(ROOT, python=python, go=go, progress=sys.stderr)
    result["substrate"] = "organizer source with extracted evidence inventory cross-check"
    return result


def write_status(root: Path, summary: dict[str, Any], *, final: bool) -> None:
    status = {
        "artifact_class": "final-release-set",
        "competition_ready": bool(final and summary.get("status") == "pass"),
        "final_package": bool(final and summary.get("status") == "pass"),
        "runtime_validated": bool(final and summary.get("runtime_validation", {}).get("status") == "pass"),
        "fixes_validated": bool(final and summary.get("fix_validation", {}).get("status") == "pass"),
        "promotion_blocker": None if final and summary.get("status") == "pass" else summary.get("blocker", "mandatory final runtime proof has not passed"),
        "summary": SUMMARY_NAME,
        "report": REPORT_NAME,
    }
    root.mkdir(parents=True, exist_ok=True)
    (root / STATUS_NAME).write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_report(root: Path, summary: dict[str, Any], *, verdict: str) -> None:
    artifacts = summary.get("artifacts", {})
    lines = [
        "# Sentinel AML Final Release Validation",
        "",
        f"Verdict: {verdict}",
        f"competition_ready: {str(summary.get('competition_ready', False)).lower()}",
        f"final_package: {str(summary.get('final_package', False)).lower()}",
        "",
        "## Artifacts",
    ]
    for key in ("player", "admin", "organizer_evidence"):
        item = artifacts.get(key, {})
        lines.append(f"- {key}: {item.get('archive', 'not-built')} sha256={item.get('sha256', 'n/a')}")
    lines.extend(["", "## Checks"])
    for check in summary.get("checks", []):
        lines.append(f"- {check.get('name')}: {check.get('status')} {check.get('message', '')}".rstrip())
    if summary.get("blocker"):
        lines.extend(["", "## Blocker", str(summary["blocker"])])
    lines.extend(["", "Raw flags are intentionally omitted; runtime rows record flag hashes only.", ""])
    root.mkdir(parents=True, exist_ok=True)
    (root / REPORT_NAME).write_text("\n".join(lines), encoding="utf-8")


def checker(admin_root: Path, python: str, action: str, base_url: str, *args: str, env: dict[str, str]) -> CommandResult:
    result = run_required([python, str(admin_root / "sentinel_aml" / "checker.py"), action, base_url, *args], cwd=admin_root, env=env, timeout=60, check=False)
    if result.returncode != CHECKER_OK:
        raise FinalReleaseFailure(f"checker {action} failed: exit={result.returncode} stdout={redact(result.stdout)} stderr={redact(result.stderr)}")
    return result


def run_sploit(evidence_root: Path, python: str, item: AMLCase, port: int, attack_data: dict[str, Any]) -> CommandResult:
    return run_required(
        [python, str(evidence_root / item.sploit), "127.0.0.1", str(port), json.dumps(attack_data, sort_keys=True), "--timeout", "8"],
        cwd=evidence_root,
        env=os.environ.copy(),
        timeout=60,
        check=False,
    )


def compose(player: Path, docker: str, project: str, *args: str, env: dict[str, str], timeout: float = 60, check: bool = True) -> CommandResult:
    return run_required(
        [docker, "compose", "-p", project, "--env-file", ".env", "-f", "deploy/compose.yaml", *args],
        cwd=player,
        env=env,
        timeout=timeout,
        check=check,
    )


def run_required(command: list[str], *, cwd: Path, env: dict[str, str], timeout: float, check: bool = True) -> CommandResult:
    started = time.monotonic()
    try:
        completed = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise FinalReleaseFailure(f"command timed out after {timeout:.0f}s: {command_label(command)}") from exc
    except OSError as exc:
        raise FinalReleaseFailure(f"command failed to start: {command_label(command)}: {exc}") from exc
    result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr, time.monotonic() - started)
    if check and result.returncode != 0:
        raise FinalReleaseFailure(
            f"command exited {result.returncode}: {command_label(command)} stdout={redact(result.stdout[-1000:])} stderr={redact(result.stderr[-1000:])}"
        )
    return result


def command_label(command: list[str]) -> str:
    return " ".join(command)


def wait_ready(base_url: str) -> None:
    deadline = time.monotonic() + 90
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base_url + "/readyz", timeout=3) as response:
                body = response.read().decode("utf-8", errors="ignore")
                if response.status == 200 and "ok" in body.lower():
                    return
        except (OSError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(1)
    raise FinalReleaseFailure(f"extracted player service did not become ready: {last_error}")


def write_player_env(player: Path, port: int) -> None:
    (player / ".env").write_text(f"SENTINEL_AML_HTTP_PORT={port}\n", encoding="utf-8")


def assert_public_attack_data_safe(attack_data: dict[str, Any]) -> None:
    serialized = json.dumps(attack_data, sort_keys=True).lower()
    forbidden = ("flag", "private_state", "checker_secret", "password", "session", "token", "confidential_comment")
    leaked = [marker for marker in forbidden if marker in serialized]
    if leaked:
        raise FinalReleaseFailure(f"checker public attack data leaked forbidden markers: {', '.join(leaked)}")


def safe_extract(archive_path: Path, dest: Path) -> None:
    clean_dir(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    with gzip.open(archive_path, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        for member in archive.getmembers():
            target = (dest / member.name).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError as exc:
                raise FinalReleaseFailure(f"unsafe archive member path: {member.name}") from exc
        archive.extractall(dest)


def clean_dir(path: Path) -> None:
    ensure_safe_clean(path)
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def ensure_safe_clean(path: Path) -> None:
    resolved = path.resolve()
    if resolved == ROOT:
        raise ValueError("refusing to clean repository root")
    temp_root = Path(tempfile.gettempdir()).resolve()
    try:
        resolved.relative_to(temp_root)
        return
    except ValueError:
        pass
    try:
        relative = resolved.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"refusing to clean outside repository: {resolved}") from exc
    if not relative.parts or relative.parts[0] not in {"out", "validation", "tmp", "temp"}:
        raise ValueError(f"refusing to clean non-generated repository path: {resolved}")


def ensure_repo_local(path: Path, first_segment: str) -> None:
    try:
        relative = path.resolve().relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path must be inside repository: {path}") from exc
    if not relative.parts or relative.parts[0] != first_segment:
        raise ValueError(f"path must be under {first_segment}/: {path}")


def copy_tree(source: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(source, dest)


def inventory(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)).replace("\\", "/") for path in root.rglob("*") if path.is_file())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def redact(text: str) -> str:
    redacted = text
    redacted = __import__("re").sub(r"(FLAG|CTF|SENTINEL)\{[^}\s]*\}", "[redacted]", redacted, flags=__import__("re").IGNORECASE)
    redacted = __import__("re").sub(r"(?i)(password|token|session|secret|flag)(\s*[=:]\s*)([^\s,;}\]]+)", r"\1\2[redacted]", redacted)
    return redacted


def add_check(summary: dict[str, Any], name: str, status: str, message: str = "") -> None:
    summary.setdefault("checks", []).append({"name": name, "status": status, "message": message})
    if status != "pass":
        raise FinalReleaseFailure(f"{name}: {message or status}")


def aggregate(statuses: Iterable[str]) -> str:
    return "fail" if any(status != "pass" for status in statuses) else "pass"


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def rel_to(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, default=DEFAULT_CANDIDATE_ROOT)
    parser.add_argument("--final-root", type=Path, default=DEFAULT_FINAL_ROOT)
    parser.add_argument("--validation-root", type=Path, default=DEFAULT_VALIDATION_ROOT)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--skip-runtime", action="store_true", help="build candidate artifacts but force a not-ready verdict")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = build_and_validate(
        candidate_root=args.candidate_root,
        final_root=args.final_root,
        validation_root=args.validation_root,
        python=args.python,
        docker=args.docker,
        go=args.go,
        skip_runtime=args.skip_runtime,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
