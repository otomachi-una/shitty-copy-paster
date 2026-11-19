#!/usr/bin/env python3
"""Build source/admin artifacts and run the artifact-first A/D gate."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_admin_organizer_artifact
import build_frontend_static_dist
import build_player_source_artifact
import check_admin_artifact_contents
import check_admin_artifact_hygiene
import check_player_no_frontend_source
import check_player_source_artifact
import check_player_source_hygiene
import check_player_source_runtime
import check_player_static_frontend
import check_semantic_red_herrings
import check_side_view_lexicon


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = ROOT / "out" / "artifacts"
FINAL_ROOT = ROOT / "out" / "final"
FINAL_ARTIFACT_DIR = FINAL_ROOT / "artifacts"
FINAL_VALIDATION_DIR = FINAL_ROOT / "validation"
SUMMARY_OUTPUT = FINAL_VALIDATION_DIR / "player_source_admin_artifact_gate_summary.json"
VALIDATION_ROOT = FINAL_VALIDATION_DIR / "player-source-admin-artifact-gate-work"
PLAYER_ARTIFACT = ARTIFACT_DIR / "sentinel-aml-player-source.tar.gz"
ADMIN_ARTIFACT = ARTIFACT_DIR / "sentinel-aml-admin-organizer.tar.gz"
PLAYER_MANIFEST = ARTIFACT_DIR / "PLAYER_SOURCE_MANIFEST.json"
ADMIN_MANIFEST = ARTIFACT_DIR / "ADMIN_MANIFEST.json"
FINAL_PLAYER_ARTIFACT = FINAL_ARTIFACT_DIR / PLAYER_ARTIFACT.name
FINAL_ADMIN_ARTIFACT = FINAL_ARTIFACT_DIR / ADMIN_ARTIFACT.name
FINAL_PLAYER_MANIFEST = FINAL_ARTIFACT_DIR / PLAYER_MANIFEST.name
FINAL_ADMIN_MANIFEST = FINAL_ARTIFACT_DIR / ADMIN_MANIFEST.name
FINAL_SHA256SUMS = FINAL_ARTIFACT_DIR / "SHA256SUMS"
OUTPUT_FILES = (
    PLAYER_ARTIFACT,
    ADMIN_ARTIFACT,
    PLAYER_MANIFEST,
    ADMIN_MANIFEST,
    ARTIFACT_DIR / "SHA256SUMS",
    ARTIFACT_DIR / "ADMIN_SHA256SUMS",
)
FINAL_OUTPUT_FILES = (
    FINAL_PLAYER_ARTIFACT,
    FINAL_ADMIN_ARTIFACT,
    FINAL_PLAYER_MANIFEST,
    FINAL_ADMIN_MANIFEST,
    FINAL_SHA256SUMS,
)


def run_gate(
    *,
    summary_output: Path = SUMMARY_OUTPUT,
    validation_root: Path = VALIDATION_ROOT,
    python: str = sys.executable,
    go: str = "go",
    docker: str = "docker",
    run_live: bool = True,
) -> dict[str, Any]:
    started = time.monotonic()
    summary: dict[str, Any] = {
        "schema": "sentinel-aml-player-source-admin-final-transfer-gate.v1",
        "status": "fail",
        "artifact_first": True,
        "repo_path_fallback": False,
        "environment": {"python": python, "go": go, "docker": docker},
        "steps": [],
        "summary_output": summary_output.as_posix(),
        "final_outputs": [path.as_posix() for path in FINAL_OUTPUT_FILES],
    }
    try:
        clean_outputs(validation_root)
        summary["steps"].append({"name": "clean-output-and-staging", "status": "pass"})
        frontend = build_frontend_static_dist.build_frontend_static_dist()
        summary["steps"].append(
            {
                "name": "build-frontend-static-dist",
                "status": frontend["status"],
                "sha256": frontend["sha256"],
                "file_count": frontend["file_count"],
            }
        )
        if frontend["status"] != "pass":
            raise RuntimeError("frontend static dist build failed")
        player = build_player_source_artifact.build_player_source_artifact(PLAYER_ARTIFACT)
        summary["steps"].append({"name": "build-player-source-artifact", "status": player["status"], "artifact": player["artifact"], "sha256": player["sha256"]})
        if player["status"] != "pass":
            raise RuntimeError("player source artifact build failed")
        admin = build_admin_organizer_artifact.build_admin_organizer_artifact(ADMIN_ARTIFACT)
        summary["steps"].append({"name": "build-admin-organizer-artifact", "status": admin["status"], "artifact": admin["artifact"], "sha256": admin["sha256"]})
        if admin["status"] != "pass":
            raise RuntimeError("admin organizer artifact build failed")

        validation_steps = run_validation_steps(
            player_artifact=PLAYER_ARTIFACT,
            admin_artifact=ADMIN_ARTIFACT,
            validation_root=validation_root,
            python=python,
            go=go,
            docker=docker,
            run_live=run_live,
        )
        summary["steps"].extend(validation_steps)
        if any(step["status"] == "fail" for step in validation_steps):
            raise RuntimeError("one or more artifact validation steps failed")

        promotion = promote_final_outputs()
        summary["steps"].append({"name": "promote-final-transfer-artifacts", "status": promotion["status"], "outputs": promotion["outputs"]})
        if promotion["status"] != "pass":
            raise RuntimeError("final artifact promotion failed")
        final_check = verify_final_outputs()
        summary["steps"].append({"name": "verify-final-transfer-sha-bindings", "status": final_check["status"], "checks": final_check["checks"]})
        if final_check["status"] != "pass":
            raise RuntimeError("final artifact SHA verification failed")

        summary["promoted_artifacts"] = final_check["artifacts"]
        summary["player_source_artifact_sha256"] = final_check["artifacts"]["player_source"]["sha256"]
        summary["admin_artifact_sha256"] = final_check["artifacts"]["admin"]["sha256"]
        summary["status"] = "pass"
    except Exception as exc:
        summary["status"] = "fail"
        summary["error"] = str(exc)
        summary_output.parent.mkdir(parents=True, exist_ok=True)
        summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finally:
        summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
        summary_output.parent.mkdir(parents=True, exist_ok=True)
        summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def run_validation_steps(
    *,
    player_artifact: Path,
    admin_artifact: Path,
    validation_root: Path,
    python: str,
    go: str,
    docker: str,
    run_live: bool,
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    append_result(steps, "validate-player-source-artifact", check_player_source_artifact.check_manifest(player_artifact))
    append_result(steps, "validate-player-static-frontend", check_player_static_frontend.check_player_static_frontend(player_artifact))
    append_result(steps, "validate-player-no-frontend-source", check_player_no_frontend_source.check_player_no_frontend_source(player_artifact))
    append_result(steps, "validate-player-source-hygiene", check_player_source_hygiene.check_player_source_hygiene(player_artifact))
    append_result(
        steps,
        "validate-side-view-lexicon",
        check_side_view_lexicon_report(
            player_artifact,
            FINAL_VALIDATION_DIR / "side-view-lexicon-final-transfer.json",
        ),
    )
    append_result(
        steps,
        "validate-semantic-red-herrings",
        check_semantic_red_herrings.check_semantic_red_herrings(ROOT),
    )
    append_result(steps, "validate-admin-artifact-contents", check_admin_artifact_contents.check_admin_artifact_contents(admin_artifact, ADMIN_MANIFEST))
    append_result(steps, "validate-admin-artifact-hygiene", check_admin_artifact_hygiene.check_admin_artifact_hygiene(admin_artifact))

    extracted = extract_player_for_build(player_artifact, validation_root / "player-source-extracted")
    steps.append(run_command_step("build-extracted-player-go", [go, "build", "./cmd/aml-api", "./cmd/aml-worker", "./cmd/aml-migrate"], cwd=extracted, env=go_env(validation_root)))
    steps.append(validate_extracted_static_frontend(extracted))
    if run_live:
        runtime = check_player_source_runtime.check_player_source_runtime(player_artifact, docker=docker, run_live=True)
        append_result(steps, "validate-player-source-runtime-smoke", runtime, allow_external_required=True)
    else:
        steps.append({"name": "validate-player-source-runtime-smoke", "status": "external-required", "message": "static-only gate invocation"})

    steps.append(run_command_step("run-checker-scenario-inventory-tests", [python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_checker_scenario_inventory.py"], cwd=ROOT))
    return steps


def append_result(steps: list[dict[str, Any]], name: str, result: dict[str, Any], *, allow_external_required: bool = False) -> None:
    status = str(result.get("status", "fail"))
    step_status = "pass" if allow_external_required and status == "external-required" else status
    steps.append(
        {
            "name": name,
            "status": step_status,
            "reported_status": status,
            "summary": compact_result(result),
        }
    )


def compact_result(result: dict[str, Any]) -> dict[str, Any]:
    compact = {key: value for key, value in result.items() if key not in {"findings", "checks", "phases"}}
    if "findings" in result:
        compact["finding_count"] = len(result.get("findings") or [])
    if "checks" in result:
        checks = result.get("checks") or []
        compact["check_count"] = len(checks)
        compact["failed_checks"] = [check for check in checks if isinstance(check, dict) and check.get("status") == "fail"][:5]
    return compact


def check_side_view_lexicon_report(artifact: Path, report_path: Path) -> dict[str, Any]:
    findings = check_side_view_lexicon.scan_repository()
    if artifact.is_file():
        findings.extend(check_side_view_lexicon.scan_artifact(artifact))
    else:
        findings.append(check_side_view_lexicon.Finding("artifact", str(artifact), 0, "artifact", False, "player source artifact is missing"))
    blocking = [finding for finding in findings if not finding.allowlisted]
    result = {
        "status": "fail" if blocking else "pass",
        "repo_root": str(ROOT),
        "artifact": str(artifact),
        "hit_count": len(findings),
        "blocking_hit_count": len(blocking),
        "allowlisted_hit_count": len(findings) - len(blocking),
        "findings": [finding.__dict__ for finding in findings],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def extract_player_for_build(artifact: Path, destination: Path) -> Path:
    clean_generated_dir(destination)
    with tarfile.open(artifact, "r:gz") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            try:
                target.relative_to(destination.resolve())
            except ValueError as exc:
                raise RuntimeError(f"unsafe player artifact member: {member.name}") from exc
        archive.extractall(destination)
    root = destination / build_player_source_artifact.ARCHIVE_ROOT
    if not root.is_dir():
        raise RuntimeError("player source artifact did not extract to expected archive root")
    return root


def run_command_step(command_name: str, command: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout: int = 180) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {"name": command_name, "status": "fail", "message": f"timeout after {timeout}s", "elapsed_seconds": round(time.monotonic() - started, 3), "command": command}
    except OSError as exc:
        return {"name": command_name, "status": "fail", "message": str(exc), "elapsed_seconds": round(time.monotonic() - started, 3), "command": command}
    output = (completed.stderr or completed.stdout).strip()
    return {
        "name": command_name,
        "status": "pass" if completed.returncode == 0 else "fail",
        "exit_code": completed.returncode,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "command": command,
        "message": output[-2000:],
    }


def validate_extracted_static_frontend(player_root: Path) -> dict[str, Any]:
    index = player_root / "web" / "dist" / "index.html"
    dockerfile = (player_root / "Dockerfile").read_text(encoding="utf-8", errors="ignore")
    source_absent = not (player_root / "frontend").exists()
    static_ok = index.is_file() and (player_root / "web" / "dist" / "runtime-config.js").is_file()
    docker_ok = "COPY web/dist /usr/share/nginx/html" in dockerfile and "npm run build" not in dockerfile and "npm ci" not in dockerfile
    ok = source_absent and static_ok and docker_ok
    return {
        "name": "validate-extracted-static-frontend",
        "status": "pass" if ok else "fail",
        "message": "static UI bundle present and frontend source absent" if ok else "static UI bundle/source exclusion contract failed",
    }


def go_env(validation_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["GOTOOLCHAIN"] = "local"
    env["GOFLAGS"] = "-mod=vendor"
    env["GOTELEMETRY"] = "off"
    env["GOCACHE"] = str((validation_root / "gocache").resolve())
    env["APPDATA"] = str((validation_root / "appdata").resolve())
    Path(env["GOCACHE"]).mkdir(parents=True, exist_ok=True)
    Path(env["APPDATA"]).mkdir(parents=True, exist_ok=True)
    return env


def promote_final_outputs() -> dict[str, Any]:
    clean_generated_dir(FINAL_ROOT)
    FINAL_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PLAYER_ARTIFACT, FINAL_PLAYER_ARTIFACT)
    shutil.copyfile(ADMIN_ARTIFACT, FINAL_ADMIN_ARTIFACT)
    write_promoted_manifest(PLAYER_MANIFEST, FINAL_PLAYER_MANIFEST, FINAL_PLAYER_ARTIFACT)
    write_promoted_manifest(ADMIN_MANIFEST, FINAL_ADMIN_MANIFEST, FINAL_ADMIN_ARTIFACT)
    write_final_checksums()
    return {
        "status": "pass",
        "outputs": [path.as_posix() for path in FINAL_OUTPUT_FILES],
    }


def write_promoted_manifest(source_manifest: Path, final_manifest: Path, final_artifact: Path) -> None:
    data = json.loads(source_manifest.read_text(encoding="utf-8"))
    artifact = data.setdefault("artifact", {})
    artifact["path"] = final_artifact.as_posix()
    artifact["sha256"] = sha256_file(final_artifact)
    artifact["size_bytes"] = final_artifact.stat().st_size
    final_manifest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_final_checksums() -> None:
    lines = [f"{sha256_file(path)}  {path.name}" for path in FINAL_OUTPUT_FILES if path.name != FINAL_SHA256SUMS.name]
    FINAL_SHA256SUMS.write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_final_outputs() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for path in FINAL_OUTPUT_FILES:
        checks.append({"name": f"final-output-present:{path.name}", "status": "pass" if path.is_file() else "fail", "path": path.as_posix()})
    player_sha = sha256_file(FINAL_PLAYER_ARTIFACT) if FINAL_PLAYER_ARTIFACT.is_file() else ""
    admin_sha = sha256_file(FINAL_ADMIN_ARTIFACT) if FINAL_ADMIN_ARTIFACT.is_file() else ""
    checks.extend(
        [
            manifest_sha_check("player-source-manifest-final-sha", FINAL_PLAYER_MANIFEST, FINAL_PLAYER_ARTIFACT, player_sha),
            manifest_sha_check("admin-manifest-final-sha", FINAL_ADMIN_MANIFEST, FINAL_ADMIN_ARTIFACT, admin_sha),
            checksum_entry_check(FINAL_SHA256SUMS, FINAL_PLAYER_ARTIFACT, player_sha),
            checksum_entry_check(FINAL_SHA256SUMS, FINAL_ADMIN_ARTIFACT, admin_sha),
            checksum_entry_check(FINAL_SHA256SUMS, FINAL_PLAYER_MANIFEST, sha256_file(FINAL_PLAYER_MANIFEST) if FINAL_PLAYER_MANIFEST.is_file() else ""),
            checksum_entry_check(FINAL_SHA256SUMS, FINAL_ADMIN_MANIFEST, sha256_file(FINAL_ADMIN_MANIFEST) if FINAL_ADMIN_MANIFEST.is_file() else ""),
        ]
    )
    return {
        "status": "fail" if any(check["status"] == "fail" for check in checks) else "pass",
        "checks": checks,
        "artifacts": {
            "player_source": {"path": FINAL_PLAYER_ARTIFACT.as_posix(), "sha256": player_sha},
            "admin": {"path": FINAL_ADMIN_ARTIFACT.as_posix(), "sha256": admin_sha},
        },
    }


def manifest_sha_check(name: str, manifest: Path, artifact: Path, artifact_sha: str) -> dict[str, Any]:
    if not manifest.is_file():
        return {"name": name, "status": "fail", "message": "manifest missing"}
    data = json.loads(manifest.read_text(encoding="utf-8"))
    meta = data.get("artifact", {})
    ok = meta.get("sha256") == artifact_sha and meta.get("path") == artifact.as_posix()
    return {"name": name, "status": "pass" if ok else "fail", "path": manifest.as_posix(), "message": "" if ok else "manifest artifact binding mismatch"}


def checksum_entry_check(checksums: Path, path: Path, digest: str) -> dict[str, Any]:
    entries = parse_checksums(checksums) if checksums.is_file() else {}
    ok = bool(digest) and entries.get(path.name) == digest
    return {"name": f"checksum-entry:{path.name}", "status": "pass" if ok else "fail", "path": checksums.as_posix(), "message": "" if ok else "checksum entry missing or stale"}


def parse_checksums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            entries[parts[1].replace("\\", "/")] = parts[0]
    return entries


def clean_outputs(validation_root: Path) -> None:
    ensure_out_path(validation_root, "validation root")
    if validation_root.exists():
        shutil.rmtree(validation_root)
    validation_root.mkdir(parents=True, exist_ok=True)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    for path in OUTPUT_FILES:
        if path.exists():
            path.unlink()
    if SUMMARY_OUTPUT.exists():
        SUMMARY_OUTPUT.unlink()


def clean_generated_dir(path: Path) -> None:
    ensure_out_path(path, "generated directory")
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def ensure_out_path(path: Path, label: str) -> None:
    resolved = path.resolve()
    out_root = (ROOT / "out").resolve()
    try:
        resolved.relative_to(out_root)
        return
    except ValueError:
        pass
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return
    raise ValueError(f"refusing to clean {label} outside out/: {path}")


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary-output", type=Path, default=SUMMARY_OUTPUT)
    parser.add_argument("--validation-root", type=Path, default=VALIDATION_ROOT)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--static-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = run_gate(
        summary_output=args.summary_output,
        validation_root=args.validation_root,
        python=args.python,
        go=args.go,
        docker=args.docker,
        run_live=not args.static_only,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
