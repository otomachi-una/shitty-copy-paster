#!/usr/bin/env python3
"""Build and sanitize the frontend static bundle for player transfer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
FRONTEND_ROOT = ROOT / "frontend"
DEFAULT_OUTPUT = ROOT / "out" / "frontend-dist"
FORBIDDEN_DIR_NAMES = {
    ".vite",
    "coverage",
    "node_modules",
    "playwright-report",
    "test-results",
}
FORBIDDEN_FILE_NAMES = {
    "package.json",
    "package-lock.json",
    "playwright.config.ts",
    "tsconfig.json",
    "vite.config.ts",
}
FORBIDDEN_SUFFIXES = (".map", ".tsbuildinfo", ".tsx", ".ts")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = build_frontend_static_dist(args.output, run_npm=not args.skip_build)
    except Exception as exc:
        print(json.dumps({"status": "fail", "message": str(exc)}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--skip-build", action="store_true", help="sanitize an existing frontend/dist without running npm")
    return parser.parse_args(argv)


def build_frontend_static_dist(output: Path = DEFAULT_OUTPUT, *, run_npm: bool = True) -> dict[str, object]:
    if run_npm:
        run_frontend_build()
    source = FRONTEND_ROOT / "dist"
    if not source.is_dir():
        raise FileNotFoundError(f"frontend build output is missing: {source.relative_to(ROOT).as_posix()}")
    validate_frontend_dist(source)
    clean_output(output)
    for path in iter_static_files(source):
        relative = path.relative_to(source)
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    validate_frontend_dist(output)
    refs = referenced_assets(output / "index.html")
    missing_refs = [ref for ref in refs if not (output / ref).is_file()]
    if missing_refs:
        raise RuntimeError(f"frontend dist index references missing asset(s): {', '.join(missing_refs)}")
    files = sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file())
    return {
        "status": "pass",
        "output": output.as_posix(),
        "sha256": sha256_tree(output),
        "file_count": len(files),
        "files": files,
    }


def run_frontend_build() -> None:
    env = os.environ.copy()
    cache = ROOT / "out" / "npm-cache"
    cache.mkdir(parents=True, exist_ok=True)
    env["npm_config_cache"] = str(cache)
    env["npm_config_update_notifier"] = "false"
    env["npm_config_fund"] = "false"
    env["npm_config_audit"] = "false"
    npm = npm_executable()
    commands = (
        [npm, "--prefix", "frontend", "ci"],
        [npm, "--prefix", "frontend", "run", "build"],
    )
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"{' '.join(command)} failed: {detail[-2000:]}")


def npm_executable() -> str:
    for candidate in ("npm.cmd", "npm"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise FileNotFoundError("npm executable was not found")


def clean_output(output: Path) -> None:
    resolved = output.resolve()
    out_root = (ROOT / "out").resolve()
    try:
        resolved.relative_to(out_root)
    except ValueError as exc:
        raise ValueError(f"refusing to clean frontend dist outside out/: {output}") from exc
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)


def validate_frontend_dist(root: Path) -> None:
    missing = [name for name in ("index.html", "runtime-config.js") if not (root / name).is_file()]
    if missing:
        raise RuntimeError(f"frontend dist is missing required file(s): {', '.join(missing)}")
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if is_forbidden_dist_path(relative):
            raise RuntimeError(f"frontend dist contains non-runtime file: {relative.as_posix()}")


def is_forbidden_dist_path(relative: Path) -> bool:
    lowered = relative.name.lower()
    return (
        any(part.lower() in FORBIDDEN_DIR_NAMES for part in relative.parts[:-1])
        or lowered in FORBIDDEN_FILE_NAMES
        or any(lowered.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES)
    )


def iter_static_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_file() and not is_forbidden_dist_path(path.relative_to(root)):
            yield path


def referenced_assets(index: Path) -> list[str]:
    text = index.read_text(encoding="utf-8", errors="ignore")
    refs: list[str] = []
    for match in re.finditer(r"""(?:src|href)=["']([^"']+)["']""", text):
        ref = match.group(1)
        if ref.startswith(("http://", "https://", "data:")):
            continue
        refs.append(ref.lstrip("/"))
    return refs


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
