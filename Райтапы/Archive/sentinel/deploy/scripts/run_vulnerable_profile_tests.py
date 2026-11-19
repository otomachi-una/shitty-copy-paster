#!/usr/bin/env python3
"""Run bounded vulnerable-profile Go tests with one out-of-repo cache."""

from __future__ import annotations

import argparse
import contextlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from run_go_release_tests import Runner, run_command


SCENARIOS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("aml1_vulnerable", ("./internal/httpapi",)),
    ("aml2_vulnerable", ("./internal/httpapi",)),
    ("aml3_vulnerable", ("./internal/httpapi", "./internal/graph")),
    ("aml4_vulnerable", ("./internal/httpapi", "./internal/exporting")),
    ("aml5_vulnerable", ("./internal/httpapi", "./internal/networkroom")),
)


def release_env(base_env: dict[str, str], cache_dir: str, appdata_dir: str) -> dict[str, str]:
    env = dict(base_env)
    env["GOTOOLCHAIN"] = "local"
    env["GOFLAGS"] = "-mod=vendor"
    env["GOTELEMETRY"] = "off"
    env["GOCACHE"] = cache_dir
    env["APPDATA"] = appdata_dir
    return env


def run_scenarios(
    repo_root: Path,
    *,
    go: str,
    package_timeout: int,
    scenarios: Sequence[tuple[str, Sequence[str]]] = SCENARIOS,
    runner: Runner = run_command,
    cache_dir: str | None = None,
    appdata_dir: str | None = None,
) -> int:
    outer_timeout = min(package_timeout + 30, 60)
    with contextlib.ExitStack() as stack:
        resolved_cache = cache_dir or stack.enter_context(tempfile.TemporaryDirectory(prefix="sentinel-aml-wave29-gocache."))
        resolved_appdata = appdata_dir or stack.enter_context(tempfile.TemporaryDirectory(prefix="sentinel-aml-wave29-appdata."))
        env = release_env(os.environ, resolved_cache, resolved_appdata)
        print(f"vulnerable profile shared GOCACHE: {resolved_cache}", flush=True)
        print(f"vulnerable profile shared APPDATA: {resolved_appdata}", flush=True)
        for tag, packages in scenarios:
            command = [
                go,
                "test",
                "-p",
                "1",
                "-timeout",
                f"{package_timeout}s",
                "-count=1",
                "-tags",
                tag,
                *packages,
            ]
            started = time.monotonic()
            print(
                f"vulnerable profile test: {tag} {' '.join(packages)}",
                flush=True,
            )
            try:
                completed = runner(
                    command,
                    cwd=repo_root,
                    env=env,
                    timeout=outer_timeout,
                )
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - started
                print(
                    f"vulnerable profile timed out after {elapsed:.3f}s: {tag} outer_timeout={outer_timeout}s",
                    file=sys.stderr,
                    flush=True,
                )
                return 1
            elapsed = time.monotonic() - started
            if completed.stdout:
                print(completed.stdout, end="", flush=True)
            if completed.stderr:
                print(completed.stderr, end="", file=sys.stderr, flush=True)
            print(
                f"vulnerable profile result: {tag} exit={completed.returncode} elapsed={elapsed:.3f}s",
                flush=True,
            )
            if completed.returncode != 0:
                return completed.returncode
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--package-timeout", type=int, default=120)
    parser.add_argument("--cache-dir", default=os.environ.get("SENTINEL_AML_SHARED_GOCACHE"))
    parser.add_argument("--appdata-dir", default=os.environ.get("SENTINEL_AML_SHARED_APPDATA"))
    args = parser.parse_args(argv)
    if args.package_timeout <= 0:
        parser.error("--package-timeout must be positive")
    if bool(args.cache_dir) != bool(args.appdata_dir):
        parser.error("--cache-dir and --appdata-dir must be provided together")
    return run_scenarios(
        Path.cwd(),
        go=args.go,
        package_timeout=args.package_timeout,
        cache_dir=args.cache_dir,
        appdata_dir=args.appdata_dir,
    )


if __name__ == "__main__":
    raise SystemExit(main())
