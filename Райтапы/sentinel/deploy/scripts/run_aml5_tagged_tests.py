#!/usr/bin/env python3
"""Run AML-5 tagged Go tests package-by-package for deterministic gate closure."""

from __future__ import annotations

import argparse
import subprocess
import sys


TAG = "aml5_vulnerable"
DEFAULT_GO_TEST_TIMEOUT = "60s"
DEFAULT_PROCESS_TIMEOUT_SECONDS = 90


def main() -> int:
    args = parse_args()
    packages = list_packages()
    if not packages:
        print("go list returned no packages", file=sys.stderr)
        return 1

    print(f"aml5 tagged package count: {len(packages)}")
    for package in packages:
        command = [
            "go",
            "test",
            "-tags",
            TAG,
            "-count=1",
            "-timeout",
            args.go_test_timeout,
            package,
        ]
        print("+ " + " ".join(command), flush=True)
        result = run_package(command, args.process_timeout_seconds)
        if result != 0:
            return result
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--go-test-timeout",
        default=DEFAULT_GO_TEST_TIMEOUT,
        help="timeout passed to each go test package run",
    )
    parser.add_argument(
        "--process-timeout-seconds",
        default=DEFAULT_PROCESS_TIMEOUT_SECONDS,
        type=int,
        help="outer subprocess timeout for each package run",
    )
    return parser.parse_args()


def list_packages() -> list[str]:
    command = ["go", "list", "-tags", TAG, "./..."]
    print("+ " + " ".join(command), flush=True)
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def run_package(command: list[str], timeout_seconds: int) -> int:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        print(f"package command timed out after {timeout_seconds}s: {' '.join(command)}", file=sys.stderr)
        if exc.stdout:
            print(exc.stdout, end="")
        if exc.stderr:
            print(exc.stderr, end="", file=sys.stderr)
        return 124

    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        print(f"package command failed with exit {result.returncode}: {' '.join(command)}", file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
