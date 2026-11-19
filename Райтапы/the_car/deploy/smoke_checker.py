#!/usr/bin/env python3
"""Run inside the ForcAD worker; print verdicts without private receipts."""

import argparse
import json
import math
import os
from pathlib import Path
import secrets
import subprocess


def positive_timeout(value):
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("timeout must be a positive number") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be a positive finite number")
    return timeout


def checker_path(value):
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("checker path must be absolute inside the worker")
    if not path.is_file():
        raise argparse.ArgumentTypeError("checker path must point to an existing file")
    if not os.access(path, os.X_OK):
        raise argparse.ArgumentTypeError("checker file must be executable")
    return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="team host, exactly as configured in ForcAD and checker keys")
    parser.add_argument("--checker", required=True, type=checker_path,
                        help="absolute path to the executable checker inside the worker")
    parser.add_argument("--timeout", type=positive_timeout, default=25,
                        help="timeout in seconds for each checker invocation (default: 25)")
    options = parser.parse_args()
    if not options.host or any(char.isspace() or char == "\0" for char in options.host):
        parser.error("host must be a nonempty IP address or hostname without whitespace")

    def invoke(action, *args):
        label = action + ("-" + args[-1] if args else "")
        try:
            result = subprocess.run(
                [options.checker, action, options.host, *args],
                capture_output=True, text=True, timeout=options.timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SystemExit(f"{label}: {type(exc).__name__}") from None
        print(f"{label}: {result.returncode}", flush=True)
        if result.returncode != 101:
            raise SystemExit(f"{label}: FAILED; check checker configuration and connectivity")
        return result

    invoke("check")
    for place in range(1, 7):
        slot = str(place)
        flag = "CARHACK_SELFTEST_" + secrets.token_hex(12)
        result = invoke("put", "manual", flag, slot)
        receipt = result.stderr.strip()
        try:
            assert isinstance(json.loads(receipt), dict)
        except (ValueError, AssertionError):
            raise SystemExit(f"put-{slot}: invalid private receipt") from None
        invoke("get", receipt, flag, slot)
    invoke("check")
    print("ALL_OK")


if __name__ == "__main__":
    main()
