#!/usr/bin/env python3
"""Validate the Wave 01 Sentinel AML ForcAD config fragment."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


EXPECTED_TASK = {
    "name": "sentinel_aml",
    "checker": "sentinel_aml/checker.py",
    "checker_type": "pfr",
    "checker_timeout": 30,
    "places": 2,
    "puts": 2,
    "gets": 2,
}

FORBIDDEN_REFERENCES = ("debug", "admin", "db", "database", "sploits", "exploit")


def load_task_config(path: Path) -> dict[str, object]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "tasks:":
        raise ValueError("config.yml must start with a top-level tasks list")

    in_task = False
    task: dict[str, object] = {}

    for raw_line in lines[1:]:
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if raw_line.startswith("  ") and not raw_line.startswith("    ") and raw_line != "  - name: sentinel_aml":
            if raw_line.startswith("  - "):
                in_task = False
                continue
            raise ValueError("config.yml tasks must be a list of task objects")
        if raw_line == "  - name: sentinel_aml":
            in_task = True
            task["name"] = "sentinel_aml"
            continue
        if in_task:
            if not raw_line.startswith("    ") or ":" not in raw_line:
                raise ValueError(f"unsupported config line: {raw_line!r}")
            key, value = raw_line.strip().split(":", 1)
            value = value.strip()
            if value.isdigit():
                task[key] = int(value)
            else:
                task[key] = value

    if not task:
        raise ValueError("config.yml must define a task-list item named sentinel_aml")
    return task


def validate_config(path: Path) -> list[str]:
    errors: list[str] = []
    task = load_task_config(path)

    for key, expected_value in EXPECTED_TASK.items():
        actual_value = task.get(key)
        if actual_value != expected_value:
            errors.append(f"sentinel_aml task {key} expected {expected_value!r}, got {actual_value!r}")

    config_text = path.read_text(encoding="utf-8").lower()
    for forbidden in FORBIDDEN_REFERENCES:
        if forbidden in config_text:
            errors.append(f"config.yml must not reference {forbidden!r} paths or behavior")

    return errors


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", nargs="?", type=Path, help="config.yml path to validate")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    args = parse_args(argv)
    config_path = args.config or repo_root / "config.yml"
    errors = validate_config(config_path)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"{config_path} ForcAD shape is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
