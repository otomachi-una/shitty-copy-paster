#!/usr/bin/env python3
"""Build a clean repository-submission archive.

This package is an internal repository handoff. It is separate from the
player-source and admin-organizer transfer artifacts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import check_repository_submission_hygiene


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "repo_root",
        nargs="?",
        type=Path,
        default=Path.cwd(),
        help="repository root to package",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=check_repository_submission_hygiene.DEFAULT_REPOSITORY_SUBMISSION_ARCHIVE,
        help="output zip path",
    )
    args = parser.parse_args(argv)

    result = check_repository_submission_hygiene.create_repository_submission_archive(args.repo_root, args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
