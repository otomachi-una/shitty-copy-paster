#!/usr/bin/env python3
"""Compatibility wrapper for the repository-submission archive builder."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_repository_submission_archive


def main(argv: list[str] | None = None) -> int:
    return build_repository_submission_archive.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
