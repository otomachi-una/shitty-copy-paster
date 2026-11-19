#!/usr/bin/env python3
"""Run byte-level hygiene checks against transfer artifact archives."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import check_admin_bundle_hygiene
import check_player_bundle_hygiene


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_ROOT = ROOT / "out" / "artifacts"
DEFAULT_PLAYER_ARTIFACT = DEFAULT_ARTIFACT_ROOT / "sentinel-aml-player-service.tar.gz"
DEFAULT_ADMIN_ARTIFACT = DEFAULT_ARTIFACT_ROOT / "sentinel-aml-admin-organizer.tar.gz"


def validate_artifact_hygiene(player_artifact: Path, admin_artifact: Path) -> dict[str, Any]:
    player_result = check_player_bundle_hygiene.validate_player_bundle(player_artifact)
    admin_result = check_admin_bundle_hygiene.validate_admin_bundle(admin_artifact)
    checks = [
        {
            "name": "player-artifact-byte-hygiene",
            "path": str(player_artifact),
            "status": player_result["status"],
            "message": summarize_checks(player_result),
        },
        {
            "name": "admin-artifact-byte-hygiene",
            "path": str(admin_artifact),
            "status": admin_result["status"],
            "message": summarize_checks(admin_result),
        },
    ]
    return {
        "status": "fail" if any(check["status"] == "fail" for check in checks) else "pass",
        "checks": checks,
        "details": {
            "player": player_result,
            "admin": admin_result,
        },
    }


def summarize_checks(result: dict[str, Any]) -> str:
    failing = [check for check in result.get("checks", []) if check.get("status") == "fail"]
    if not failing:
        return "artifact hygiene passed"
    return "; ".join(str(check.get("message", "")) for check in failing if check.get("message"))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--player-artifact", type=Path, default=DEFAULT_PLAYER_ARTIFACT)
    parser.add_argument("--admin-artifact", type=Path, default=DEFAULT_ADMIN_ARTIFACT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = validate_artifact_hygiene(args.player_artifact, args.admin_artifact)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
