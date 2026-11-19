#!/usr/bin/env python3
"""Run exact player source artifact runtime validation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import check_player_source_runtime


def check_exact_artifact_runtime(
    artifact: Path,
    *,
    docker: str = "docker",
    run_live: bool = True,
) -> dict[str, Any]:
    if artifact.is_dir():
        return {
            "schema": "sentinel-aml-exact-artifact-runtime.v1",
            "status": "fail",
            "artifact": artifact.as_posix(),
            "checks": [
                {
                    "name": "artifact-is-archive",
                    "status": "fail",
                    "message": "player input must be the transfer tar.gz, not an extracted or repository directory",
                }
            ],
        }
    result = check_player_source_runtime.check_player_source_runtime(artifact, docker=docker, run_live=run_live)
    result["schema"] = "sentinel-aml-exact-artifact-runtime.v1"
    result["artifact_first"] = True
    result["repo_path_fallback"] = False
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--docker", default=os.environ.get("DOCKER", "docker"))
    parser.add_argument("--json-report", type=Path)
    parser.add_argument("--static-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = check_exact_artifact_runtime(args.artifact, docker=args.docker, run_live=not args.static_only)
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
