#!/usr/bin/env python3
"""Validate the complete player source artifact contract."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


manifest_checker = load_module("check_artifact_manifests", SCRIPT_DIR / "check_artifact_manifests.py")
hygiene_checker = load_module("check_player_source_hygiene", SCRIPT_DIR / "check_player_source_hygiene.py")
static_frontend_checker = load_module("check_player_static_frontend", SCRIPT_DIR / "check_player_static_frontend.py")
no_frontend_source_checker = load_module("check_player_no_frontend_source", SCRIPT_DIR / "check_player_no_frontend_source.py")
promoted_manifest_checker = load_module("check_player_source_manifest", SCRIPT_DIR / "check_player_source_manifest.py")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args(argv)
    manifest = check_manifest(args.artifact)
    hygiene = hygiene_checker.check_player_source_hygiene(args.artifact)
    static_frontend = static_frontend_checker.check_player_static_frontend(args.artifact)
    no_frontend_source = no_frontend_source_checker.check_player_no_frontend_source(args.artifact)
    checks = [
        *manifest["checks"],
        *hygiene["checks"],
        {
            "name": "player-static-frontend",
            "status": static_frontend["status"],
            "message": "" if static_frontend["status"] == "pass" else f"findings={len(static_frontend['findings'])}",
        },
        {
            "name": "player-no-frontend-source",
            "status": no_frontend_source["status"],
            "message": "" if no_frontend_source["status"] == "pass" else f"findings={len(no_frontend_source['findings'])}",
        },
    ]
    status = "fail" if any(check["status"] == "fail" for check in checks) else "pass"
    result = {
        "status": status,
        "artifact": args.artifact.as_posix(),
        "file_count": hygiene.get("file_count"),
        "checks": checks,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "pass" else 1


def check_manifest(artifact: Path) -> dict[str, object]:
    if (artifact.parent / manifest_checker.MANIFEST_NAME).is_file():
        return manifest_checker.check_manifest(artifact)
    output_root = artifact.parent.parent if artifact.parent.name == "artifacts" else artifact.parent
    promoted = promoted_manifest_checker.check_player_source_manifest(output_root)
    return {
        "status": promoted["status"],
        "file_count": None,
        "checks": [
            {
                "name": "player-source-manifest",
                "status": promoted["status"],
                "message": "; ".join(finding["message"] for finding in promoted["findings"]),
            }
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())
