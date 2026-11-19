#!/usr/bin/env python3
"""Validate Sentinel AML artifact-first build mechanics."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT_PATH = ROOT / "scripts" / "build_artifacts.py"
spec = importlib.util.spec_from_file_location("build_artifacts", BUILD_SCRIPT_PATH)
build_artifacts = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = build_artifacts
spec.loader.exec_module(build_artifacts)


def make_target_block(makefile: str, target: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target)}:\s*(?:.*\n)?", makefile)
    if match is None:
        return ""
    start = match.start()
    next_target = re.search(r"(?m)^[A-Za-z0-9_-]+:", makefile[match.end() :])
    end = match.end() + next_target.start() if next_target else len(makefile)
    return makefile[start:end]


class ArtifactBuildMechanicsTest(unittest.TestCase):
    def test_current_branch_static_artifact_target_and_preserved_evidence(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertRegex(makefile, r"(?m)^artifacts:")
        self.assertRegex(makefile, r"(?m)^artifact-gate:")
        self.assertIn("scripts/build_artifacts.py", makefile)
        self.assertIn("scripts/check_artifacts.py", makefile)
        artifact_target = make_target_block(makefile, "artifact-gate")
        self.assertIn("npm --prefix frontend run security:scan:source", artifact_target)
        self.assertIn("npm --prefix frontend run security:scan:dist", artifact_target)

        admin_files = {path.as_posix() for path in build_artifacts.iter_admin_organizer_files(ROOT)}
        for required in build_artifacts.ADMIN_REQUIRED_FILES:
            self.assertIn(required, admin_files)
        self.assertIn("tests/test_checker_check_workflow.py", admin_files)
        self.assertIn("tests/test_checker_put_workflow.py", admin_files)
        self.assertIn("docs/wave_reports/wave_32_sploit_fix_matrix.md", admin_files)

    def test_clean_output_dirs_remove_stale_generated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            stale = output_root / "artifacts" / "stale.txt"
            stale.parent.mkdir(parents=True)
            stale.write_text("stale\n", encoding="utf-8")

            build_artifacts.clean_output_dirs(output_root / "artifacts", output_root / "manifests", output_root / "checksums")

            self.assertFalse(stale.exists())
            self.assertTrue((output_root / "artifacts").is_dir())
            self.assertTrue((output_root / "manifests").is_dir())
            self.assertTrue((output_root / "checksums").is_dir())

    def test_manifests_match_archive_inventory_and_checksums_match_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            build_fixture_outputs(output_root)

            validation = build_artifacts.validate_outputs(output_root)

        self.assertEqual(validation["status"], "pass", validation["checks"])

    def test_player_source_is_primary_and_binary_is_non_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            build_fixture_outputs(output_root)

            source_manifest = json.loads((output_root / "manifests" / build_artifacts.PLAYER_SOURCE_MANIFEST_NAME).read_text(encoding="utf-8"))
            binary_manifest = json.loads((output_root / "manifests" / build_artifacts.PLAYER_BINARY_MANIFEST_NAME).read_text(encoding="utf-8"))
            admin_manifest = json.loads((output_root / "manifests" / build_artifacts.ADMIN_MANIFEST_NAME).read_text(encoding="utf-8"))

        self.assertEqual(source_manifest["artifact"]["name"], build_artifacts.PLAYER_SOURCE_ARTIFACT_NAME)
        self.assertEqual(source_manifest["artifact"]["artifact_class"], "player-source")
        self.assertIs(source_manifest["artifact"]["primary"], True)
        self.assertIs(source_manifest["artifact"]["player_facing"], True)
        self.assertIs(source_manifest["artifact_contract"]["binary_only_sufficient_for_classic_ad"], False)
        self.assertIs(binary_manifest["artifact"]["primary"], False)
        self.assertEqual(binary_manifest["artifact"]["artifact_class"], "player-binary")
        self.assertIs(admin_manifest["artifact"]["player_facing"], False)

    def test_player_binary_manifest_lists_only_runtime_ui_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            build_fixture_outputs(output_root)

            manifest = json.loads((output_root / "manifests" / build_artifacts.PLAYER_BINARY_MANIFEST_NAME).read_text(encoding="utf-8"))

        ui_files = sorted(entry["path"] for entry in manifest["files"] if "/ui/" in entry["path"])
        self.assertIn("sentinel-aml-player-service/ui/index.html", ui_files)
        self.assertIn("sentinel-aml-player-service/ui/runtime-config.js", ui_files)
        self.assertIn("sentinel-aml-player-service/ui/assets/app.js", ui_files)
        forbidden_fragments = (
            ".map",
            ".tsbuildinfo",
            "/node_modules/",
            "/src/",
            "/tests/",
            "/e2e/",
            "/playwright-report/",
            "/test-results/",
            "/package.json",
            "/package-lock.json",
            "/playwright.config.ts",
        )
        for path in ui_files:
            self.assertFalse(any(fragment in path for fragment in forbidden_fragments), path)
        components = {component["key"]: component for component in manifest["delivered_components"]}
        self.assertEqual(components["participant-ui"]["file_count"], len(ui_files))
        self.assertIs(components["participant-ui"]["included"], True)

    def test_distribution_docs_do_not_promote_binary_only_or_full_repo_zip(self):
        docs = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                ROOT / "docs" / "player_source_admin_packaging_requirements.md",
                ROOT / "docs" / "decisions" / "ADR-0003-source-based-player-distribution.md",
                ROOT / "docs" / "source_of_truth_map.md",
                ROOT / "docs" / "13_roadmap.md",
            )
            if path.exists()
        ).lower()

        self.assertIn("sentinel-aml-player-source.tar.gz", docs)
        self.assertIn("sentinel-aml-admin-organizer.tar.gz", docs)
        self.assertIn("binary-only is not sufficient", docs)
        self.assertIn("full repository zip is never a player artifact", docs)
        forbidden = (
            "binary-only is the primary player distribution",
            "binary only is the primary player distribution",
            "full repository zip is a player artifact",
            "full repository archive is a player artifact",
        )
        for phrase in forbidden:
            self.assertNotIn(phrase, docs)

    def test_player_source_artifact_excludes_organizer_material_and_defect_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            build_fixture_outputs(output_root)

            validation = build_artifacts.validate_outputs(output_root)
            archive_files = set(build_artifacts.archive_inventory(output_root / "artifacts" / build_artifacts.PLAYER_SOURCE_ARTIFACT_NAME))

        self.assertEqual(validation["status"], "pass", validation["checks"])
        self.assertIn("sentinel-aml-player-source/cmd/aml-api/main.go", archive_files)
        self.assertIn("sentinel-aml-player-source/internal/service/service.go", archive_files)
        self.assertIn("sentinel-aml-player-source/PACKAGE_MANIFEST.json", archive_files)
        forbidden_prefixes = (
            "sentinel-aml-player-source/checkers/",
            "sentinel-aml-player-source/sploits/",
            "sentinel-aml-player-source/fixes/",
            "sentinel-aml-player-source/docs/",
            "sentinel-aml-player-source/tests/",
        )
        for path in archive_files:
            self.assertFalse(path.startswith(forbidden_prefixes), path)

    def test_rerun_overwrites_stale_generated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            build_fixture_outputs(output_root, player_text="first\n")
            player_archive = output_root / "artifacts" / build_artifacts.PLAYER_SOURCE_ARTIFACT_NAME
            first_digest = build_artifacts.sha256_file(player_archive)
            stale = output_root / "artifacts" / "stale.generated"
            stale.write_text("must be cleaned\n", encoding="utf-8")

            build_fixture_outputs(output_root, player_text="second\n")
            second_digest = build_artifacts.sha256_file(player_archive)

            self.assertFalse(stale.exists())
            self.assertNotEqual(first_digest, second_digest)
            self.assertEqual(build_artifacts.validate_outputs(output_root)["status"], "pass")

    def test_verify_fails_if_required_artifact_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            build_fixture_outputs(output_root)
            (output_root / "artifacts" / build_artifacts.ADMIN_ARTIFACT_NAME).unlink()

            validation = build_artifacts.validate_outputs(output_root)

        self.assertEqual(validation["status"], "fail")
        self.assertIn("artifacts/sentinel-aml-admin-organizer.tar.gz", validation["checks"][0]["message"])

    def test_verify_fails_if_required_player_ui_component_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            build_fixture_outputs(output_root, include_ui=False)

            validation = build_artifacts.validate_outputs(output_root)

        self.assertEqual(validation["status"], "fail")
        component_check = next(check for check in validation["checks"] if check["name"] == "player-component-contract")
        self.assertEqual(component_check["status"], "fail")
        self.assertIn("ui/index.html", component_check["message"])

    def test_verify_only_cli_returns_failure_for_missing_required_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            build_fixture_outputs(output_root)
            (output_root / "artifacts" / build_artifacts.PLAYER_SOURCE_ARTIFACT_NAME).unlink()

            completed = subprocess.run(
                [sys.executable, "-B", str(BUILD_SCRIPT_PATH), "--output-root", str(output_root), "--verify-only"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 1)
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "fail")


def build_fixture_outputs(output_root: Path, *, player_text: str = "player\n", include_ui: bool = True) -> None:
    artifacts_dir = output_root / "artifacts"
    manifests_dir = output_root / "manifests"
    checksums_dir = output_root / "checksums"
    build_artifacts.clean_output_dirs(artifacts_dir, manifests_dir, checksums_dir)

    fixture_root = output_root.parent / "fixture-input"
    if fixture_root.exists():
        shutil.rmtree(fixture_root)
    player_source_tree = fixture_root / "player-source"
    player_tree = fixture_root / "player-binary"
    admin_tree = fixture_root / "admin"
    (player_source_tree / "cmd" / "aml-api").mkdir(parents=True)
    (player_source_tree / "cmd" / "aml-migrate").mkdir(parents=True)
    (player_source_tree / "cmd" / "aml-worker").mkdir(parents=True)
    (player_source_tree / "deploy").mkdir(parents=True)
    (player_source_tree / "internal" / "service").mkdir(parents=True)
    (player_source_tree / "scripts" / "migrate").mkdir(parents=True)
    (player_source_tree / "migrations").mkdir(parents=True)
    (player_source_tree / "web" / "dist").mkdir(parents=True)
    (player_tree / "bin").mkdir(parents=True)
    if include_ui:
        (player_tree / "ui" / "assets").mkdir(parents=True)
    (admin_tree / "checkers" / "sentinel_aml").mkdir(parents=True)
    (player_source_tree / "go.mod").write_text("module sentinel.test\n\ngo 1.22\n", encoding="utf-8")
    (player_source_tree / "go.sum").write_text("", encoding="utf-8")
    (player_source_tree / "cmd" / "aml-api" / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    (player_source_tree / "cmd" / "aml-migrate" / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    (player_source_tree / "cmd" / "aml-worker" / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    (player_source_tree / "internal" / "service" / "service.go").write_text("package service\n\nfunc Ready() bool { return true }\n", encoding="utf-8")
    (player_source_tree / "scripts" / "migrate" / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    (player_source_tree / "migrations" / "000001_create_users_sessions.sql").write_text("select 1;\n", encoding="utf-8")
    build_artifacts.write_player_source_docs(player_source_tree, None)
    (player_source_tree / "README.md").write_text(player_text, encoding="utf-8")
    (player_source_tree / "TROUBLESHOOTING.md").write_text("Run `make logs` to inspect local runtime logs.\n", encoding="utf-8")
    (player_source_tree / "Makefile").write_text("up:\n\ndown:\n\nlogs:\n\nrebuild:\n\nsmoke:\n", encoding="utf-8")
    (player_source_tree / "Dockerfile").write_text(
        "FROM golang:1.22-alpine AS go-build\n"
        "RUN GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go build -o /out/aml-api ./cmd/aml-api\n"
        "RUN GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go build -o /out/aml-worker ./cmd/aml-worker\n"
        "RUN GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go build -o /out/aml-migrate ./cmd/aml-migrate\n",
        encoding="utf-8",
    )
    (player_source_tree / "docker-compose.yml").write_text("services:\n  postgres:\n    image: postgres:16-alpine\n", encoding="utf-8")
    (player_source_tree / "deploy" / "player.env.example").write_text("SENTINEL_AML_API_PORT=8080\n", encoding="utf-8")
    (player_source_tree / "web" / "dist" / "index.html").write_text("<!doctype html><title>Sentinel AML</title>\n", encoding="utf-8")
    (player_source_tree / "web" / "dist" / "runtime-config.js").write_text("window.__SENTINEL_AML_CONFIG__ = {};\n", encoding="utf-8")
    (player_tree / "README.md").write_text(player_text, encoding="utf-8")
    (player_tree / "bin" / "aml-api").write_text("binary-placeholder\n", encoding="utf-8")
    (player_tree / "bin" / "aml-worker").write_text("binary-placeholder\n", encoding="utf-8")
    (player_tree / "bin" / "aml-migrate").write_text("binary-placeholder\n", encoding="utf-8")
    if include_ui:
        (player_tree / "ui" / "index.html").write_text("<!doctype html><div id=\"root\"></div>\n", encoding="utf-8")
        (player_tree / "ui" / "runtime-config.js").write_text("window.__SENTINEL_AML_CONFIG__ = { apiBaseUrl: '' };\n", encoding="utf-8")
        (player_tree / "ui" / "assets" / "app.js").write_text("console.log('sentinel aml');\n", encoding="utf-8")
    (player_tree / "PACKAGING_STATUS.json").write_text(
        json.dumps(
            {
                "artifact_class": "player-service",
                "artifact_contract": "player-service-with-ui.v1",
                "delivery_mode": "binary-image",
                "participant_ui": {"included": include_ui, "required": True, "delivery_path": "ui/"},
                "delivered_components": [
                    {"key": "backend-runtime", "included": True, "required": True, "delivery_path": "bin/"},
                    {"key": "participant-ui", "included": include_ui, "required": True, "delivery_path": "ui/"},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (admin_tree / "checkers" / "sentinel_aml" / "checker.py").write_text("checker\n", encoding="utf-8")
    (admin_tree / "fixes.txt").write_text("fix evidence\n", encoding="utf-8")

    player_source_archive = artifacts_dir / build_artifacts.PLAYER_SOURCE_ARTIFACT_NAME
    player_binary_archive = artifacts_dir / build_artifacts.PLAYER_BINARY_ARTIFACT_NAME
    player_archive = artifacts_dir / build_artifacts.PLAYER_LEGACY_BINARY_ARTIFACT_NAME
    admin_archive = artifacts_dir / build_artifacts.ADMIN_ARTIFACT_NAME
    player_source_files = [
        Path("go.mod"),
        Path("go.sum"),
        Path("cmd/aml-api/main.go"),
        Path("cmd/aml-migrate/main.go"),
        Path("cmd/aml-worker/main.go"),
        Path("internal/service/service.go"),
        Path("scripts/migrate/main.go"),
        Path("migrations/000001_create_users_sessions.sql"),
        Path("README.md"),
        Path("TROUBLESHOOTING.md"),
        Path("Makefile"),
        Path("Dockerfile"),
        Path("docker-compose.yml"),
        Path("deploy/player.env.example"),
        Path("web/dist/index.html"),
        Path("web/dist/runtime-config.js"),
        Path("PACKAGE_MANIFEST.json"),
    ]
    player_files = [
        Path("README.md"),
        Path("PACKAGING_STATUS.json"),
        Path("bin/aml-api"),
        Path("bin/aml-worker"),
        Path("bin/aml-migrate"),
    ]
    if include_ui:
        player_files.extend([Path("ui/index.html"), Path("ui/runtime-config.js"), Path("ui/assets/app.js")])
    player_source_entries = build_artifacts.write_archive(
        player_source_tree,
        player_source_files,
        player_source_archive,
        build_artifacts.PLAYER_SOURCE_SPEC.archive_root,
    )
    player_binary_entries = build_artifacts.write_archive(
        player_tree,
        player_files,
        player_binary_archive,
        build_artifacts.PLAYER_BINARY_SPEC.archive_root,
    )
    player_entries = build_artifacts.write_archive(player_tree, player_files, player_archive, build_artifacts.PLAYER_SPEC.archive_root)
    admin_entries = build_artifacts.write_archive(
        admin_tree,
        [Path("checkers/sentinel_aml/checker.py"), Path("fixes.txt")],
        admin_archive,
        build_artifacts.ADMIN_SPEC.archive_root,
    )
    player_source_manifest = build_artifacts.write_manifest(
        output_root,
        build_artifacts.PLAYER_SOURCE_SPEC,
        player_source_archive,
        manifests_dir / build_artifacts.PLAYER_SOURCE_SPEC.manifest_name,
        player_source_entries,
    )
    player_binary_manifest = build_artifacts.write_manifest(
        output_root,
        build_artifacts.PLAYER_BINARY_SPEC,
        player_binary_archive,
        manifests_dir / build_artifacts.PLAYER_BINARY_SPEC.manifest_name,
        player_binary_entries,
    )
    player_manifest = build_artifacts.write_manifest(
        output_root,
        build_artifacts.PLAYER_SPEC,
        player_archive,
        manifests_dir / build_artifacts.PLAYER_SPEC.manifest_name,
        player_entries,
    )
    admin_manifest = build_artifacts.write_manifest(
        output_root,
        build_artifacts.ADMIN_SPEC,
        admin_archive,
        manifests_dir / build_artifacts.ADMIN_SPEC.manifest_name,
        admin_entries,
    )
    build_artifacts.write_checksum_file(
        output_root,
        [
            player_source_archive,
            player_binary_archive,
            player_archive,
            admin_archive,
            player_source_manifest,
            player_binary_manifest,
            player_manifest,
            admin_manifest,
        ],
        checksums_dir / build_artifacts.CHECKSUM_FILE_NAME,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="run the artifact mechanics tests")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not args.run:
        result = {
            "status": "pass",
            "checks": [
                {
                    "name": "artifact-check-script-present",
                    "path": "scripts/check_artifacts.py",
                    "status": "pass",
                    "message": "use --run for deterministic artifact mechanics tests",
                }
            ],
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ArtifactBuildMechanicsTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
