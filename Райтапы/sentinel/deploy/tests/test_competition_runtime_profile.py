import importlib.util
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

GUARD_PATH = ROOT / "scripts" / "check_competition_runtime_profile.py"
guard_spec = importlib.util.spec_from_file_location("check_competition_runtime_profile", GUARD_PATH)
competition_guard = importlib.util.module_from_spec(guard_spec)
assert guard_spec.loader is not None
guard_spec.loader.exec_module(competition_guard)


class CompetitionRuntimeProfileTest(unittest.TestCase):
    def test_current_branch_default_binary_mode_has_no_static_failures(self):
        result = competition_guard.validate_competition_runtime_profile(ROOT)
        failures = [check for check in result["checks"] if check["status"] == "fail"]

        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["mode"], "binary")

    def test_makefile_competition_tags_are_complete_and_used_for_internal_runtime_build(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        for tag in competition_guard.REQUIRED_COMPETITION_TAGS:
            self.assertIn(tag, makefile)
        for legacy_tag in competition_guard.LEGACY_COMPATIBILITY_TAGS:
            self.assertNotIn(f"COMPETITION_TAGS = {legacy_tag}", makefile)
        self.assertIn('$(GO_RELEASE_ENV) $(GO) build -tags "$(COMPETITION_TAGS)" $(COMPETITION_RUNTIME_TARGETS)', makefile)
        self.assertIn("./cmd/aml-api ./cmd/aml-worker ./scripts/migrate", makefile)

    def test_binary_player_artifact_with_artifact_local_runtime_proof_policy_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = make_player_artifact(
                root / "player.tar.gz",
                {
                    "PACKAGING_STATUS.json": '{"delivery_mode":"binary-image"}\n',
                    "bin/aml-api": "binary\n",
                    "bin/aml-worker": "binary\n",
                    "bin/aml-migrate": "binary\n",
                    "Dockerfile": "FROM alpine:3.20\n",
                },
            )
            manifest = write_manifest(
                root / "player_manifest.json",
                archive_root="sentinel-aml-player-service",
                files=("PACKAGING_STATUS.json", "bin/aml-api", "bin/aml-worker", "bin/aml-migrate", "Dockerfile"),
                runtime_profile=binary_runtime_profile(),
            )

            check = competition_guard.check_binary_player_artifact_strategy(root, manifest, artifact)

        self.assertEqual(check["status"], "pass", check["message"])

    def test_missing_runtime_proof_policy_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = make_player_artifact(
                root / "player.tar.gz",
                {
                    "PACKAGING_STATUS.json": '{"delivery_mode":"binary-image"}\n',
                    "bin/aml-api": "binary\n",
                    "bin/aml-worker": "binary\n",
                    "bin/aml-migrate": "binary\n",
                },
            )
            profile = binary_runtime_profile()
            profile["runtime_evidence"] = []
            profile.pop("artifact_local_runtime_proof", None)
            manifest = write_manifest(
                root / "player_manifest.json",
                archive_root="sentinel-aml-player-service",
                files=("PACKAGING_STATUS.json", "bin/aml-api", "bin/aml-worker", "bin/aml-migrate"),
                runtime_profile=profile,
            )

            check = competition_guard.check_binary_player_artifact_strategy(root, manifest, artifact)

        self.assertEqual(check["status"], "fail")
        self.assertIn("exact_artifact_runtime_evidence_count=0", check["message"])
        self.assertIn("artifact_local_runtime_proof_policy=False", check["message"])

    def test_stale_secure_default_source_dockerfile_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = make_player_artifact(
                root / "source.tar.gz",
                {
                    "PACKAGING_STATUS.json": '{"delivery_mode":"source"}\n',
                    "go.mod": "module example\n",
                    "go.sum": "",
                    "Dockerfile": "FROM golang:1.22\nRUN go build ./cmd/aml-api\n",
                    "deploy/compose.yaml": "services:\n  api:\n    build: ..\n",
                    "cmd/aml-api/main.go": "package main\n",
                },
            )
            manifest = write_manifest(
                root / "player_manifest.json",
                archive_root="sentinel-aml-player-service",
                files=("PACKAGING_STATUS.json", "go.mod", "go.sum", "Dockerfile", "deploy/compose.yaml", "cmd/aml-api/main.go"),
                runtime_profile=source_runtime_profile(),
            )

            check = competition_guard.check_source_player_artifact_strategy(root, manifest, artifact)

        self.assertEqual(check["status"], "fail")
        self.assertIn("dockerfile_uses_tags=False", check["message"])

    def test_source_artifact_containing_dual_policy_files_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = make_player_artifact(
                root / "source.tar.gz",
                {
                    "PACKAGING_STATUS.json": '{"delivery_mode":"source"}\n',
                    "go.mod": "module example\n",
                    "go.sum": "",
                    "Dockerfile": 'FROM golang:1.22\nRUN go build -tags "${COMPETITION_TAGS}" ./cmd/aml-api\n',
                    "deploy/compose.yaml": "services:\n  api:\n    build: ..\n",
                    "internal/httpapi/audit_default.go": "package httpapi\n",
                    "internal/httpapi/audit_detail.go": "package httpapi\n",
                },
            )
            manifest = write_manifest(
                root / "player_manifest.json",
                archive_root="sentinel-aml-player-service",
                files=(
                    "PACKAGING_STATUS.json",
                    "go.mod",
                    "go.sum",
                    "Dockerfile",
                    "deploy/compose.yaml",
                    "internal/httpapi/audit_default.go",
                    "internal/httpapi/audit_detail.go",
                ),
                runtime_profile=source_runtime_profile(),
            )

            check = competition_guard.check_source_player_artifact_strategy(root, manifest, artifact)

        self.assertEqual(check["status"], "fail")
        self.assertIn("audit_default.go", check["message"])
        self.assertIn("audit_detail.go", check["message"])

    def test_static_guard_fails_when_competition_tag_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_guard_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace(" network_room_detail", ""),
                encoding="utf-8",
            )

            check = competition_guard.check_makefile_competition_tags(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("network_room_detail", check["message"])


def binary_runtime_profile() -> dict[str, object]:
    return {
        "delivery_mode": "binary-image",
        "player_default_mode": True,
        "built_runtime": {
            "platform": "linux/amd64",
            "targets": [
                "sentinel-aml-player-service/bin/aml-api",
                "sentinel-aml-player-service/bin/aml-worker",
                "sentinel-aml-player-service/bin/aml-migrate",
            ],
        },
        "build_profile_evidence": {
            "profile": "competition-runtime",
            "labels_exposed_in_player_artifact": False,
        },
        "runtime_evidence_required": True,
        "runtime_evidence": [],
        "artifact_local_runtime_proof": {
            "status": "external-required",
            "summary_path": "out/artifact-first-validation-summary.json",
            "artifact_bindings": [
                "player_artifact_sha256",
                "admin_artifact_sha256",
            ],
            "required_summary_fields": [
                "player_artifact_sha256",
                "admin_artifact_sha256",
                "runtime_validation.runtime_smoke.status",
                "runtime_validation.checker_check_havoc.status",
                "runtime_validation.sploit_matrix.status",
                "runtime_validation.fix_workflow.status",
                "runtime_validation.matrix_status.status",
            ],
        },
    }


def source_runtime_profile() -> dict[str, object]:
    return {
        "delivery_mode": "source",
        "runtime_evidence": [
            {
                "kind": "runtime-smoke",
                "status": "pass",
                "path": "docs/wave_reports/wave_34_player_package_runtime_proof.md",
            }
        ],
    }


def write_manifest(path: Path, *, archive_root: str, files: tuple[str, ...], runtime_profile: dict[str, object]) -> Path:
    manifest = {
        "artifact": {
            "archive_root": archive_root,
            "artifact_class": "player-service",
            "name": "sentinel-aml-player-service.tar.gz",
        },
        "files": [
            {
                "path": f"{archive_root}/{relative}",
                "sha256": "0" * 64,
                "size_bytes": 1,
            }
            for relative in files
        ],
        "file_count": len(files),
        "runtime_profile": runtime_profile,
    }
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def make_player_artifact(path: Path, members: dict[str, str]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for relative, content in sorted(members.items()):
            data = content.encode("utf-8")
            info = tarfile.TarInfo(f"sentinel-aml-player-service/{relative}")
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return path


def copy_guard_tree(destination: Path) -> Path:
    for name in ("scripts", "tests"):
        shutil.copytree(
            ROOT / name,
            destination / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    shutil.copyfile(ROOT / "Makefile", destination / "Makefile")
    return destination


if __name__ == "__main__":
    unittest.main()
