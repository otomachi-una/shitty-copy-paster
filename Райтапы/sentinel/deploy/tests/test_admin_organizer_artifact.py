from __future__ import annotations

import gzip
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


builder = load_script("build_admin_organizer_artifact", ROOT / "scripts" / "build_admin_organizer_artifact.py")
contents = load_script("check_admin_artifact_contents", ROOT / "scripts" / "check_admin_artifact_contents.py")
hygiene = load_script("check_admin_artifact_hygiene", ROOT / "scripts" / "check_admin_artifact_hygiene.py")


class AdminOrganizerArtifactTest(unittest.TestCase):
    def build_artifact(self, directory: Path) -> Path:
        artifact = directory / "sentinel-aml-admin-organizer.tar.gz"
        result = builder.build_admin_organizer_artifact(artifact)
        self.assertEqual(result["status"], "pass", result)
        return artifact

    def test_builder_is_deterministic_and_writes_external_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = self.build_artifact(root / "a")
            second = self.build_artifact(root / "b")
            first_manifest = json.loads((first.parent / "ADMIN_MANIFEST.json").read_text(encoding="utf-8"))

            self.assertEqual(builder.sha256_file(first), builder.sha256_file(second))
            self.assertEqual(first_manifest["artifact"]["sha256"], builder.sha256_file(first))
            self.assertEqual(first_manifest["artifact"]["artifact_class"], "admin-organizer")
            self.assertFalse(first_manifest["artifact"]["player_facing"])
            self.assertTrue(first_manifest["artifact"]["organizer_only"])

    def test_admin_artifact_contains_checker_sploits_fixes_validation_and_docs(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self.build_artifact(Path(tmp))
            files = set(archive_members(artifact))

        required = {
            "sentinel-aml-admin-organizer/README_ADMIN.md",
            "sentinel-aml-admin-organizer/ADMIN_MANIFEST.json",
            "sentinel-aml-admin-organizer/SHA256SUMS",
            "sentinel-aml-admin-organizer/config.yml",
            "sentinel-aml-admin-organizer/checkers/sentinel_aml/checker.py",
            "sentinel-aml-admin-organizer/scripts/check_exact_artifact_live_acceptance.py",
            "sentinel-aml-admin-organizer/scripts/check_player_source_runtime.py",
            "sentinel-aml-admin-organizer/tests/test_live_competition_matrix.py",
            "sentinel-aml-admin-organizer/docs/source_of_truth_map.md",
            "sentinel-aml-admin-organizer/validation/README.md",
        }
        required.update(f"sentinel-aml-admin-organizer/sploits/sentinel_aml/{name}" for name in builder.REQUIRED_SPLOITS)
        required.update(f"sentinel-aml-admin-organizer/fixes/sentinel_aml/{name}" for name in builder.REQUIRED_FIXES)
        self.assertTrue(required <= files, sorted(required - files))

    def test_admin_artifact_checkers_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self.build_artifact(Path(tmp))
            content_result = contents.check_admin_artifact_contents(artifact)
            hygiene_result = hygiene.check_admin_artifact_hygiene(artifact)

        self.assertEqual(content_result["status"], "pass", content_result)
        self.assertEqual(hygiene_result["status"], "pass", hygiene_result)

    def test_admin_artifact_has_no_participant_archive_confusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self.build_artifact(Path(tmp))
            names = archive_members(artifact)

        joined = "\n".join(names)
        self.assertNotIn("sentinel-aml-player-source.tar.gz", joined)
        self.assertNotIn("sentinel-aml-player-binary.tar.gz", joined)
        self.assertNotIn("sentinel-aml-player-service.tar.gz", joined)
        self.assertNotIn("__pycache__", joined)
        self.assertNotIn("node_modules", joined)
        self.assertNotIn("validation/exact-artifact-live", joined)

    def test_admin_artifact_hygiene_fails_on_nested_player_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "bad.tar.gz"
            files = {
                "sentinel-aml-admin-organizer/README_ADMIN.md": "organizer-only; must not be distributed to participant teams. do not copy this package into player source distributions\n",
                "sentinel-aml-admin-organizer/ADMIN_MANIFEST.json": json.dumps(
                    {"artifact": {"archive_root": "sentinel-aml-admin-organizer", "player_facing": False, "organizer_only": True}}
                ),
                "sentinel-aml-admin-organizer/out/sentinel-aml-player-source.tar.gz": "nested\n",
            }
            write_tar(artifact, files)
            result = hygiene.check_admin_artifact_hygiene(artifact)

        self.assertEqual(result["status"], "fail")
        self.assertGreaterEqual(result["hit_count"], 1)

    def test_makefile_admin_organizer_targets_exist(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertRegex(makefile, r"(?m)^admin-organizer-artifact:")
        self.assertRegex(makefile, r"(?m)^admin-organizer-artifact-gate:")
        target = makefile.split("admin-organizer-artifact-gate:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("scripts/build_admin_organizer_artifact.py", target)
        self.assertIn("scripts/check_admin_artifact_contents.py", target)
        self.assertIn("scripts/check_admin_artifact_hygiene.py", target)


def archive_members(artifact: Path) -> list[str]:
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        return sorted(member.name for member in archive.getmembers() if member.isfile())


def write_tar(path: Path, files: dict[str, str]) -> None:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, text in sorted(files.items()):
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(payload.getvalue())


if __name__ == "__main__":
    unittest.main()
