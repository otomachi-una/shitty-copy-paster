import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


source_manifest = load_script("check_player_source_manifest")
live_acceptance = load_script("check_artifact_first_live_acceptance")


class PlayerSourceExactHashBindingTest(unittest.TestCase):
    def test_player_source_manifest_matches_current_artifact_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            artifact, digest = write_source_artifact_output(output_root, b"current source artifact\n")

            result = source_manifest.check_player_source_manifest(output_root)
            self.assertEqual(result["status"], "pass")

            artifact.write_bytes(b"stale artifact bytes\n")
            stale_digest = source_manifest.sha256_file(artifact)
            stale = source_manifest.check_player_source_manifest(output_root)

        self.assertEqual(stale["status"], "fail")
        self.assertTrue(any("SHA" in finding["message"] for finding in stale["findings"]))
        self.assertNotEqual(digest, stale_digest)

    def test_live_acceptance_binding_fails_on_stale_artifact_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp) / "out"
            artifact, digest = write_legacy_artifact_output(output_root, b"runtime artifact\n")
            summary = output_root / "validation" / "exact-artifact-live-acceptance-summary.json"
            summary.parent.mkdir(parents=True)
            summary.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-aml-exact-artifact-live-acceptance.v1",
                        "status": "pass",
                        "runtime_validation": {"player_artifact_sha256": digest},
                    }
                ),
                encoding="utf-8",
            )

            passing = live_acceptance.check_artifact_first_live_acceptance(output_root, summary_path=summary, require_live=True)
            self.assertEqual(passing["status"], "pass")

            artifact.write_bytes(b"mutated runtime artifact\n")
            failing = live_acceptance.check_artifact_first_live_acceptance(output_root, summary_path=summary, require_live=True)

        self.assertEqual(failing["status"], "fail")
        self.assertTrue(any("does not match" in finding["message"] for finding in failing["findings"]))


def write_source_artifact_output(output_root: Path, payload: bytes) -> tuple[Path, str]:
    artifact = output_root / "artifacts" / source_manifest.ARTIFACT_NAME
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(payload)
    digest = source_manifest.sha256_file(artifact)
    manifest = output_root / "manifests" / source_manifest.MANIFEST_NAME
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "artifact": {
                    "name": source_manifest.ARTIFACT_NAME,
                    "artifact_class": "player-source",
                    "primary": True,
                    "player_facing": True,
                    "distribution_model": "source-based-player",
                    "sha256": digest,
                    "size_bytes": artifact.stat().st_size,
                },
                "artifact_contract": {
                    "primary_player_artifact": True,
                    "distribution_model": "source-based-player",
                },
            }
        ),
        encoding="utf-8",
    )
    checksums = output_root / "checksums" / source_manifest.CHECKSUMS_NAME
    checksums.parent.mkdir(parents=True)
    checksums.write_text(f"{digest}  artifacts/{source_manifest.ARTIFACT_NAME}\n", encoding="utf-8")
    return artifact, digest


def write_legacy_artifact_output(output_root: Path, payload: bytes) -> tuple[Path, str]:
    artifact = output_root / "artifacts" / live_acceptance.PLAYER_LEGACY_ARTIFACT
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(payload)
    return artifact, live_acceptance.sha256_file(artifact)


if __name__ == "__main__":
    unittest.main()
