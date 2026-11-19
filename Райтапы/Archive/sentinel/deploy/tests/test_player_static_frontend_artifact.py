from __future__ import annotations

import importlib.util
import io
import sys
import tarfile
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


builder = load_script("build_player_source_artifact")
static_frontend = load_script("check_player_static_frontend")


class PlayerStaticFrontendArtifactTest(unittest.TestCase):
    def test_generated_artifact_includes_valid_static_frontend(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sentinel-aml-player-source.tar.gz"
            self.assertEqual(builder.build_player_source_artifact(artifact)["status"], "pass")

            result = static_frontend.check_player_static_frontend(artifact)

        self.assertEqual(result["status"], "pass", result)
        self.assertGreaterEqual(result["frontend_dist_file_count"], 3)
        self.assertTrue(result["frontend_static_sha256"])

    def test_missing_static_asset_reference_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "fixture.tar.gz"
            write_tar(
                artifact,
                {
                    "web/dist/index.html": '<title>Sentinel AML</title><script src="/runtime-config.js"></script><script type="module" src="/assets/missing.js"></script>',
                    "web/dist/runtime-config.js": 'window.__SENTINEL_CONFIG__ = { apiBaseUrl: "" };\n',
                },
            )

            result = static_frontend.check_player_static_frontend(artifact)

        self.assertEqual(result["status"], "fail")
        self.assertTrue(any(finding["token"] == "asset-ref" for finding in result["findings"]))


def write_tar(path: Path, files: dict[str, str]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for relative, content in sorted(files.items()):
            data = content.encode("utf-8")
            info = tarfile.TarInfo(f"{static_frontend.ARCHIVE_ROOT}/{relative}")
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    unittest.main()
