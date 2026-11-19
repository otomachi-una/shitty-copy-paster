from __future__ import annotations

import gzip
import importlib.util
import io
import json
import tarfile
import tempfile
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_exact_artifact_live_acceptance.py"
spec = importlib.util.spec_from_file_location("check_exact_artifact_live_acceptance", SCRIPT_PATH)
live_acceptance = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = live_acceptance
spec.loader.exec_module(live_acceptance)


class ExactArtifactLiveAcceptanceTest(unittest.TestCase):
    def test_failure_summary_binds_exact_artifact_sha_before_live_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            player = root / "out" / "artifacts" / "sentinel-aml-player-service.tar.gz"
            admin = root / "out" / "artifacts" / "sentinel-aml-admin-organizer.tar.gz"
            make_archive(player, "sentinel-aml-player-service", {"README.md": "player\n"})
            make_archive(admin, "sentinel-aml-admin-organizer", {"README.md": "admin\n"})
            summary_path = root / "out" / "summary.json"

            summary = live_acceptance.run_acceptance(
                player_artifact=player,
                admin_artifact=admin,
                validation_root=ROOT / "validation" / "unit-live-acceptance",
                summary_output=summary_path,
                python="python",
                go="go",
                docker="docker",
            )

            written = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "fail")
            self.assertEqual(written["status"], "fail")
            self.assertRegex(written["artifacts"]["player"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(written["artifacts"]["admin"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertIn("extracted artifact contract is missing required files", written["error"])

    def test_safe_extract_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bad.tar.gz"
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode="w") as tar:
                info = tarfile.TarInfo("../escape.txt")
                data = b"bad\n"
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            with archive.open("wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
                    gz.write(payload.getvalue())

            with self.assertRaises(live_acceptance.AcceptanceFailure):
                live_acceptance.safe_extract(archive, ROOT / "validation" / "unit-live-acceptance-bad")


def make_archive(path: Path, root_name: str, files: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as tar:
        for relative, text in files.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(f"{root_name}/{relative}")
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(payload.getvalue())


if __name__ == "__main__":
    unittest.main()
