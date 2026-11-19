import importlib.util
import gzip
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate_forcad_config.py"

spec = importlib.util.spec_from_file_location("validate_forcad_config", VALIDATOR_PATH)
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)


class ForcadLayoutTest(unittest.TestCase):
    def test_config_shape(self):
        task = validator.load_task_config(ROOT / "config.yml")

        self.assertIsInstance(task, dict)
        self.assertEqual(task["name"], "sentinel_aml")
        self.assertEqual(task["checker"], "sentinel_aml/checker.py")
        self.assertEqual(task["checker_type"], "pfr")
        self.assertEqual(task["checker_timeout"], 30)
        self.assertEqual(task["places"], 2)
        self.assertEqual(task["puts"], 2)
        self.assertEqual(task["gets"], 2)
        self.assertEqual(validator.validate_config(ROOT / "config.yml"), [])

    def test_config_rejects_mapping_shape(self):
        mapping_config = """tasks:
  sentinel_aml:
    checker: sentinel_aml/checker.py
    checker_type: pfr
    checker_timeout: 30
    places: 2
    puts: 2
    gets: 2
"""
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
            tmp.write(mapping_config)
            tmp_path = Path(tmp.name)

        try:
            with self.assertRaises(ValueError):
                validator.load_task_config(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_checker_and_sploit_directories_are_separate(self):
        checker_dir = ROOT / "checkers" / "sentinel_aml"
        sploit_dir = ROOT / "sploits" / "sentinel_aml"

        self.assertTrue((checker_dir / "checker.py").is_file())
        self.assertTrue((checker_dir / "checker_lib.py").is_file())
        self.assertTrue((sploits_readme := sploit_dir / "README.md").is_file())
        self.assertNotEqual(checker_dir.resolve(), sploit_dir.resolve())
        self.assertNotIn("checkers", sploits_readme.relative_to(ROOT).parts)

    def test_config_has_no_debug_db_or_exploit_reference(self):
        config_text = (ROOT / "config.yml").read_text(encoding="utf-8").lower()
        for forbidden in ("debug", "admin", "db", "database", "sploits", "exploit"):
            self.assertNotIn(forbidden, config_text)

    def test_reference_exploits_are_organizer_only(self):
        sploit_dir = ROOT / "sploits" / "sentinel_aml"
        expected_files = {
            "aml_dedup_preview.py",
            "aml_audit_timeline.py",
            "aml_related_graph.py",
            "aml_export_redaction.py",
            "aml_network_room.py",
        }

        existing_python_files = {path.name for path in sploit_dir.glob("*.py")}
        self.assertEqual(existing_python_files, expected_files)

        player_artifact = ROOT / "inputs" / "team-public" / "sentinel-aml-player-source.tar.gz"
        admin_artifact = ROOT / "inputs" / "organizer-private" / "sentinel-aml-admin-organizer.tar.gz"
        if player_artifact.is_file():
            player_files = archive_members(player_artifact)
            for filename in expected_files:
                self.assertNotIn(f"sentinel-aml-player-source/sploits/sentinel_aml/{filename}", player_files)
        if admin_artifact.is_file():
            admin_files = archive_members(admin_artifact)
            for filename in expected_files:
                self.assertIn(f"sentinel-aml-admin-organizer/sploits/sentinel_aml/{filename}", admin_files)

    def test_reference_exploit_readme_lists_future_contract_names(self):
        readme_text = (ROOT / "sploits" / "sentinel_aml" / "README.md").read_text(encoding="utf-8")
        expected_future_files = {
            "aml_dedup_preview.py",
            "aml_audit_timeline.py",
            "aml_related_graph.py",
            "aml_export_redaction.py",
            "aml_network_room.py",
        }
        generic_store_names = {
            "ex_case_note_body.py",
            "ex_edd_confidential_comment.py",
        }

        for filename in expected_future_files:
            self.assertIn(filename, readme_text)
        for filename in generic_store_names:
            self.assertNotIn(filename, readme_text)

    def test_checker_placeholder_fails_closed(self):
        checker_path = ROOT / "checkers" / "sentinel_aml" / "checker.py"
        self.assertIn("Wave 11", checker_path.read_text(encoding="utf-8"))

def archive_members(path: Path) -> set[str]:
    with gzip.open(path, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        return {member.name for member in archive.getmembers() if member.isfile()}


if __name__ == "__main__":
    unittest.main()
