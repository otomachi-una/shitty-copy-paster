import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave17_gate.py"

spec = importlib.util.spec_from_file_location("check_wave17_gate", SCRIPT_PATH)
wave17_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave17_gate)


class Wave17GateTest(unittest.TestCase):
    def test_wave17_gate_current_branch_has_no_failures(self):
        result = wave17_gate.validate_wave17_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_wave17_rejects_missing_vulnerable_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave17_tree(Path(tmp))
            (root / "internal" / "exporting" / "export_profile_aml4_vulnerable.go").unlink()

            check = wave17_gate.check_profile_split(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml4_vulnerable", check["message"])

    def test_wave17_rejects_edd_or_network_leak_in_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave17_tree(Path(tmp))
            profile = root / "internal" / "exporting" / "export_profile_aml4_vulnerable.go"
            profile.write_text(
                profile.read_text(encoding="utf-8") + "\nconst bad = \"confidential_comment network_room\"\n",
                encoding="utf-8",
            )

            check = wave17_gate.check_profile_split(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("confidential_comment", check["message"])
        self.assertIn("network_room", check["message"])

    def test_wave17_rejects_default_export_body_field_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave17_tree(Path(tmp))
            redaction = root / "internal" / "exporting" / "redaction.go"
            redaction.write_text(
                redaction.read_text(encoding="utf-8").replace(
                    "LinkedPrivateNotes []map[string]any     `json:\"linked_private_notes,omitempty\"`",
                    "LinkedPrivateNotes []map[string]any     `json:\"linked_private_notes,omitempty\"`\n\tBody string `json:\"body\"`",
                ),
                encoding="utf-8",
            )

            check = wave17_gate.check_export_bundle_profile_contract(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn('json:"body"', check["message"])

    def test_wave17_rejects_reference_exploit_or_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave17_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_export_redaction.py").write_text("print('future exploit')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "aml_export_redaction.patch").write_text("future fix\n", encoding="utf-8")

            check = wave17_gate.check_no_reference_exploit_or_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_export_redaction.py", check["message"])
        self.assertIn("aml_export_redaction.patch", check["message"])

    def test_wave17_rejects_debug_admin_profile_toggle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave17_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "bad_toggle.go"
            target.write_text("package httpapi\nconst EnableDebugAdminExportVariant = true\n", encoding="utf-8")

            check = wave17_gate.check_no_debug_admin_toggles(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("bad_toggle.go", check["message"])
        self.assertIn("EnableDebugAdmin", check["message"])

    def test_wave17_rejects_aml5_activation_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave17_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "aml5_profile.go"
            target.write_text("package httpapi\nconst aml5_vulnerable = true\n", encoding="utf-8")

            check = wave17_gate.check_no_future_aml_activation(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml5_vulnerable", check["message"])

    def test_wave17_requires_makefile_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave17_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(makefile.read_text(encoding="utf-8").replace("wave17-gate:", "wave17-disabled:"), encoding="utf-8")

            check = wave17_gate.check_makefile_wave17_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave17-gate", check["message"])

    def test_wave17_requires_serialized_tagged_sweep(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave17_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace(
                    "$(GO_OFFLINE_ENV) go test -p 1 -tags aml4_vulnerable ./...",
                    "$(GO_OFFLINE_ENV) go test -tags aml4_vulnerable ./...",
                ),
                encoding="utf-8",
            )

            check = wave17_gate.check_makefile_wave17_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("-p 1", check["message"])


def minimal_wave17_tree(root: Path) -> Path:
    for relative in (
        "internal/exporting/redaction.go",
        "internal/exporting/export_profile_secure.go",
        "internal/exporting/export_profile_aml4_vulnerable.go",
        "internal/exporting/export_profile_aml4_vulnerable_test.go",
        "internal/httpapi/server.go",
        "internal/httpapi/export_profile_secure.go",
        "internal/httpapi/export_profile_aml4_vulnerable.go",
        "internal/httpapi/export_profile_secure_test.go",
        "internal/httpapi/aml4_vulnerable_export_test.go",
        "docs/wave_reports/wave_17_W17-T01_handoff.md",
        "config.yml",
        "docker-compose.yml",
        "Makefile",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for dirname in ("cmd", "checkers"):
        (root / dirname).mkdir(exist_ok=True)
    sploits = root / "sploits" / "sentinel_aml"
    sploits.mkdir(parents=True)
    shutil.copyfile(ROOT / "sploits" / "sentinel_aml" / "README.md", sploits / "README.md")
    fixes = root / "fixes" / "sentinel_aml"
    fixes.mkdir(parents=True)
    shutil.copyfile(ROOT / "fixes" / "sentinel_aml" / "README.md", fixes / "README.md")
    return root


if __name__ == "__main__":
    unittest.main()
