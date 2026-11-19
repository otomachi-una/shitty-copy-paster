import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave28_gate.py"

spec = importlib.util.spec_from_file_location("check_wave28_gate", SCRIPT_PATH)
wave28_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave28_gate)

WAVE23_TEST_PATH = ROOT / "tests" / "test_wave23_gate.py"
wave23_spec = importlib.util.spec_from_file_location("test_wave23_gate_for_wave28", WAVE23_TEST_PATH)
wave23_tests = importlib.util.module_from_spec(wave23_spec)
assert wave23_spec.loader is not None
wave23_spec.loader.exec_module(wave23_tests)


class Wave28GateTest(unittest.TestCase):
    def test_wave28_gate_current_branch_has_no_failures(self):
        result = wave28_gate.validate_wave28_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_missing_aml5_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            (root / wave28_gate.AML5_PATCH).unlink()

            check = wave28_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.patch", check["message"])

    def test_extra_nonstandard_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml5_fix.txt").write_text("nonstandard\n", encoding="utf-8")

            check = wave28_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml5_fix.txt", check["message"])

    def test_patch_scope_rejects_docs_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            patch = root / wave28_gate.AML5_PATCH
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/docs/wave_reports/wave_28_W28-F01_handoff.md b/docs/wave_reports/wave_28_W28-F01_handoff.md",
                        "--- a/docs/wave_reports/wave_28_W28-F01_handoff.md",
                        "+++ b/docs/wave_reports/wave_28_W28-F01_handoff.md",
                        "@@ -1,1 +1,1 @@",
                        "-# Wave 28 W28-F01 Handoff",
                        "+# Wave 28 W28-F01 Handoff",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave28_gate.check_aml5_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("docs/wave_reports/wave_28_W28-F01_handoff.md", check["message"])

    def test_patch_scope_rejects_gate_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            patch = root / wave28_gate.AML5_PATCH
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/scripts/check_wave28_gate.py b/scripts/check_wave28_gate.py",
                        "--- a/scripts/check_wave28_gate.py",
                        "+++ b/scripts/check_wave28_gate.py",
                        "@@ -1,1 +1,1 @@",
                        "-#!/usr/bin/env python3",
                        "+#!/usr/bin/env python3",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave28_gate.check_aml5_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("scripts/check_wave28_gate.py", check["message"])

    def test_patch_scope_rejects_outside_aml5_network_room_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            patch = root / wave28_gate.AML5_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\ndiff --git a/internal/httpapi/server.go b/internal/httpapi/server.go\n--- a/internal/httpapi/server.go\n+++ b/internal/httpapi/server.go\n@@ -1,1 +1,1 @@\n-package httpapi\n+package httpapi\n",
                encoding="utf-8",
            )

            check = wave28_gate.check_aml5_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("internal/httpapi/server.go", check["message"])

    def test_missing_required_projection_change_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            patch = root / wave28_gate.AML5_PATCH
            patch.write_text(patch.read_text(encoding="utf-8").replace("+\t\t`\"scope_coverage_complete\":true`,\n", ""), encoding="utf-8")

            check = wave28_gate.check_aml5_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("scope_coverage_complete", check["message"])

    def test_patch_blocks_leak_rejects_sensitive_rename_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            patch = root / wave28_gate.AML5_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n+\tForeignNoteBody string `json:\"foreign_note_body\"`\n+\tPrivateNoteBody string `json:\"private_note_body\"`\n+\tValueHash string `json:\"value_hash\"`\n",
                encoding="utf-8",
            )

            check = wave28_gate.check_aml5_patch_blocks_network_room_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("ForeignNoteBody", check["message"])
        self.assertIn("PrivateNoteBody", check["message"])
        self.assertIn("ValueHash", check["message"])

    def test_patch_blocks_leak_rejects_private_material_reintroduction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            patch = root / wave28_gate.AML5_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n+\titem.PrivateNotes = append(item.PrivateNotes, DossierPrivateNote{Body: note.Body})\n+\titem.EDDComments = append(item.EDDComments, DossierEDDComment{ConfidentialComment: record.ConfidentialComment})\n",
                encoding="utf-8",
            )

            check = wave28_gate.check_aml5_patch_blocks_network_room_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("PrivateNotes = append", check["message"])
        self.assertIn("EDDComments = append", check["message"])
        self.assertIn(".ConfidentialComment", check["message"])

    def test_patch_blocks_leak_rejects_debug_admin_direct_db_and_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            patch = root / wave28_gate.AML5_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n+\timport \"database/sql\"\n+\trows, _ := r.db.QueryContext(ctx, \"SELECT body FROM case_notes\")\n+\texec.Command(\"sh\")\n+\t_ = \"/api/admin\"\n",
                encoding="utf-8",
            )

            check = wave28_gate.check_aml5_patch_blocks_network_room_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("database/sql", check["message"])
        self.assertIn("SELECT ", check["message"])
        self.assertIn("exec.Command", check["message"])
        self.assertIn("/api/admin", check["message"])

    def test_anti_coarse_fix_rejects_endpoint_dossier_and_worker_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            patch = root / wave28_gate.AML5_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n-\t/api/network/rooms\n-\t/api/network/rooms/{room_id}/join\n-\t/api/network/rooms/{room_id}/dossier\n-\thandleNetworkRoomDossier\n-\taml-worker\n",
                encoding="utf-8",
            )

            check = wave28_gate.check_aml5_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("/api/network/rooms", check["message"])
        self.assertIn("handleNetworkRoomDossier", check["message"])
        self.assertIn("aml-worker", check["message"])

    def test_anti_coarse_fix_rejects_public_summary_evidence_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            patch = root / wave28_gate.AML5_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                .replace("Owner network dossier shell", "Owner hidden shell")
                .replace("Foreign network dossier shell", "Foreign hidden shell")
                .replace("scope_coverage_complete", "coverage_hidden"),
                encoding="utf-8",
            )

            check = wave28_gate.check_aml5_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("Owner network dossier shell", check["message"])
        self.assertIn("Foreign network dossier shell", check["message"])
        self.assertIn("scope_coverage_complete", check["message"])

    def test_exploit_parser_extracts_from_vulnerable_network_room_output(self):
        dossier = {
            "cases": [
                {
                    "context_blocks": [{"content": "network note FLAG{wave28-vulnerable}"}],
                    "evaluation_blocks": [{"content": "review note FLAG{wave28-vulnerable-review}"}],
                }
            ]
        }

        flag = wave23_tests.aml_network_room.extract_flag_from_dossier(dossier)

        self.assertEqual(flag, "FLAG{wave28-vulnerable}")

    def test_exploit_parser_fails_safely_on_fixed_public_dossier_output(self):
        dossier = {
            "room": {"id": 901, "public_summary": "AML5 public network summary"},
            "cases": [
                {
                    "case_id": 401,
                    "customer_id": 999,
                    "owned_by_requester": False,
                    "public_summary": "Foreign network dossier shell",
                    "public_risk_tags": ["shared-entity"],
                    "scope_coverage_complete": True,
                }
            ],
            "scope_policy": "case_reference_scope",
            "coverage_policy": "summary_coverage",
        }

        flag = wave23_tests.aml_network_room.extract_flag_from_dossier(dossier)
        serialized = json.dumps(dossier, sort_keys=True)

        self.assertIsNone(flag)
        self.assertIn("Foreign network dossier shell", serialized)
        self.assertIn("scope_coverage_complete", serialized)
        self.assertNotIn("context_blocks", serialized)
        self.assertNotIn("evaluation_blocks", serialized)
        self.assertNotIn("confidential_comment", serialized)
        self.assertNotIn("FLAG{", serialized)

    def test_exploit_succeeds_on_accepted_vulnerable_fixture(self):
        with wave23_tests.fake_aml5_service(wave23_tests.valid_attack_data(), "FLAG{wave28-vulnerable-evidence}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave23_tests.aml_network_room.main(
                    [server.host, str(server.port), json.dumps(wave23_tests.valid_attack_data()), "--timeout", "2"]
                )

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{wave28-vulnerable-evidence}")

    def test_exploit_fails_safely_on_accepted_fixed_fixture(self):
        with wave23_tests.fake_aml5_service(wave23_tests.valid_attack_data(), None) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave23_tests.aml_network_room.main(
                    [server.host, str(server.port), json.dumps(wave23_tests.valid_attack_data()), "--timeout", "2"]
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found", stderr.getvalue())

    def test_makefile_target_requires_full_gate_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            (root / "Makefile").write_text("wave28-gate:\n\tpython -B scripts/check_wave28_gate.py\n", encoding="utf-8")

            check = wave28_gate.check_makefile_wave28_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("test_checker_*.py", check["message"])
        self.assertIn("test_wave28_gate.py", check["message"])
        self.assertIn("aml_network_room.patch", check["message"])
        self.assertIn("check_archive_hygiene.py", check["message"])

    def test_makefile_target_rejects_unbounded_go_test_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave28_tree(Path(tmp))
            makefile = (root / "Makefile").read_text(encoding="utf-8")
            makefile = makefile.replace(
                "$(PYTHON) -B scripts/run_go_release_tests.py --go $(GO) --package-timeout 120",
                "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...",
            )
            (root / "Makefile").write_text(makefile, encoding="utf-8")

            check = wave28_gate.check_makefile_wave28_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("forbidden unbounded", check["message"])


def minimal_wave28_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml", "internal/httpapi", "internal/networkroom"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave28_gate.py",
        "scripts/run_go_release_tests.py",
        "sploits/sentinel_aml/aml_dedup_preview.py",
        "sploits/sentinel_aml/aml_audit_timeline.py",
        "sploits/sentinel_aml/aml_related_graph.py",
        "sploits/sentinel_aml/aml_export_redaction.py",
        "sploits/sentinel_aml/aml_network_room.py",
        "fixes/sentinel_aml/README.md",
        "fixes/sentinel_aml/aml_dedup_preview.patch",
        "fixes/sentinel_aml/aml_audit_timeline.patch",
        "fixes/sentinel_aml/aml_related_graph.patch",
        "fixes/sentinel_aml/aml_export_redaction.patch",
        "fixes/sentinel_aml/aml_network_room.patch",
        "docs/wave_reports/wave_28_W28-F01_handoff.md",
        "docs/wave_reports/wave_28_W28-F02_handoff.md",
        "Makefile",
        "internal/httpapi/network_room_profile_aml5_vulnerable.go",
        "internal/networkroom/dossier_profile_aml5_vulnerable.go",
        "internal/networkroom/repository_aml5_vulnerable.go",
        "internal/networkroom/repository_aml5_vulnerable_test.go",
        "internal/httpapi/aml5_vulnerable_network_room_test.go",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_file():
            shutil.copyfile(source, target)
        else:
            target.write_text("placeholder\n", encoding="utf-8")
    return root


if __name__ == "__main__":
    unittest.main()
