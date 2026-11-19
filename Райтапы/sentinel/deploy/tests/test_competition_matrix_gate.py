import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_competition_matrix_gate.py"

spec = importlib.util.spec_from_file_location("check_competition_matrix_gate", SCRIPT_PATH)
competition_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(competition_gate)


class CompetitionMatrixGateTest(unittest.TestCase):
    def test_current_branch_competition_gate_passes(self):
        result = competition_gate.validate_competition_matrix_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_missing_adr_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / competition_gate.ADR_PATH).unlink()

            result = competition_gate.validate_competition_matrix_gate(root)

        self.assertEqual(result["status"], "fail")
        adr = next(check for check in result["checks"] if check["name"] == "competition-adr-present")
        self.assertEqual(adr["status"], "fail")

    def test_missing_reference_fix_skeleton_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / competition_gate.FIXES_README_PATH).unlink()

            result = competition_gate.validate_competition_matrix_gate(root)

        self.assertEqual(result["status"], "fail")
        skeleton = next(check for check in result["checks"] if check["name"] == "reference-fix-skeleton-present")
        self.assertEqual(skeleton["status"], "fail")

    def test_debug_admin_variant_toggle_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "debug_variant.go"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("package httpapi\n\nconst EnableDebugAdminVariant = true\n", encoding="utf-8")

            check = competition_gate.check_no_debug_admin_variant_toggles(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("debug_variant.go", check["message"])

    def test_matrix_placeholder_missing_from_adr_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            adr = root / competition_gate.ADR_PATH
            adr.write_text(
                adr.read_text(encoding="utf-8").replace("exploit-blocked gate", "blocked exploit check"),
                encoding="utf-8",
            )

            check = competition_gate.check_matrix_placeholders(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("exploit-blocked gate", check["message"])

    def test_aml1_concrete_cell_requires_wave14_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "internal" / "httpapi" / "dedup_profile_case_match.go").unlink()

            check = competition_gate.check_aml1_vulnerable_checker_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("dedup_profile_case_match.go", check["message"])

    def test_aml1_exploit_success_cell_requires_wave19_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_dedup_preview.py").unlink()

            check = competition_gate.check_aml1_exploit_success_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_dedup_preview.py", check["message"])

    def test_wave28_sequence_requires_five_exploits_and_five_fix_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_wave28_exploit_and_fix_sequence(root)

        self.assertEqual(check["status"], "pass")

    def test_wave28_sequence_rejects_extra_exploit_and_nonstandard_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_unplanned.py").write_text("print('extra')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "aml1_fix.txt").write_text("nonstandard\n", encoding="utf-8")

            check = competition_gate.check_wave28_exploit_and_fix_sequence(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_unplanned.py", check["message"])
        self.assertIn("aml1_fix.txt", check["message"])

    def test_aml1_fix_cells_are_concrete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_aml1_fix_cells_concrete(root)

        self.assertEqual(check["status"], "pass")

    def test_aml1_fix_cells_reject_missing_fix_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch").unlink()

            check = competition_gate.check_aml1_fix_cells_concrete(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("fix_artifacts=[]", check["message"])

    def test_aml2_concrete_cell_requires_wave15_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "internal" / "httpapi" / "audit_profile_detail.go").unlink()

            check = competition_gate.check_aml2_vulnerable_checker_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("audit_profile_detail.go", check["message"])

    def test_aml2_exploit_success_cell_requires_wave20_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_aml2_exploit_success_cell(root)

        self.assertEqual(check["status"], "pass")

    def test_aml2_exploit_success_cell_rejects_missing_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_audit_timeline.py").unlink()

            check = competition_gate.check_aml2_exploit_success_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_audit_timeline.py", check["message"])

    def test_aml2_fix_cells_are_concrete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_aml2_fix_cells_concrete(root)

        self.assertEqual(check["status"], "pass")

    def test_aml2_fix_cells_reject_missing_fix_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch").unlink()

            check = competition_gate.check_aml2_fix_cells_concrete(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("fix_artifacts=[]", check["message"])

    def test_aml3_concrete_cell_requires_wave16_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "internal" / "httpapi" / "graph_profile_entity_review.go").unlink()

            check = competition_gate.check_aml3_vulnerable_checker_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("graph_profile_entity_review.go", check["message"])

    def test_aml3_exploit_success_cell_requires_wave21_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_aml3_exploit_success_cell(root)

        self.assertEqual(check["status"], "pass")

    def test_aml3_exploit_success_cell_rejects_missing_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_related_graph.py").unlink()

            check = competition_gate.check_aml3_exploit_success_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_related_graph.py", check["message"])

    def test_aml3_fix_cells_are_concrete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_aml3_fix_cells_concrete(root)

        self.assertEqual(check["status"], "pass")

    def test_aml3_fix_cells_reject_missing_fix_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_related_graph.patch").unlink()

            check = competition_gate.check_aml3_fix_cells_concrete(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("fix_artifacts=[]", check["message"])

    def test_aml4_concrete_cell_requires_wave17_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "internal" / "httpapi" / "export_profile_linked_case.go").unlink()

            check = competition_gate.check_aml4_vulnerable_checker_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("export_profile_linked_case.go", check["message"])

    def test_aml4_exploit_success_cell_requires_wave22_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_aml4_exploit_success_cell(root)

        self.assertEqual(check["status"], "pass")

    def test_aml4_exploit_success_cell_rejects_missing_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_export_redaction.py").unlink()

            check = competition_gate.check_aml4_exploit_success_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_export_redaction.py", check["message"])

    def test_aml4_fix_cells_are_concrete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_aml4_fix_cells_concrete(root)

        self.assertEqual(check["status"], "pass")

    def test_aml4_fix_cells_reject_missing_fix_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_export_redaction.patch").unlink()

            check = competition_gate.check_aml4_fix_cells_concrete(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("fix_artifacts=[]", check["message"])

    def test_aml5_concrete_cell_requires_wave18_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "internal" / "httpapi" / "network_room_profile_detail.go").unlink()

            check = competition_gate.check_aml5_vulnerable_checker_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("network_room_profile_detail.go", check["message"])

    def test_aml5_exploit_success_cell_requires_wave23_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_aml5_exploit_success_cell(root)

        self.assertEqual(check["status"], "pass")

    def test_aml5_exploit_success_cell_rejects_missing_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_network_room.py").unlink()

            check = competition_gate.check_aml5_exploit_success_cell(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.py", check["message"])

    def test_aml5_fix_cells_are_concrete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_aml5_fix_cells_concrete(root)

        self.assertEqual(check["status"], "pass")

    def test_aml5_fix_cells_reject_missing_fix_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_network_room.patch").unlink()

            check = competition_gate.check_aml5_fix_cells_concrete(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("fix_artifacts=[]", check["message"])

    def test_wave32_matrix_shape_covers_all_five_rows_and_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_wave32_validation_matrix_shape(root)

        self.assertEqual(check["status"], "pass")
        self.assertEqual([row["aml"] for row in competition_gate.WAVE32_SPLOIT_FIX_MATRIX], [f"AML-{idx}" for idx in range(1, 6)])
        self.assertIn("fixed profile blocks sploit", competition_gate.WAVE32_MATRIX_COLUMNS)
        self.assertIn("CHECK/HAVOC stays green", competition_gate.WAVE32_MATRIX_COLUMNS)

    def test_wave32_sploit_business_paths_are_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_wave32_sploit_syntax_and_business_paths(root)

        self.assertEqual(check["status"], "pass")

    def test_wave32_sploit_path_evidence_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            sploit = root / "sploits" / "sentinel_aml" / "aml_network_room.py"
            sploit.write_text(
                sploit.read_text(encoding="utf-8").replace("/api/network/rooms/{room_id}/dossier", "/api/network/rooms/{room_id}/summary"),
                encoding="utf-8",
            )

            check = competition_gate.check_wave32_sploit_syntax_and_business_paths(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("/api/network/rooms/{room_id}/dossier", check["message"])

    def test_wave32_sploit_shortcuts_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            sploit = root / "sploits" / "sentinel_aml" / "aml_dedup_preview.py"
            sploit.write_text(sploit.read_text(encoding="utf-8") + "\nDB_SHORTCUT = 'sqlite3:///flags'\n", encoding="utf-8")

            check = competition_gate.check_wave32_sploit_syntax_and_business_paths(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("sqlite3", check["message"])

    def test_wave32_fix_patch_and_simulation_evidence_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_wave32_fix_patch_and_simulation_evidence(root)

        self.assertEqual(check["status"], "pass")

    def test_wave32_fixed_block_simulation_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            test_path = root / "tests" / "test_wave26_gate.py"
            test_path.write_text(
                test_path.read_text(encoding="utf-8").replace(
                    "test_aml3_exploit_fails_safely_on_fixed_public_graph_output",
                    "test_aml3_fixed_graph_output_placeholder",
                ),
                encoding="utf-8",
            )

            check = competition_gate.check_wave32_fix_patch_and_simulation_evidence(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("test_aml3_exploit_fails_safely_on_fixed_public_graph_output", check["message"])

    def test_wave32_docs_and_report_evidence_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))

            check = competition_gate.check_wave32_docs_and_report_evidence(root)

        self.assertEqual(check["status"], "pass")

    def test_wave32_docs_require_all_matrix_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            report = root / "docs" / "wave_reports" / "wave_32_sploit_fix_matrix.md"
            report.write_text(
                report.read_text(encoding="utf-8").replace("fixed profile blocks sploit", "fixed profile evidence"),
                encoding="utf-8",
            )
            matrix = root / "docs" / "09_vulnerability_matrix.md"
            matrix.write_text(
                matrix.read_text(encoding="utf-8").replace("fixed profile blocks sploit", "fixed profile evidence"),
                encoding="utf-8",
            )

            check = competition_gate.check_wave32_docs_and_report_evidence(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("fixed profile blocks sploit", check["message"])

    def test_unsequenced_aml_activation_markers_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_competition_tree(Path(tmp))
            target = root / "internal" / "httpapi" / "aml6_profile.go"
            target.write_text("package httpapi\nconst aml6_vulnerable = true\n", encoding="utf-8")

            check = competition_gate.check_no_unsequenced_aml_activation(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml6_vulnerable", check["message"])


def minimal_competition_tree(root: Path) -> Path:
    for dirname in ("cmd", "internal", "checkers/sentinel_aml", "scripts", "tests", "docs/decisions", "sploits/sentinel_aml", "fixes/sentinel_aml"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "scripts" / "check_competition_matrix_gate.py", root / "scripts" / "check_competition_matrix_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave14_gate.py", root / "scripts" / "check_wave14_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave15_gate.py", root / "scripts" / "check_wave15_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave16_gate.py", root / "scripts" / "check_wave16_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave17_gate.py", root / "scripts" / "check_wave17_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave18_gate.py", root / "scripts" / "check_wave18_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave19_gate.py", root / "scripts" / "check_wave19_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave20_gate.py", root / "scripts" / "check_wave20_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave21_gate.py", root / "scripts" / "check_wave21_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave22_gate.py", root / "scripts" / "check_wave22_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave23_gate.py", root / "scripts" / "check_wave23_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave24_gate.py", root / "scripts" / "check_wave24_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave25_gate.py", root / "scripts" / "check_wave25_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave26_gate.py", root / "scripts" / "check_wave26_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave27_gate.py", root / "scripts" / "check_wave27_gate.py")
    shutil.copyfile(ROOT / "scripts" / "check_wave28_gate.py", root / "scripts" / "check_wave28_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave19_gate.py", root / "tests" / "test_wave19_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave20_gate.py", root / "tests" / "test_wave20_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave21_gate.py", root / "tests" / "test_wave21_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave22_gate.py", root / "tests" / "test_wave22_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave23_gate.py", root / "tests" / "test_wave23_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave24_gate.py", root / "tests" / "test_wave24_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave25_gate.py", root / "tests" / "test_wave25_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave26_gate.py", root / "tests" / "test_wave26_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave27_gate.py", root / "tests" / "test_wave27_gate.py")
    shutil.copyfile(ROOT / "tests" / "test_wave28_gate.py", root / "tests" / "test_wave28_gate.py")
    shutil.copyfile(ROOT / "docs" / "decisions" / "ADR-0002-competition-variant-and-reference-fix-strategy.md", root / competition_gate.ADR_PATH)
    shutil.copyfile(ROOT / "docs" / "09_vulnerability_matrix.md", root / "docs" / "09_vulnerability_matrix.md")
    shutil.copyfile(ROOT / "checkers" / "sentinel_aml" / "checker_lib.py", root / "checkers" / "sentinel_aml" / "checker_lib.py")
    shutil.copyfile(ROOT / "sploits" / "sentinel_aml" / "README.md", root / "sploits" / "sentinel_aml" / "README.md")
    shutil.copyfile(ROOT / "sploits" / "sentinel_aml" / "aml_dedup_preview.py", root / "sploits" / "sentinel_aml" / "aml_dedup_preview.py")
    shutil.copyfile(ROOT / "sploits" / "sentinel_aml" / "aml_audit_timeline.py", root / "sploits" / "sentinel_aml" / "aml_audit_timeline.py")
    shutil.copyfile(ROOT / "sploits" / "sentinel_aml" / "aml_related_graph.py", root / "sploits" / "sentinel_aml" / "aml_related_graph.py")
    shutil.copyfile(ROOT / "sploits" / "sentinel_aml" / "aml_export_redaction.py", root / "sploits" / "sentinel_aml" / "aml_export_redaction.py")
    shutil.copyfile(ROOT / "sploits" / "sentinel_aml" / "aml_network_room.py", root / "sploits" / "sentinel_aml" / "aml_network_room.py")
    shutil.copyfile(ROOT / "fixes" / "sentinel_aml" / "README.md", root / competition_gate.FIXES_README_PATH)
    shutil.copyfile(ROOT / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch", root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch")
    shutil.copyfile(ROOT / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch", root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch")
    shutil.copyfile(ROOT / "fixes" / "sentinel_aml" / "aml_related_graph.patch", root / "fixes" / "sentinel_aml" / "aml_related_graph.patch")
    shutil.copyfile(ROOT / "fixes" / "sentinel_aml" / "aml_export_redaction.patch", root / "fixes" / "sentinel_aml" / "aml_export_redaction.patch")
    shutil.copyfile(ROOT / "fixes" / "sentinel_aml" / "aml_network_room.patch", root / "fixes" / "sentinel_aml" / "aml_network_room.patch")
    (root / "docs" / "wave_reports").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "docs" / "wave_reports" / "wave_32_sploit_fix_matrix.md", root / "docs" / "wave_reports" / "wave_32_sploit_fix_matrix.md")
    shutil.copyfile(ROOT / "docs" / "wave_reports" / "wave_24_W24-T01_handoff.md", root / "docs" / "wave_reports" / "wave_24_W24-T01_handoff.md")
    shutil.copyfile(ROOT / "docs" / "wave_reports" / "wave_25_W25-T01_handoff.md", root / "docs" / "wave_reports" / "wave_25_W25-T01_handoff.md")
    shutil.copyfile(ROOT / "docs" / "wave_reports" / "wave_26_W26-T01_handoff.md", root / "docs" / "wave_reports" / "wave_26_W26-T01_handoff.md")
    shutil.copyfile(ROOT / "docs" / "wave_reports" / "wave_27_W27-T01_handoff.md", root / "docs" / "wave_reports" / "wave_27_W27-T01_handoff.md")
    shutil.copyfile(ROOT / "docs" / "wave_reports" / "wave_28_W28-F01_handoff.md", root / "docs" / "wave_reports" / "wave_28_W28-F01_handoff.md")
    shutil.copyfile(ROOT / "Makefile", root / "Makefile")
    (root / "config.yml").write_text("tasks: []\n", encoding="utf-8")
    (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (root / "internal" / "httpapi" / "routes.go").parent.mkdir(parents=True, exist_ok=True)
    (root / "internal" / "httpapi" / "routes.go").write_text("package httpapi\n", encoding="utf-8")
    for relative in (
        "internal/httpapi/dedup_profile_default.go",
        "internal/httpapi/dedup_profile_case_match.go",
        "internal/httpapi/dedup_profile_case_match_test.go",
        "internal/httpapi/audit_profile_default.go",
        "internal/httpapi/audit_profile_detail.go",
        "internal/httpapi/audit_profile_detail_test.go",
        "internal/httpapi/graph_profile_default.go",
        "internal/httpapi/graph_profile_entity_review.go",
        "internal/graph/repository_entity_review.go",
        "internal/httpapi/graph_profile_entity_review_test.go",
        "internal/exporting/export_profile_default.go",
        "internal/exporting/export_profile_linked_case.go",
        "internal/httpapi/export_profile_default.go",
        "internal/httpapi/export_profile_linked_case.go",
        "internal/httpapi/export_profile_linked_case_test.go",
        "internal/httpapi/network_room_profile_default.go",
        "internal/httpapi/network_room_profile_detail.go",
        "internal/networkroom/dossier_profile_room_detail.go",
        "internal/networkroom/repository_room_detail.go",
        "internal/httpapi/network_room_profile_detail_test.go",
        "internal/networkroom/repository_room_detail_test.go",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


if __name__ == "__main__":
    unittest.main()
