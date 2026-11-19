import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave24_gate.py"

spec = importlib.util.spec_from_file_location("check_wave24_gate", SCRIPT_PATH)
wave24_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave24_gate)

WAVE19_TEST_PATH = ROOT / "tests" / "test_wave19_gate.py"
wave19_spec = importlib.util.spec_from_file_location("test_wave19_gate_for_wave24", WAVE19_TEST_PATH)
wave19_tests = importlib.util.module_from_spec(wave19_spec)
assert wave19_spec.loader is not None
wave19_spec.loader.exec_module(wave19_tests)


class Wave24GateTest(unittest.TestCase):
    def test_wave24_gate_current_branch_has_no_failures(self):
        result = wave24_gate.validate_wave24_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_missing_aml1_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch").unlink()

            check = wave24_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("expected one AML-1 fix artifact", check["message"])

    def test_unknown_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "unexpected_fix.patch").write_text("too early\n", encoding="utf-8")

            check = wave24_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("unexpected_fix.patch", check["message"])

    def test_missing_exploit_inventory_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_network_room.py").unlink()

            check = wave24_gate.check_reference_exploits(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.py", check["message"])

    def test_patch_scope_rejects_missing_safe_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch"
            patch.write_text(patch.read_text(encoding="utf-8").replace("PublicMatchEvidenceSources", "LegacyEvidenceSources"), encoding="utf-8")

            check = wave24_gate.check_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("PublicMatchEvidenceSources", check["message"])

    def test_patch_blocks_leak_rejects_added_private_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch"
            patch.write_text(patch.read_text(encoding="utf-8") + "\n+\tPrivateNotes []string `json:\"private_notes\"`\n", encoding="utf-8")

            check = wave24_gate.check_patch_blocks_aml1_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("private_notes", check["message"])

    def test_anti_coarse_fix_rejects_dedup_endpoint_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch"
            patch.write_text(patch.read_text(encoding="utf-8") + "\n-\t/api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview\n", encoding="utf-8")

            check = wave24_gate.check_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("/merge-preview", check["message"])

    def test_patch_blocks_leak_rejects_dedup_disablement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch"
            patch.write_text(patch.read_text(encoding="utf-8") + "\n+\tconst DisableDedup = true\n", encoding="utf-8")

            check = wave24_gate.check_patch_blocks_aml1_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("DisableDedup", check["message"])

    def test_patch_scope_rejects_docs_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch"
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/docs/wave_reports/wave_24_W24-T01_handoff.md b/docs/wave_reports/wave_24_W24-T01_handoff.md",
                        "--- a/docs/wave_reports/wave_24_W24-T01_handoff.md",
                        "+++ b/docs/wave_reports/wave_24_W24-T01_handoff.md",
                        "@@ -1,1 +1,1 @@",
                        "-# W24-T01 Handoff - AML-1 Narrow Reference Fix Artifact",
                        "+# W24-T01 Handoff - AML-1 Narrow Reference Fix Artifact",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave24_gate.check_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("docs/wave_reports/wave_24_W24-T01_handoff.md", check["message"])

    def test_patch_scope_rejects_gate_constant_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch"
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/scripts/check_wave24_gate.py b/scripts/check_wave24_gate.py",
                        "--- a/scripts/check_wave24_gate.py",
                        "+++ b/scripts/check_wave24_gate.py",
                        "@@ -1,1 +1,1 @@",
                        "-#!/usr/bin/env python3",
                        "+#!/usr/bin/env python3",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave24_gate.check_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("scripts/check_wave24_gate.py", check["message"])

    def test_aml1_exploit_succeeds_on_vulnerable_fixture(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "CaseNote.body",
            "case_id": 5201,
            "matching_reference": "victim-shared-hint",
        }
        with wave19_tests.fake_aml1_service("FLAG{wave24-vulnerable-evidence}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave19_tests.aml_dedup_preview.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{wave24-vulnerable-evidence}")
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("GET", "/api/cases/6201/duplicates"), paths)
        self.assertIn(("GET", "/api/cases/6201/duplicates/5201/merge-preview"), paths)

    def test_aml1_exploit_fails_safely_on_fixed_public_output(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "CaseNote.body",
            "case_id": 5201,
            "matching_reference": "victim-shared-hint",
        }
        with wave19_tests.fake_aml1_service(None) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave19_tests.aml_dedup_preview.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found in match explanation", stderr.getvalue())
        self.assertNotIn("FLAG{", stderr.getvalue())
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("GET", "/api/cases/6201/duplicates"), paths)
        self.assertIn(("GET", "/api/cases/6201/duplicates/5201/merge-preview"), paths)

    def test_patch_apply_check_rejects_corrupt_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_dedup_preview.patch").write_text("not a patch\n", encoding="utf-8")

            check = wave24_gate.check_patch_applies(root)

        self.assertEqual(check["status"], "fail")

    def test_docs_require_t01_handoff_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            (root / wave24_gate.HANDOFF_T01_PATH).write_text("W24-T01 AML-1\n", encoding="utf-8")

            check = wave24_gate.check_docs(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("test_checker_*.py", check["message"])

    def test_makefile_target_requires_full_gate_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            (root / "Makefile").write_text("wave24-gate:\n\tpython -B scripts/check_wave24_gate.py\n", encoding="utf-8")

            check = wave24_gate.check_makefile_wave24_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("test_checker_*.py", check["message"])
        self.assertIn("check_archive_hygiene.py", check["message"])

    def test_makefile_target_rejects_unbounded_go_test_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            makefile = (root / "Makefile").read_text(encoding="utf-8")
            makefile = makefile.replace(
                "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...",
                "$(GO_RELEASE_ENV) $(GO) test ./...",
            )
            (root / "Makefile").write_text(makefile, encoding="utf-8")

            check = wave24_gate.check_makefile_wave24_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("forbidden unbounded", check["message"])
        self.assertIn("$(GO) test ./...", check["message"])

    def test_makefile_target_requires_unique_release_cache_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave24_tree(Path(tmp))
            makefile = (root / "Makefile").read_text(encoding="utf-8")
            makefile = makefile.replace(
                'GO_RELEASE_ENV = GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=$$(mktemp -d "$${TMPDIR:-/tmp}/sentinel-aml-gocache.XXXXXXXXXX") APPDATA=$$(mktemp -d "$${TMPDIR:-/tmp}/sentinel-aml-appdata.XXXXXXXXXX")',
                "GO_RELEASE_ENV = GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=$${TMPDIR:-/tmp}/sentinel-aml-gocache APPDATA=$${TMPDIR:-/tmp}/sentinel-aml-appdata",
            )
            (root / "Makefile").write_text(makefile, encoding="utf-8")

            check = wave24_gate.check_makefile_wave24_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("missing no-repo-cache release env markers", check["message"])


def minimal_wave24_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml", "internal/httpapi"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave24_gate.py",
        "sploits/sentinel_aml/aml_dedup_preview.py",
        "sploits/sentinel_aml/aml_audit_timeline.py",
        "sploits/sentinel_aml/aml_related_graph.py",
        "sploits/sentinel_aml/aml_export_redaction.py",
        "sploits/sentinel_aml/aml_network_room.py",
        "fixes/sentinel_aml/README.md",
        "fixes/sentinel_aml/aml_dedup_preview.patch",
        "docs/wave_reports/wave_24_W24-T01_handoff.md",
        "Makefile",
        "internal/httpapi/dedup_profile_case_match.go",
        "internal/httpapi/dedup_profile_case_match_test.go",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


if __name__ == "__main__":
    unittest.main()
