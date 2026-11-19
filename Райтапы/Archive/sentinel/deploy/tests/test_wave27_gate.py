import contextlib
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave27_gate.py"

spec = importlib.util.spec_from_file_location("check_wave27_gate", SCRIPT_PATH)
wave27_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave27_gate)

WAVE22_TEST_PATH = ROOT / "tests" / "test_wave22_gate.py"
wave22_spec = importlib.util.spec_from_file_location("test_wave22_gate_for_wave27", WAVE22_TEST_PATH)
wave22_tests = importlib.util.module_from_spec(wave22_spec)
assert wave22_spec.loader is not None
wave22_spec.loader.exec_module(wave22_tests)

GO_RELEASE_RUNNER_PATH = ROOT / "scripts" / "run_go_release_tests.py"
go_runner_spec = importlib.util.spec_from_file_location("run_go_release_tests_for_wave27", GO_RELEASE_RUNNER_PATH)
go_release_runner = importlib.util.module_from_spec(go_runner_spec)
assert go_runner_spec.loader is not None
go_runner_spec.loader.exec_module(go_release_runner)


class Wave27GateTest(unittest.TestCase):
    def test_wave27_gate_current_branch_has_no_failures(self):
        result = wave27_gate.validate_wave27_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_missing_aml4_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_export_redaction.patch").unlink()

            check = wave27_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_export_redaction.patch", check["message"])

    def test_extra_aml5_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_network_room.patch").write_text("too early\n", encoding="utf-8")

            check = wave27_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.patch", check["message"])

    def test_missing_exploit_inventory_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_export_redaction.py").unlink()

            check = wave27_gate.check_reference_exploits(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_export_redaction.py", check["message"])

    def test_patch_scope_rejects_docs_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/docs/wave_reports/wave_27_W27-T01_handoff.md b/docs/wave_reports/wave_27_W27-T01_handoff.md",
                        "--- a/docs/wave_reports/wave_27_W27-T01_handoff.md",
                        "+++ b/docs/wave_reports/wave_27_W27-T01_handoff.md",
                        "@@ -1,1 +1,1 @@",
                        "-# Wave 27 W27-T01 Handoff",
                        "+# Wave 27 W27-T01 Handoff",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave27_gate.check_aml4_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("docs/wave_reports/wave_27_W27-T01_handoff.md", check["message"])

    def test_patch_scope_rejects_gate_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/scripts/check_wave27_gate.py b/scripts/check_wave27_gate.py",
                        "--- a/scripts/check_wave27_gate.py",
                        "+++ b/scripts/check_wave27_gate.py",
                        "@@ -1,1 +1,1 @@",
                        "-#!/usr/bin/env python3",
                        "+#!/usr/bin/env python3",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave27_gate.check_aml4_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("scripts/check_wave27_gate.py", check["message"])

    def test_patch_scope_rejects_outside_aml4_export_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\ndiff --git a/internal/httpapi/server.go b/internal/httpapi/server.go\n--- a/internal/httpapi/server.go\n+++ b/internal/httpapi/server.go\n@@ -1,1 +1,1 @@\n-package httpapi\n+package httpapi\n",
                encoding="utf-8",
            )

            check = wave27_gate.check_aml4_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("internal/httpapi/server.go", check["message"])

    def test_patch_blocks_leak_rejects_raw_linked_note_body_reintroduction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n+\tbundle.LinkedPrivateNotes = append(bundle.LinkedPrivateNotes, map[string]any{\"body\": strings.TrimSpace(note.Body)})\n",
                encoding="utf-8",
            )

            check = wave27_gate.check_aml4_patch_blocks_export_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("bundle.LinkedPrivateNotes", check["message"])

    def test_patch_blocks_leak_rejects_private_edd_direct_db_debug_and_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n+\t_ = \"EDDRecord.confidential_comment\"\n+\timport \"database/sql\"\n+\texec.Command(\"sh\")\n+\t_ = \"/api/admin\"\n",
                encoding="utf-8",
            )

            check = wave27_gate.check_aml4_patch_blocks_export_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("EDDRecord.confidential_comment", check["message"])
        self.assertIn("database/sql", check["message"])
        self.assertIn("exec.Command", check["message"])
        self.assertIn("/api/admin", check["message"])

    def test_patch_blocks_leak_rejects_sensitive_renames_hashes_and_raw_diffs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n+\tLinkedNoteBody string `json:\"linked_note_body\"`\n+\tInternalComment string `json:\"internal_comment\"`\n+\tAnalystInternalNote string `json:\"analyst_internal_note\"`\n+\tDiffJSON string `json:\"diff_json\"`\n+\tValueHash string `json:\"value_hash\"`\n",
                encoding="utf-8",
            )

            check = wave27_gate.check_aml4_patch_blocks_export_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("LinkedNoteBody", check["message"])
        self.assertIn("InternalComment", check["message"])
        self.assertIn("AnalystInternalNote", check["message"])
        self.assertIn("DiffJSON", check["message"])
        self.assertIn("ValueHash", check["message"])

    def test_patch_anti_coarse_fix_rejects_deletion_of_linked_public_export_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                .replace("AML4 linked public shell", "AML4 hidden linked shell")
                .replace("linked_cases", "hiddenlinkedcases")
                .replace("restricted_field", "hiddensensitivefield"),
                encoding="utf-8",
            )

            check = wave27_gate.check_aml4_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("AML4 linked public shell", check["message"])
        self.assertIn("linked_cases", check["message"])
        self.assertIn("restricted_field", check["message"])

    def test_patch_anti_coarse_fix_rejects_export_and_dispute_endpoint_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n-\t/api/cases/{case_id}/exports\n-\t/api/exports/{export_id}\n-\t/api/disputes\n-\t/api/disputes/{dispute_id}/export\n",
                encoding="utf-8",
            )

            check = wave27_gate.check_aml4_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("/api/cases/{case_id}/exports", check["message"])
        self.assertIn("/api/exports/{export_id}", check["message"])
        self.assertIn("/api/disputes/{dispute_id}/export", check["message"])

    def test_patch_anti_coarse_fix_rejects_export_handler_or_bundle_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n-\thandleCreateCaseExport\n-\thandleDisputeExport\n-\tBuildBundle\n-\tExportBundleView\n-\tLinkedCases\n",
                encoding="utf-8",
            )

            check = wave27_gate.check_aml4_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("handleCreateCaseExport", check["message"])
        self.assertIn("BuildBundle", check["message"])
        self.assertIn("LinkedCases", check["message"])

    def test_patch_anti_coarse_fix_rejects_export_disablement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            patch = root / wave27_gate.AML4_PATCH
            patch.write_text(patch.read_text(encoding="utf-8") + "\n+\tconst DisableExport = true\n", encoding="utf-8")

            check = wave27_gate.check_aml4_patch_blocks_export_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("DisableExport", check["message"])

    def test_aml4_exploit_parser_extracts_from_vulnerable_linked_private_note(self):
        response = {
            "bundle": {
                "linked_private_notes": [
                    {"case_id": 4201, "note_id": 901, "body": "linked case note FLAG{wave27-parser-vulnerable}"}
                ]
            }
        }

        values = list(wave22_tests.aml_export_redaction.iter_linked_private_note_bodies(response))
        flags = [wave22_tests.aml_export_redaction.extract_flag(value) for value in values]

        self.assertEqual(flags, ["FLAG{wave27-parser-vulnerable}"])

    def test_aml4_exploit_parser_fails_safely_on_fixed_public_export_payload(self):
        response = {
            "bundle": {
                "redaction_policy": "public",
                "root_case": {"case_id": 601, "public_summary": "AML4 root public shell"},
                "linked_cases": [{"case_id": 4201, "public_summary": "AML4 linked public shell"}],
                "audit_summaries": [{"event_type": "case_exported", "restricted_field": True}],
                "edd_summaries": [{"customer_id": 3201, "review_status": "in_review"}],
            }
        }

        values = list(wave22_tests.aml_export_redaction.iter_linked_private_note_bodies(response))

        self.assertEqual(values, [])
        serialized = json.dumps(response, sort_keys=True)
        self.assertNotIn("FLAG{", serialized)
        self.assertNotIn("linked_private_notes", serialized)
        self.assertNotIn("confidential_comment", serialized)

    def test_aml4_exploit_succeeds_on_vulnerable_fixture(self):
        with wave22_tests.fake_aml4_service("FLAG{wave27-vulnerable-evidence}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave22_tests.aml_export_redaction.main(
                    [server.host, str(server.port), json.dumps(wave22_tests.valid_attack_data()), "--timeout", "2"]
                )

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{wave27-vulnerable-evidence}")
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("POST", "/api/disputes/701/export"), paths)
        self.assertIn(("GET", "/api/exports/801"), paths)

    def test_aml4_exploit_fails_safely_on_fixed_public_export_output(self):
        with wave22_tests.fake_aml4_service(None) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave22_tests.aml_export_redaction.main(
                    [server.host, str(server.port), json.dumps(wave22_tests.valid_attack_data()), "--timeout", "2"]
                )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found", stderr.getvalue())

    def test_fixed_export_fixture_preserves_public_evidence_and_owner_private_paths(self):
        with fake_fixed_aml4_export_service("FLAG{wave27-owner-only}") as server:
            client = wave22_tests.aml_export_redaction.Client(server.host, str(server.port), timeout=2)
            created = client.request_json("POST", "/api/disputes/701/export", {"purpose": "regulatory_report"}, token="attacker-token", expected_statuses=(201,))
            stored = client.request_json("GET", "/api/exports/801", token="attacker-token")
            owner_notes = client.request_json("GET", "/api/cases/4201/notes", token="owner-token")
            owner_edd = client.request_json("GET", "/api/customers/3201/edd", token="owner-token")

            with self.assertRaises(wave22_tests.aml_export_redaction.HTTPStatusError):
                client.request_json("GET", "/api/cases/4201/notes", token="attacker-token")
            with self.assertRaises(wave22_tests.aml_export_redaction.HTTPStatusError):
                client.request_json("GET", "/api/customers/3201/edd", token="attacker-token")

        public_payload = json.dumps({"created": created, "stored": stored}, sort_keys=True)
        self.assertIn("AML4 root public shell", public_payload)
        self.assertIn("AML4 linked public shell", public_payload)
        self.assertIn("linked_cases", public_payload)
        self.assertIn("redaction_policy", public_payload)
        self.assertIn("restricted_field", public_payload)
        for forbidden in ("FLAG{wave27-owner-only}", "linked_private_notes", "confidential_comment", '"body"', "diff_json", "raw_db_row"):
            self.assertNotIn(forbidden, public_payload)
        self.assertNotIn("analyst_internal_note", public_payload)
        self.assertEqual(owner_notes["notes"][0]["body"], "linked owner note FLAG{wave27-owner-only}")
        self.assertEqual(owner_edd["edd_records"][0]["confidential_comment"], "linked owner EDD FLAG{wave27-owner-only}")
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("POST", "/api/disputes/701/export"), paths)
        self.assertIn(("GET", "/api/exports/801"), paths)
        self.assertIn(("GET", "/api/cases/4201/notes"), paths)
        self.assertIn(("GET", "/api/customers/3201/edd"), paths)

    def test_makefile_target_requires_full_gate_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            (root / "Makefile").write_text("wave27-gate:\n\tpython -B scripts/check_wave27_gate.py\n", encoding="utf-8")

            check = wave27_gate.check_makefile_wave27_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("test_checker_*.py", check["message"])
        self.assertIn("test_run_go_release_tests.py", check["message"])
        self.assertIn("aml_export_redaction.patch", check["message"])
        self.assertIn("check_archive_hygiene.py", check["message"])

    def test_makefile_target_rejects_unbounded_go_test_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            makefile = (root / "Makefile").read_text(encoding="utf-8")
            makefile = makefile.replace(
                "$(PYTHON) -B scripts/run_go_release_tests.py --go $(GO) --package-timeout 120",
                "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...",
            )
            (root / "Makefile").write_text(makefile, encoding="utf-8")

            check = wave27_gate.check_makefile_wave27_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("forbidden unbounded", check["message"])

    def test_makefile_target_invokes_package_by_package_go_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave27_tree(Path(tmp))
            target = wave27_gate.make_target_block((root / "Makefile").read_text(encoding="utf-8"), "wave27-gate")

        self.assertIn("scripts/run_go_release_tests.py --go $(GO) --package-timeout 120", target)
        self.assertNotIn("$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...", target)

    def test_go_release_runner_sorts_packages_and_runs_each_with_isolated_release_env(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append({"command": command, "cwd": cwd, "env": env, "timeout": timeout})
            if command[1] == "list":
                return subprocess.CompletedProcess(command, 0, "example.com/sentinel/b\nexample.com/sentinel/a\n", "")
            return subprocess.CompletedProcess(command, 0, f"ok {command[-1]}\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = go_release_runner.run_release_tests(
                root,
                go="go",
                package_timeout=120,
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )

        self.assertEqual(exit_code, 0, stderr.getvalue())
        test_commands = [call for call in calls if call["command"][1] == "test"]
        self.assertEqual([call["command"][-1] for call in test_commands], ["example.com/sentinel/a", "example.com/sentinel/b"])
        self.assertEqual(stdout.getvalue().splitlines()[0], "go test package: example.com/sentinel/a")
        for call in test_commands:
            self.assertEqual(call["env"]["GOTOOLCHAIN"], "local")
            self.assertEqual(call["env"]["GOFLAGS"], "-mod=vendor")
            self.assertEqual(call["env"]["GOTELEMETRY"], "off")
            self.assertNotIn(str(root), call["env"]["GOCACHE"])
            self.assertNotIn(str(root), call["env"]["APPDATA"])
            self.assertEqual(call["timeout"], 150)


def minimal_wave27_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml", "internal/httpapi", "internal/exporting"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave27_gate.py",
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
        "docs/wave_reports/wave_27_W27-T01_handoff.md",
        "docs/wave_reports/wave_27_W27-T02_handoff.md",
        "docs/wave_reports/wave_27_W27-T03_handoff.md",
        "Makefile",
        "internal/httpapi/export_profile_aml4_vulnerable.go",
        "internal/exporting/export_profile_aml4_vulnerable.go",
        "internal/httpapi/aml4_vulnerable_export_test.go",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


class FakeFixedAML4ExportService:
    def __init__(self, private_flag: str):
        self.private_flag = private_flag
        self.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.host = "127.0.0.1"
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _handler(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                parent.handle(self)

            def do_POST(self):
                parent.handle(self)

            def log_message(self, _format, *args):
                return

        return Handler

    def handle(self, handler):
        length = int(handler.headers.get("Content-Length", "0") or "0")
        raw_body = handler.rfile.read(length) if length else b""
        body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        self.requests.append({"method": handler.command, "path": handler.path, "body": body})

        if (handler.command, handler.path) == ("POST", "/api/disputes/701/export"):
            self.write_json(handler, 201, self.export_response())
            return
        if (handler.command, handler.path) == ("GET", "/api/exports/801"):
            self.write_json(handler, 200, self.export_response())
            return
        if (handler.command, handler.path) == ("GET", "/api/cases/4201/notes"):
            if handler.headers.get("Authorization") != "Bearer owner-token":
                self.write_json(handler, 404, {"error": "not_found"})
                return
            self.write_json(handler, 200, {"notes": [{"id": 901, "body": f"linked owner note {self.private_flag}"}]})
            return
        if (handler.command, handler.path) == ("GET", "/api/customers/3201/edd"):
            if handler.headers.get("Authorization") != "Bearer owner-token":
                self.write_json(handler, 404, {"error": "not_found"})
                return
            self.write_json(handler, 200, {"edd_records": [{"id": 902, "confidential_comment": f"linked owner EDD {self.private_flag}"}]})
            return
        self.write_json(handler, 404, {"error": "not_found"})

    def export_response(self):
        return {
            "id": 801,
            "root_case_id": 601,
            "dispute_id": 701,
            "purpose": "regulatory_report",
            "bundle": {
                "redaction_policy": "public",
                "root_case": {"case_id": 601, "public_summary": "AML4 root public shell"},
                "linked_cases": [{"case_id": 4201, "public_summary": "AML4 linked public shell"}],
                "audit_summaries": [{"event_type": "case_exported", "restricted_field": True}],
                "edd_summaries": [{"customer_id": 3201, "review_status": "in_review"}],
                "items": [],
            },
        }

    def write_json(self, handler, status, payload):
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(raw)


def fake_fixed_aml4_export_service(private_flag: str):
    return FakeFixedAML4ExportService(private_flag)


if __name__ == "__main__":
    unittest.main()
