import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave25_gate.py"

spec = importlib.util.spec_from_file_location("check_wave25_gate", SCRIPT_PATH)
wave25_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave25_gate)

WAVE20_TEST_PATH = ROOT / "tests" / "test_wave20_gate.py"
wave20_spec = importlib.util.spec_from_file_location("test_wave20_gate_for_wave25", WAVE20_TEST_PATH)
wave20_tests = importlib.util.module_from_spec(wave20_spec)
assert wave20_spec.loader is not None
wave20_spec.loader.exec_module(wave20_tests)


class Wave25GateTest(unittest.TestCase):
    def test_wave25_gate_current_branch_has_no_failures(self):
        result = wave25_gate.validate_wave25_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_missing_aml2_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch").unlink()

            check = wave25_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_audit_timeline.patch", check["message"])

    def test_extra_nonstandard_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_future.patch").write_text("too early\n", encoding="utf-8")

            check = wave25_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_future.patch", check["message"])

    def test_missing_exploit_inventory_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_network_room.py").unlink()

            check = wave25_gate.check_reference_exploits(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.py", check["message"])

    def test_patch_scope_rejects_docs_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch"
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/docs/wave_reports/wave_25_W25-T01_handoff.md b/docs/wave_reports/wave_25_W25-T01_handoff.md",
                        "--- a/docs/wave_reports/wave_25_W25-T01_handoff.md",
                        "+++ b/docs/wave_reports/wave_25_W25-T01_handoff.md",
                        "@@ -1,1 +1,1 @@",
                        "-# W25-T01 Handoff - AML-2 Narrow Reference Fix Artifact",
                        "+# W25-T01 Handoff - AML-2 Narrow Reference Fix Artifact",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave25_gate.check_aml2_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("docs/wave_reports/wave_25_W25-T01_handoff.md", check["message"])

    def test_patch_scope_rejects_gate_constant_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch"
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/scripts/check_wave25_gate.py b/scripts/check_wave25_gate.py",
                        "--- a/scripts/check_wave25_gate.py",
                        "+++ b/scripts/check_wave25_gate.py",
                        "@@ -1,1 +1,1 @@",
                        "-#!/usr/bin/env python3",
                        "+#!/usr/bin/env python3",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave25_gate.check_aml2_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("scripts/check_wave25_gate.py", check["message"])

    def test_patch_anti_coarse_fix_rejects_timeline_endpoint_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch"
            patch.write_text(patch.read_text(encoding="utf-8") + "\n-\thandleCaseTimeline\n-\t/api/cases/{case_id}/timeline\n", encoding="utf-8")

            check = wave25_gate.check_aml2_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("handleCaseTimeline", check["message"])
        self.assertIn("/timeline", check["message"])

    def test_patch_anti_coarse_fix_rejects_activity_route_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch"
            patch.write_text(
                patch.read_text(encoding="utf-8") + "\n-\tcase len(parts) == 2 && parts[1] == \"activity\":\n-\t\t/api/customers/{customer_id}/activity\n",
                encoding="utf-8",
            )

            check = wave25_gate.check_aml2_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("activity", check["message"])

    def test_patch_anti_coarse_fix_rejects_audit_disablement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch"
            patch.write_text(patch.read_text(encoding="utf-8") + "\n+\tconst DisableAudit = true\n", encoding="utf-8")

            check = wave25_gate.check_aml2_patch_blocks_timeline_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("DisableAudit", check["message"])

    def test_patch_blocks_leak_rejects_raw_body_reintroduction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch"
            patch.write_text(patch.read_text(encoding="utf-8") + "\n+\t\t\t\tNew:      noteBody\n+\t\t\t\tRedacted: false\n", encoding="utf-8")

            check = wave25_gate.check_aml2_patch_blocks_timeline_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("New:      noteBody", check["message"])
        self.assertIn("Redacted: false", check["message"])

    def test_patch_blocks_leak_rejects_direct_db_shell_and_debug_shortcuts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            patch = root / "fixes" / "sentinel_aml" / "aml_audit_timeline.patch"
            patch.write_text(patch.read_text(encoding="utf-8") + "\n+\timport \"database/sql\"\n+\texec.Command(\"sh\")\n+\t_ = \"/api/admin\"\n", encoding="utf-8")

            check = wave25_gate.check_aml2_patch_blocks_timeline_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("database/sql", check["message"])
        self.assertIn("exec.Command", check["message"])
        self.assertIn("/api/admin", check["message"])

    def test_aml2_exploit_succeeds_on_vulnerable_fixture(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "CaseNote.body",
            "case_id": 5201,
            "customer_id": 1201,
            "entity_hint": "aml2-shared-entity",
            "dedup_hint": "aml2-public-locator",
        }
        with wave20_tests.fake_aml2_service("FLAG{wave25-vulnerable-evidence}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave20_tests.aml_audit_timeline.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{wave25-vulnerable-evidence}")
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("GET", "/api/entities/aml2-shared-entity/activity"), paths)
        self.assertNotIn(("GET", "/api/cases/5201/timeline"), paths)
        self.assertNotIn(("GET", "/api/cases/5201/notes"), paths)

    def test_aml2_exploit_fails_safely_on_fixed_redacted_output_and_preserves_event(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "CaseNote.body",
            "case_id": 5201,
            "entity_hint": "aml2-shared-entity",
            "dedup_hint": "aml2-public-locator",
        }
        with fake_fixed_aml2_service("FLAG{wave25-fixed-private-note}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave20_tests.aml_audit_timeline.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found", stderr.getvalue())
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("GET", "/api/entities/aml2-shared-entity/activity"), paths)
        self.assertNotIn(("GET", "/api/cases/5201/timeline"), paths)
        self.assertNotIn(("GET", "/api/cases/5201/notes"), paths)
        timeline = server.last_timeline
        self.assertEqual(timeline["activities"][0]["object_type"], "case_note")
        self.assertEqual(timeline["activities"][0]["changes"][0]["field"], "restricted_field")
        self.assertEqual(timeline["activities"][0]["changes"][0]["new"], "[redacted]")
        self.assertIs(timeline["activities"][0]["changes"][0]["redacted"], True)
        self.assertNotIn("FLAG{wave25-fixed-private-note}", json.dumps(timeline))

    def test_fixed_fixture_owner_note_path_still_returns_private_note_to_owner(self):
        with fake_fixed_aml2_service("FLAG{wave25-owner-note-still-private}") as server:
            client = wave20_tests.aml_audit_timeline.Client(server.host, str(server.port), timeout=2)
            notes = client.request_json("GET", "/api/cases/5201/notes", token="owner-token")

        self.assertEqual(notes["notes"][0]["body"], "owner note FLAG{wave25-owner-note-still-private}")

    def test_makefile_target_requires_full_gate_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            (root / "Makefile").write_text("wave25-gate:\n\tpython -B scripts/check_wave25_gate.py\n", encoding="utf-8")

            check = wave25_gate.check_makefile_wave25_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("test_checker_*.py", check["message"])
        self.assertIn("aml_audit_timeline.patch", check["message"])
        self.assertIn("check_archive_hygiene.py", check["message"])

    def test_makefile_target_rejects_unbounded_go_test_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave25_tree(Path(tmp))
            makefile = (root / "Makefile").read_text(encoding="utf-8")
            makefile = makefile.replace(
                "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...",
                "$(GO_RELEASE_ENV) $(GO) test ./...",
            )
            (root / "Makefile").write_text(makefile, encoding="utf-8")

            check = wave25_gate.check_makefile_wave25_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("forbidden unbounded", check["message"])


def minimal_wave25_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml", "internal/httpapi"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave25_gate.py",
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
        "docs/wave_reports/wave_25_W25-T01_handoff.md",
        "docs/wave_reports/wave_25_W25-T02_handoff.md",
        "Makefile",
        "internal/httpapi/audit_profile_detail.go",
        "internal/httpapi/audit_profile_detail_test.go",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


class FakeFixedAML2Service:
    def __init__(self, private_flag: str):
        self.private_flag = private_flag
        self.requests = []
        self.last_timeline = {}
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

        if (handler.command, handler.path) == ("POST", "/api/auth/register"):
            self.write_json(handler, 201, {"user": {"id": 1}, "session": {"token": "registration-token"}})
            return
        if (handler.command, handler.path) == ("POST", "/api/auth/login"):
            self.write_json(handler, 200, {"user": {"id": 1}, "session": {"token": "attacker-token"}})
            return
        if (handler.command, handler.path) == ("POST", "/api/customers"):
            self.write_json(handler, 201, {"id": 42, "entity_hint": body.get("entity_hint", "")})
            return
        if (handler.command, handler.path) == ("GET", "/api/entities/aml2-shared-entity/activity"):
            self.last_timeline = {
                "activities": [
                    {
                        "id": 9001,
                        "object_type": "case_note",
                        "object_id": 7001,
                        "event_type": "created",
                        "public_message": "review context updated",
                        "activity_narrative": "Review context updated",
                        "activity_detail_level": "related_view",
                        "changes": [{"field": "restricted_field", "new": "[redacted]", "redacted": True}],
                    }
                ]
            }
            self.write_json(handler, 200, self.last_timeline)
            return
        if (handler.command, handler.path) == ("GET", "/api/cases/5201/notes"):
            token = handler.headers.get("Authorization", "")
            if token != "Bearer owner-token":
                self.write_json(handler, 404, {"error": "not_found"})
                return
            self.write_json(handler, 200, {"notes": [{"id": 7001, "body": f"owner note {self.private_flag}"}]})
            return
        self.write_json(handler, 404, {"error": "not_found"})

    def write_json(self, handler, status, payload):
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(raw)


def fake_fixed_aml2_service(private_flag: str):
    return FakeFixedAML2Service(private_flag)


if __name__ == "__main__":
    unittest.main()
