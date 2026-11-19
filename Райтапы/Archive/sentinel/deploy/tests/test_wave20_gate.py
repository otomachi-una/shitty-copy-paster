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
GATE_PATH = ROOT / "scripts" / "check_wave20_gate.py"
EXPLOIT_PATH = ROOT / "sploits" / "sentinel_aml" / "aml_audit_timeline.py"

gate_spec = importlib.util.spec_from_file_location("check_wave20_gate", GATE_PATH)
wave20_gate = importlib.util.module_from_spec(gate_spec)
assert gate_spec.loader is not None
gate_spec.loader.exec_module(wave20_gate)

exploit_spec = importlib.util.spec_from_file_location("aml_audit_timeline", EXPLOIT_PATH)
aml_audit_timeline = importlib.util.module_from_spec(exploit_spec)
assert exploit_spec.loader is not None
exploit_spec.loader.exec_module(aml_audit_timeline)


class Wave20GateTest(unittest.TestCase):
    def test_wave20_gate_current_branch_has_no_failures(self):
        result = wave20_gate.validate_wave20_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_exploit_cli_help_is_available_without_service_request(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                aml_audit_timeline.parse_args(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("Exploit AML-2", stdout.getvalue())
        self.assertIn("attack_info", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_attack_data_requires_activity_entity_hint_and_locator(self):
        with self.assertRaises(aml_audit_timeline.ExploitError):
            aml_audit_timeline.load_attack_data(json.dumps({"service": "sentinel_aml", "store": "EDDRecord.confidential_comment", "entity_hint": "x", "dedup_hint": "x"}))
        with self.assertRaises(aml_audit_timeline.ExploitError):
            aml_audit_timeline.load_attack_data(json.dumps({"service": "sentinel_aml", "store": "CaseNote.body", "case_id": 1, "dedup_hint": "x"}))
        with self.assertRaises(aml_audit_timeline.ExploitError):
            aml_audit_timeline.load_attack_data(json.dumps({"service": "sentinel_aml", "store": "CaseNote.body", "entity_hint": "x"}))

    def test_exploit_extracts_flag_from_vulnerable_timeline_change(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "CaseNote.body",
            "case_id": 5201,
            "customer_id": 1201,
            "entity_hint": "aml2-shared-entity",
            "dedup_hint": "aml2-public-locator",
            "typology_hint": "audit-review",
        }
        with fake_aml2_service("FLAG{audit-timeline-leak}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_audit_timeline.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{audit-timeline-leak}")
        self.assertEqual(stderr.getvalue(), "")
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("POST", "/api/auth/register"), paths)
        self.assertIn(("POST", "/api/auth/login"), paths)
        self.assertIn(("POST", "/api/customers"), paths)
        self.assertIn(("GET", "/api/entities/aml2-shared-entity/activity"), paths)
        self.assertNotIn(("GET", "/api/cases/5201/timeline"), paths)
        self.assertNotIn(("GET", "/api/cases/5201/notes"), paths)

    def test_exploit_extracts_flag_from_vulnerable_raw_diff_json(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "CaseNote.body",
            "case_id": 5201,
            "entity_hint": "aml2-shared-entity",
            "dedup_hint": "aml2-public-locator",
        }
        with fake_aml2_service("FLAG{audit-raw-diff-leak}", raw_diff_only=True) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_audit_timeline.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{audit-raw-diff-leak}")
        self.assertEqual(stderr.getvalue(), "")

    def test_exploit_fails_safely_against_secure_redacted_timeline(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "CaseNote.body",
            "case_id": 5201,
            "entity_hint": "aml2-shared-entity",
            "dedup_hint": "aml2-public-locator",
        }
        with fake_aml2_service(None) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_audit_timeline.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found", stderr.getvalue())

    def test_wave20_rejects_missing_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave20_tree(Path(tmp))
            (root / wave20_gate.EXPLOIT_PATH).unlink()

            check = wave20_gate.check_reference_exploit(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("missing=True", check["message"])

    def test_wave20_rejects_direct_database_shell_and_note_owner_route_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave20_tree(Path(tmp))
            exploit = root / wave20_gate.EXPLOIT_PATH
            exploit.write_text(
                exploit.read_text(encoding="utf-8") + "\nimport sqlite3\nfrom subprocess import run\nGET /api/cases/{case_id}/notes\n",
                encoding="utf-8",
            )

            check = wave20_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("sqlite3", check["message"])
        self.assertIn("subprocess", check["message"])
        self.assertIn("/api/cases/{case_id}/notes", check["message"])

    def test_wave20_rejects_public_attack_data_secret_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave20_tree(Path(tmp))
            exploit = root / wave20_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nleak = attack_data.get('session')\n", encoding="utf-8")

            check = wave20_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("public attack-data secret lookup", check["message"])

    def test_wave20_rejects_import_time_service_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave20_tree(Path(tmp))
            exploit = root / wave20_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nrun_exploit('127.0.0.1', '8080', {}, 1.0)\n", encoding="utf-8")

            check = wave20_gate.check_exploit_cli_import_safety(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("run_exploit", check["message"])

    def test_wave20_rejects_nonstandard_exploits_and_reference_fixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave20_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_future.py").write_text("print('too early')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "aml_future.patch").write_text("fix too early\n", encoding="utf-8")

            check = wave20_gate.check_no_later_exploits_or_fixes(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_future.py", check["message"])
        self.assertIn("aml_future.patch", check["message"])

    def test_wave20_requires_make_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave20_tree(Path(tmp))
            (root / "Makefile").write_text("competition-matrix-gate:\n\tpython -B scripts/check_competition_matrix_gate.py\n", encoding="utf-8")

            check = wave20_gate.check_makefile_wave20_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave20-gate", check["message"])

    def test_wave20_make_target_requires_archive_hygiene_after_compile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave20_tree(Path(tmp))
            makefile = root / "Makefile"
            makefile.write_text(
                makefile.read_text(encoding="utf-8").replace("\n\t$(PYTHON) -B scripts/check_archive_hygiene.py\n", "\n"),
                encoding="utf-8",
            )

            check = wave20_gate.check_makefile_wave20_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("check_archive_hygiene.py", check["message"])


class FakeAML2Service:
    def __init__(self, leaked_flag, raw_diff_only=False):
        self.leaked_flag = leaked_flag
        self.raw_diff_only = raw_diff_only
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
            self.write_json(handler, 200, {"activities": [self.timeline_event()]})
            return
        self.write_json(handler, 404, {"error": "not_found"})

    def timeline_event(self):
        if self.leaked_flag is None:
            return {
                "id": 9001,
                "object_type": "case_note",
                "object_id": 7001,
                "event_type": "created",
                "public_message": "review context updated",
                "activity_narrative": "Review context updated",
                "activity_detail_level": "related_view",
                "changes": [{"field": "restricted_field", "new": "[REDACTED]", "redacted": True}],
            }
        change = {"field": "activity_narrative", "new": f"analyst note {self.leaked_flag}", "redacted": False}
        event = {
            "id": 9001,
            "object_type": "case_note",
            "object_id": 7001,
            "event_type": "created",
            "public_message": "review context updated",
            "activity_narrative": f"analyst note {self.leaked_flag}",
            "activity_detail_level": "collaborator_detail",
            "activity_provenance": "review_context_excerpt",
            "changes": [] if self.raw_diff_only else [change],
        }
        if self.raw_diff_only:
            event["diff_json"] = json.dumps([change], sort_keys=True)
        return event

    def write_json(self, handler, status, payload):
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(raw)


def fake_aml2_service(leaked_flag, raw_diff_only=False):
    return FakeAML2Service(leaked_flag, raw_diff_only=raw_diff_only)


def minimal_wave20_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave20_gate.py",
        "sploits/sentinel_aml/aml_dedup_preview.py",
        "sploits/sentinel_aml/aml_audit_timeline.py",
        "sploits/sentinel_aml/aml_related_graph.py",
        "sploits/sentinel_aml/aml_export_redaction.py",
        "sploits/sentinel_aml/aml_network_room.py",
        "sploits/sentinel_aml/README.md",
        "fixes/sentinel_aml/README.md",
        "fixes/sentinel_aml/aml_dedup_preview.patch",
        "fixes/sentinel_aml/aml_audit_timeline.patch",
        "fixes/sentinel_aml/aml_related_graph.patch",
        "fixes/sentinel_aml/aml_export_redaction.patch",
        "fixes/sentinel_aml/aml_network_room.patch",
        "docs/wave_reports/wave_20_W20-T01_handoff.md",
        "docs/wave_reports/wave_20_W20-T02_handoff.md",
        "docs/wave_reports/wave_20_W20-F01_handoff.md",
        "Makefile",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


if __name__ == "__main__":
    unittest.main()
