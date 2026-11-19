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
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts" / "check_wave22_gate.py"
EXPLOIT_PATH = ROOT / "sploits" / "sentinel_aml" / "aml_export_redaction.py"

gate_spec = importlib.util.spec_from_file_location("check_wave22_gate", GATE_PATH)
wave22_gate = importlib.util.module_from_spec(gate_spec)
assert gate_spec.loader is not None
gate_spec.loader.exec_module(wave22_gate)

exploit_spec = importlib.util.spec_from_file_location("aml_export_redaction", EXPLOIT_PATH)
aml_export_redaction = importlib.util.module_from_spec(exploit_spec)
assert exploit_spec.loader is not None
exploit_spec.loader.exec_module(aml_export_redaction)


class Wave22AML4ExploitTest(unittest.TestCase):
    def test_wave22_gate_current_branch_has_no_failures(self):
        result = wave22_gate.validate_wave22_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_exploit_cli_help_is_available_without_service_request(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                aml_export_redaction.parse_args(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("Exploit AML-4", stdout.getvalue())
        self.assertIn("attack_info", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_attack_data_accepts_json_file_and_nested_public_case_note_locator(self):
        payload = {
            "attack_data": {
                "service": "sentinel_aml",
                "store": "CaseNote.body",
                "case_id": 4201,
                "customer_id": 3201,
                "dedup_hint": "aml4-shared-export-hint",
                "typology_hint": "regulatory-export",
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "attack.json"
            path.write_text(json.dumps(payload), encoding="utf-8")

            loaded = aml_export_redaction.load_attack_data(str(path))

        self.assertEqual(loaded["case_id"], 4201)
        self.assertEqual(loaded["dedup_hint"], "aml4-shared-export-hint")

    def test_attack_data_rejects_wrong_or_incomplete_locator_data(self):
        bad_inputs = [
            {"service": "sentinel_aml", "store": "EDDRecord", "case_id": 1, "dedup_hint": "x", "customer_id": 1},
            {"service": "other_service", "store": "CaseNote.body", "case_id": 1, "dedup_hint": "x", "customer_id": 1},
            {"service": "sentinel_aml", "store": "CaseNote.body", "dedup_hint": "x", "customer_id": 1},
            {"service": "sentinel_aml", "store": "CaseNote.body", "case_id": 1, "customer_id": 1},
            {"service": "sentinel_aml", "store": "CaseNote.body", "case_id": 1, "dedup_hint": "x"},
        ]
        for payload in bad_inputs:
            with self.subTest(payload=payload):
                with self.assertRaises(aml_export_redaction.ExploitError):
                    aml_export_redaction.load_attack_data(json.dumps(payload))

    def test_attack_data_rejects_credential_confidential_and_flag_like_public_data(self):
        for key in ("username", "password", "token", "session", "flag", "checker_secret", "private_state", "confidential_comment"):
            payload = valid_attack_data()
            payload[key] = "forbidden"
            with self.subTest(key=key):
                with self.assertRaises(aml_export_redaction.ExploitError):
                    aml_export_redaction.load_attack_data(json.dumps(payload))

        payload = valid_attack_data()
        payload["typology_hint"] = "FLAG{should-not-be-public-data}"
        with self.assertRaises(aml_export_redaction.ExploitError):
            aml_export_redaction.load_attack_data(json.dumps(payload))

    def test_exploit_extracts_flag_from_vulnerable_export_readback(self):
        with fake_aml4_service("FLAG{export-linked-note-leak}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_export_redaction.main([server.host, str(server.port), json.dumps(valid_attack_data()), "--timeout", "2"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{export-linked-note-leak}")
        self.assertEqual(stderr.getvalue(), "")
        paths = [(request["method"], request["path"]) for request in server.requests]
        for expected in (
            ("POST", "/api/auth/register"),
            ("POST", "/api/auth/login"),
            ("POST", "/api/customers"),
            ("POST", "/api/customers/101/accounts"),
            ("POST", "/api/transactions"),
            ("GET", "/api/alerts/queue"),
            ("POST", "/api/alerts/501/claim"),
            ("POST", "/api/alerts/501/case"),
            ("POST", "/api/disputes"),
            ("POST", "/api/disputes/701/export"),
            ("GET", "/api/exports/801"),
        ):
            self.assertIn(expected, paths)
        forbidden_path_fragments = ("/notes", "/edd", "/timeline", "/graph/", "/network/")
        self.assertEqual([path for _method, path in paths if any(fragment in path for fragment in forbidden_path_fragments)], [])

    def test_exploit_fails_safely_against_secure_redacted_export(self):
        with fake_aml4_service(None) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_export_redaction.main([server.host, str(server.port), json.dumps(valid_attack_data()), "--timeout", "2"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found", stderr.getvalue())

    def test_exploit_import_is_safe(self):
        spec = importlib.util.spec_from_file_location("aml_export_redaction_import_safety", EXPLOIT_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network at import")):
            spec.loader.exec_module(module)

    def test_exploit_source_uses_only_export_dispute_side_view(self):
        text = EXPLOIT_PATH.read_text(encoding="utf-8")
        required = [
            "argparse",
            "urllib.request",
            "CaseNote.body",
            "case_id",
            "dedup_hint",
            "/api/auth/register",
            "/api/auth/login",
            "/api/customers",
            "/api/disputes",
            "/api/disputes/{dispute_id}/export",
            "/api/exports/{export_id}",
            "linked_private_notes",
            "body",
            "extract_flag",
            "if __name__ == \"__main__\":",
            "raise SystemExit(main())",
        ]
        for marker in required:
            self.assertIn(marker, text)

        forbidden = [
            "sqlite3",
            "psycopg",
            "pymysql",
            "subprocess",
            "os.system",
            "popen",
            "DATABASE_URL",
            "checker_private",
            "/api/debug",
            "/api/admin",
            "/debug",
            "/admin",
            "/api/cases/{case_id}/notes",
            "/api/customers/{customer_id}/edd",
            "/api/cases/{case_id}/timeline",
            "/api/graph/entities",
            "/api/network/rooms",
            "SELECT ",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
        ]
        lowered = text.lower()
        for marker in forbidden:
            self.assertNotIn(marker.lower(), lowered)

    def test_wave22_rejects_missing_aml4_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave22_tree(Path(tmp))
            (root / wave22_gate.EXPLOIT_PATH).unlink()

            check = wave22_gate.check_reference_exploits(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("missing=True", check["message"])

    def test_wave22_rejects_premature_aml5_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave22_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_network_room.py").write_text("print('too early')\n", encoding="utf-8")

            check = wave22_gate.check_reference_exploits(root)
            later = wave22_gate.check_no_later_exploits_or_fixes(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.py", check["message"])
        self.assertEqual(later["status"], "fail")
        self.assertIn("aml_network_room.py", later["message"])

    def test_wave22_rejects_reference_fix_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave22_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_export_redaction.patch").write_text("fix too early\n", encoding="utf-8")

            check = wave22_gate.check_no_later_exploits_or_fixes(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_export_redaction.patch", check["message"])

    def test_wave22_rejects_direct_database_shell_debug_and_wrong_surface_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave22_tree(Path(tmp))
            exploit = root / wave22_gate.EXPLOIT_PATH
            exploit.write_text(
                exploit.read_text(encoding="utf-8")
                + "\nimport sqlite3\nfrom subprocess import run\n/api/cases/{case_id}/notes\n/api/debug\n/api/graph/entities\n",
                encoding="utf-8",
            )

            check = wave22_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("sqlite3", check["message"])
        self.assertIn("subprocess", check["message"])
        self.assertIn("/api/cases/{case_id}/notes", check["message"])
        self.assertIn("/api/debug", check["message"])
        self.assertIn("/api/graph/entities", check["message"])

    def test_wave22_rejects_public_attack_data_secret_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave22_tree(Path(tmp))
            exploit = root / wave22_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nleak = attack_data.get('session')\n", encoding="utf-8")

            check = wave22_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("public attack-data secret lookup", check["message"])

    def test_wave22_rejects_import_time_service_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave22_tree(Path(tmp))
            exploit = root / wave22_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nrun_exploit('127.0.0.1', '8080', {}, 1.0)\n", encoding="utf-8")

            check = wave22_gate.check_exploit_cli_import_safety(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("run_exploit", check["message"])

    def test_wave22_requires_make_target_and_archive_hygiene(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave22_tree(Path(tmp))
            (root / "Makefile").write_text("competition-matrix-gate:\n\tpython -B scripts/check_competition_matrix_gate.py\n", encoding="utf-8")

            check = wave22_gate.check_makefile_wave22_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave22-gate", check["message"])


class FakeAML4Service:
    def __init__(self, leaked_flag):
        self.leaked_flag = leaked_flag
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

        responses = {
            ("POST", "/api/auth/register"): (201, {"user": {"id": 1}, "session": {"token": "registration-token"}}),
            ("POST", "/api/auth/login"): (200, {"user": {"id": 1}, "session": {"token": "attacker-token"}}),
            ("POST", "/api/customers"): (201, {"id": 101}),
            ("POST", "/api/customers/101/accounts"): (201, {"id": 201}),
            ("POST", "/api/transactions"): (201, {"id": 301}),
            ("GET", "/api/alerts/queue"): (200, {"alerts": [{"id": 501, "transaction_id": 301}]}),
            ("POST", "/api/alerts/501/claim"): (200, {"id": 501}),
            ("POST", "/api/alerts/501/case"): (201, {"id": 601}),
            ("POST", "/api/disputes"): (201, {"id": 701, "case_id": body.get("case_id", 0), "status": "OPEN"}),
            ("POST", "/api/disputes/701/export"): (201, {"id": 801, "root_case_id": 601, "dispute_id": 701, "bundle": {"linked_cases": [{"case_id": 4201}]}}),
            ("GET", "/api/exports/801"): (200, self.export_readback()),
        }
        status, payload = responses.get((handler.command, handler.path), (404, {"error": "not_found"}))
        self.write_json(handler, status, payload)

    def export_readback(self):
        bundle = {
            "purpose": "regulatory_report",
            "redaction_policy": "public",
            "root_case": {"case_id": 601},
            "linked_cases": [{"case_id": 4201, "public_summary": "victim public shell"}],
            "audit_summaries": [],
            "edd_summaries": [],
            "items": [],
        }
        if self.leaked_flag is not None:
            bundle["linked_private_notes"] = [{"case_id": 4201, "note_id": 901, "body": f"victim linked note {self.leaked_flag}"}]
        return {"id": 801, "root_case_id": 601, "dispute_id": 701, "purpose": "regulatory_report", "bundle": bundle}

    def write_json(self, handler, status, payload):
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(raw)


def valid_attack_data():
    return {
        "service": "sentinel_aml",
        "store": "CaseNote.body",
        "case_id": 4201,
        "customer_id": 3201,
        "dedup_hint": "aml4-shared-export-hint",
        "typology_hint": "regulatory-export",
    }


def fake_aml4_service(leaked_flag):
    return FakeAML4Service(leaked_flag)


def minimal_wave22_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave22_gate.py",
        "sploits/sentinel_aml/aml_dedup_preview.py",
        "sploits/sentinel_aml/aml_audit_timeline.py",
        "sploits/sentinel_aml/aml_related_graph.py",
        "sploits/sentinel_aml/aml_export_redaction.py",
        "sploits/sentinel_aml/README.md",
        "fixes/sentinel_aml/README.md",
        "docs/wave_reports/wave_22_W22-T01_handoff.md",
        "docs/wave_reports/wave_22_W22-T02_handoff.md",
        "Makefile",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


if __name__ == "__main__":
    unittest.main()
