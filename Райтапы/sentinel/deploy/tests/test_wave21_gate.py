import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
import threading


ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts" / "check_wave21_gate.py"
EXPLOIT_PATH = ROOT / "sploits" / "sentinel_aml" / "aml_related_graph.py"

gate_spec = importlib.util.spec_from_file_location("check_wave21_gate", GATE_PATH)
wave21_gate = importlib.util.module_from_spec(gate_spec)
assert gate_spec.loader is not None
gate_spec.loader.exec_module(wave21_gate)

exploit_spec = importlib.util.spec_from_file_location("aml_related_graph", EXPLOIT_PATH)
aml_related_graph = importlib.util.module_from_spec(exploit_spec)
assert exploit_spec.loader is not None
exploit_spec.loader.exec_module(aml_related_graph)


class Wave21AML3ExploitTest(unittest.TestCase):
    def test_wave21_gate_current_branch_has_no_failures(self):
        result = wave21_gate.validate_wave21_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_exploit_cli_help_is_available_without_service_request(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                aml_related_graph.parse_args(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("Exploit AML-3", stdout.getvalue())
        self.assertIn("attack_info", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_attack_data_requires_place2_public_edd_record_and_entity_hint(self):
        valid = {
            "service": "sentinel_aml",
            "store": "EDDRecord",
            "customer_id": 2201,
            "entity_hint": "aml3-shared-entity",
            "typology_hint": "counterparty-watchlist",
        }
        self.assertEqual(aml_related_graph.load_attack_data(json.dumps(valid))["entity_hint"], "aml3-shared-entity")

        bad_inputs = [
            {"service": "sentinel_aml", "store": "CaseNote.body", "customer_id": 1, "entity_hint": "x"},
            {"service": "other_service", "store": "EDDRecord", "customer_id": 1, "entity_hint": "x"},
            {"service": "sentinel_aml", "store": "EDDRecord", "customer_id": 1},
            {"service": "sentinel_aml", "store": "EDDRecord", "entity_hint": "x"},
            {"service": "sentinel_aml", "store": "EDDRecord.confidential_comment", "customer_id": 1, "entity_hint": "x"},
        ]
        for payload in bad_inputs:
            with self.subTest(payload=payload):
                with self.assertRaises(aml_related_graph.ExploitError):
                    aml_related_graph.load_attack_data(json.dumps(payload))

    def test_attack_data_rejects_credential_like_public_fields(self):
        for key in ("username", "password", "token", "session", "flag", "checker_secret", "private_state", "confidential_comment"):
            payload = {
                "service": "sentinel_aml",
                "store": "EDDRecord",
                "customer_id": 2201,
                "entity_hint": "aml3-shared-entity",
                key: "forbidden",
            }
            with self.subTest(key=key):
                with self.assertRaises(aml_related_graph.ExploitError):
                    aml_related_graph.load_attack_data(json.dumps(payload))

        with self.assertRaises(aml_related_graph.ExploitError):
            aml_related_graph.load_attack_data(
                json.dumps(
                    {
                        "service": "sentinel_aml",
                        "store": "EDDRecord",
                        "customer_id": 2201,
                        "entity_hint": "aml3-shared-entity",
                        "typology_hint": "FLAG{should-not-be-public-data}",
                    }
                )
            )

    def test_exploit_extracts_flag_from_vulnerable_graph_edd_summary(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "EDDRecord",
            "customer_id": 2201,
            "entity_hint": "aml3-shared-entity",
            "typology_hint": "counterparty-watchlist",
        }
        with fake_aml3_service("FLAG{related-graph-edd-leak}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_related_graph.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{related-graph-edd-leak}")
        self.assertEqual(stderr.getvalue(), "")
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("POST", "/api/auth/register"), paths)
        self.assertIn(("POST", "/api/auth/login"), paths)
        self.assertIn(("POST", "/api/customers"), paths)
        self.assertIn(("GET", "/api/graph/entities/aml3-shared-entity/edd-summaries"), paths)
        forbidden_paths = [path for _method, path in paths if path.startswith("/api/customers/") and path.endswith("/edd")]
        self.assertEqual(forbidden_paths, [])

    def test_exploit_fails_safely_against_secure_metadata_only_graph_response(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "EDDRecord",
            "customer_id": 2201,
            "entity_hint": "aml3-shared-entity",
        }
        with fake_aml3_service(None) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_related_graph.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found", stderr.getvalue())

    def test_exploit_import_is_safe(self):
        spec = importlib.util.spec_from_file_location("aml_related_graph_import_safety", EXPLOIT_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network at import")):
            spec.loader.exec_module(module)

    def test_exploit_source_uses_only_graph_edd_summary_side_view(self):
        text = EXPLOIT_PATH.read_text(encoding="utf-8")
        required = [
            "argparse",
            "urllib.request",
            "EDDRecord",
            "entity_hint",
            "/api/auth/register",
            "/api/auth/login",
            "/api/customers",
            "/api/graph/entities/{quoted_hint}/edd-summaries",
            "assessment_summary",
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
            "/api/customers/{customer_id}/edd",
            "/api/cases/",
            "/timeline",
            "/api/disputes",
            "/api/network",
            "SELECT ",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
        ]
        lowered = text.lower()
        for marker in forbidden:
            self.assertNotIn(marker.lower(), lowered)

    def test_wave21_rejects_missing_aml3_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave21_tree(Path(tmp))
            (root / wave21_gate.EXPLOIT_PATH).unlink()

            check = wave21_gate.check_reference_exploits(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("missing=True", check["message"])

    def test_wave21_rejects_later_exploits_and_reference_fixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave21_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_export_redaction.py").write_text("print('too early')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "aml_related_graph.patch").write_text("fix too early\n", encoding="utf-8")

            check = wave21_gate.check_no_later_exploits_or_fixes(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_export_redaction.py", check["message"])
        self.assertIn("aml_related_graph.patch", check["message"])

    def test_wave21_rejects_direct_database_shell_debug_and_wrong_surface_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave21_tree(Path(tmp))
            exploit = root / wave21_gate.EXPLOIT_PATH
            exploit.write_text(
                exploit.read_text(encoding="utf-8")
                + "\nimport sqlite3\nfrom subprocess import run\n/api/customers/{customer_id}/edd\n/api/debug\n",
                encoding="utf-8",
            )

            check = wave21_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("sqlite3", check["message"])
        self.assertIn("subprocess", check["message"])
        self.assertIn("/api/customers/{customer_id}/edd", check["message"])
        self.assertIn("/api/debug", check["message"])

    def test_wave21_rejects_public_attack_data_secret_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave21_tree(Path(tmp))
            exploit = root / wave21_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nleak = attack_data.get('session')\n", encoding="utf-8")

            check = wave21_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("public attack-data secret lookup", check["message"])

    def test_wave21_rejects_import_time_service_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave21_tree(Path(tmp))
            exploit = root / wave21_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nrun_exploit('127.0.0.1', '8080', {}, 1.0)\n", encoding="utf-8")

            check = wave21_gate.check_exploit_cli_import_safety(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("run_exploit", check["message"])

    def test_wave21_requires_make_target_and_archive_hygiene(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave21_tree(Path(tmp))
            (root / "Makefile").write_text("competition-matrix-gate:\n\tpython -B scripts/check_competition_matrix_gate.py\n", encoding="utf-8")

            check = wave21_gate.check_makefile_wave21_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave21-gate", check["message"])


class FakeAML3Service:
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

        if (handler.command, handler.path) == ("POST", "/api/auth/register"):
            self.write_json(handler, 201, {"user": {"id": 1}, "session": {"token": "registration-token"}})
            return
        if (handler.command, handler.path) == ("POST", "/api/auth/login"):
            self.write_json(handler, 200, {"user": {"id": 1}, "session": {"token": "attacker-token"}})
            return
        if (handler.command, handler.path) == ("POST", "/api/customers"):
            self.write_json(handler, 201, {"id": 42, "entity_hint": body.get("entity_hint", "")})
            return
        if (handler.command, handler.path) == ("GET", "/api/graph/entities/aml3-shared-entity/edd-summaries"):
            self.write_json(handler, 200, self.graph_summaries())
            return
        self.write_json(handler, 404, {"error": "not_found"})

    def graph_summaries(self):
        summary = {
            "customer_id": 2201,
            "entity_hint": "aml3-shared-entity",
            "review_status": "IN_REVIEW",
            "risk_tags": ["risk_level:high"],
        }
        if self.leaked_flag is not None:
            summary["assessment_summary"] = f"victim EDD note {self.leaked_flag}"
        return {"summaries": [summary]}

    def write_json(self, handler, status, payload):
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(raw)


def fake_aml3_service(leaked_flag):
    return FakeAML3Service(leaked_flag)


def minimal_wave21_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave21_gate.py",
        "sploits/sentinel_aml/aml_dedup_preview.py",
        "sploits/sentinel_aml/aml_audit_timeline.py",
        "sploits/sentinel_aml/aml_related_graph.py",
        "sploits/sentinel_aml/README.md",
        "fixes/sentinel_aml/README.md",
        "docs/wave_reports/wave_21_W21-T01_handoff.md",
        "docs/wave_reports/wave_21_W21-T02_handoff.md",
        "Makefile",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


if __name__ == "__main__":
    unittest.main()
