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
GATE_PATH = ROOT / "scripts" / "check_wave19_gate.py"
EXPLOIT_PATH = ROOT / "sploits" / "sentinel_aml" / "aml_dedup_preview.py"

gate_spec = importlib.util.spec_from_file_location("check_wave19_gate", GATE_PATH)
wave19_gate = importlib.util.module_from_spec(gate_spec)
assert gate_spec.loader is not None
gate_spec.loader.exec_module(wave19_gate)

exploit_spec = importlib.util.spec_from_file_location("aml_dedup_preview", EXPLOIT_PATH)
aml_dedup_preview = importlib.util.module_from_spec(exploit_spec)
assert exploit_spec.loader is not None
exploit_spec.loader.exec_module(aml_dedup_preview)


class Wave19GateTest(unittest.TestCase):
    def test_wave19_gate_current_branch_has_no_failures(self):
        result = wave19_gate.validate_wave19_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_exploit_exists_among_known_reference_scripts(self):
        scripts = sorted(path.name for path in (ROOT / "sploits" / "sentinel_aml").glob("*.py"))

        self.assertIn("aml_dedup_preview.py", scripts)
        self.assertTrue(set(f"sploits/sentinel_aml/{name}" for name in scripts).issubset(wave19_gate.KNOWN_EXPLOITS))
        self.assertTrue(EXPLOIT_PATH.is_file())

    def test_exploit_cli_help_is_available_without_service_request(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                aml_dedup_preview.parse_args(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("Exploit AML-1", stdout.getvalue())
        self.assertIn("attack_info", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_exploit_extracts_flag_over_normal_dedup_chain(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "CaseNote.body",
            "case_id": 5201,
            "customer_id": 1201,
            "matching_reference": "victim-shared-hint",
            "typology_hint": "counterparty-watchlist",
        }
        with fake_aml1_service("FLAG{dedup-preview-leak}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_dedup_preview.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{dedup-preview-leak}")
        self.assertEqual(stderr.getvalue(), "")
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("POST", "/api/auth/register"), paths)
        self.assertIn(("POST", "/api/auth/login"), paths)
        self.assertIn(("POST", "/api/customers"), paths)
        self.assertIn(("POST", "/api/transactions"), paths)
        self.assertIn(("GET", "/api/alerts/queue"), paths)
        self.assertIn(("POST", "/api/alerts/4201/claim"), paths)
        self.assertIn(("POST", "/api/alerts/4201/case"), paths)
        self.assertIn(("GET", "/api/cases/6201/duplicates"), paths)
        self.assertIn(("GET", "/api/cases/6201/duplicates/5201/merge-preview"), paths)

    def test_exploit_fails_safely_against_secure_preview(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "CaseNote.body",
            "case_id": 5201,
            "matching_reference": "victim-shared-hint",
        }
        with fake_aml1_service(None) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_dedup_preview.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found in match explanation", stderr.getvalue())

    def test_attack_data_requires_case_note_body_and_dedup_hint(self):
        with self.assertRaises(aml_dedup_preview.ExploitError):
            aml_dedup_preview.load_attack_data(json.dumps({"service": "sentinel_aml", "store": "EDDRecord", "case_id": 1}))
        with self.assertRaises(aml_dedup_preview.ExploitError):
            aml_dedup_preview.load_attack_data(json.dumps({"service": "sentinel_aml", "store": "CaseNote.body", "case_id": 1}))

    def test_wave19_rejects_missing_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave19_tree(Path(tmp))
            (root / wave19_gate.EXPLOIT_PATH).unlink()

            check = wave19_gate.check_reference_exploit(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("missing=True", check["message"])

    def test_wave19_rejects_direct_database_or_shell_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave19_tree(Path(tmp))
            exploit = root / wave19_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nimport sqlite3\nSELECT password FROM sessions\n", encoding="utf-8")

            check = wave19_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("sqlite3", check["message"])
        self.assertIn("SELECT ", check["message"])

    def test_wave19_rejects_shell_imports_without_command_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave19_tree(Path(tmp))
            exploit = root / wave19_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nfrom subprocess import run\n", encoding="utf-8")

            check = wave19_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("subprocess", check["message"])

    def test_wave19_rejects_import_time_service_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave19_tree(Path(tmp))
            exploit = root / wave19_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nrun_exploit('127.0.0.1', '8080', {}, 1.0)\n", encoding="utf-8")

            check = wave19_gate.check_exploit_cli_import_safety(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("run_exploit", check["message"])

    def test_wave19_rejects_public_attack_data_secret_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave19_tree(Path(tmp))
            exploit = root / wave19_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nleak = attack_data.get('password')\n", encoding="utf-8")

            check = wave19_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("public attack-data secret lookup", check["message"])

    def test_wave19_rejects_public_attack_data_secret_bracket_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave19_tree(Path(tmp))
            exploit = root / wave19_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nleak = attack_data['token']\n", encoding="utf-8")

            check = wave19_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("public attack-data secret lookup", check["message"])

    def test_wave19_rejects_unknown_exploits_and_fix_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave19_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "unexpected_exploit.py").write_text("print('too early')\n", encoding="utf-8")
            (root / "fixes" / "sentinel_aml" / "unexpected_fix.patch").write_text("fix too early\n", encoding="utf-8")

            check = wave19_gate.check_no_later_exploits_or_fixes(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("unexpected_exploit.py", check["message"])
        self.assertIn("unexpected_fix.patch", check["message"])

    def test_wave19_rejects_any_non_readme_fix_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave19_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "notes.txt").write_text("too early\n", encoding="utf-8")
            nested = root / "fixes" / "sentinel_aml" / "aml1_fix"
            nested.mkdir()
            (nested / "README.md").write_text("too early\n", encoding="utf-8")

            check = wave19_gate.check_no_later_exploits_or_fixes(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("notes.txt", check["message"])
        self.assertIn("aml1_fix", check["message"])

    def test_wave19_requires_make_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave19_tree(Path(tmp))
            (root / "Makefile").write_text("competition-matrix-gate:\n\tpython -B scripts/check_competition_matrix_gate.py\n", encoding="utf-8")

            check = wave19_gate.check_makefile_wave19_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave19-gate", check["message"])


class FakeAML1Service:
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
            self.write_json(handler, 201, {"id": 2201})
            return
        if (handler.command, handler.path) == ("POST", "/api/customers/2201/accounts"):
            self.write_json(handler, 201, {"id": 3201})
            return
        if (handler.command, handler.path) == ("POST", "/api/transactions"):
            self.write_json(handler, 201, {"id": 4101, "account_id": 3201})
            return
        if (handler.command, handler.path) == ("GET", "/api/alerts/queue"):
            self.write_json(handler, 200, {"alerts": [{"id": 4201, "transaction_id": 4101}]})
            return
        if (handler.command, handler.path) == ("POST", "/api/alerts/4201/claim"):
            self.write_json(handler, 200, {"id": 4201, "status": "CLAIMED"})
            return
        if (handler.command, handler.path) == ("POST", "/api/alerts/4201/case"):
            self.write_json(handler, 201, {"id": 6201, "dedup_hint": body.get("dedup_hint")})
            return
        if (handler.command, handler.path) == ("GET", "/api/cases/6201/duplicates"):
            self.write_json(handler, 200, {"candidates": [{"case_id": 5201, "public_summary": "victim"}]})
            return
        if (handler.command, handler.path) == ("GET", "/api/cases/6201/duplicates/5201/merge-preview"):
            candidate = {"case_id": 5201, "public_summary": "victim", "match_explanation": "public evidence"}
            if self.leaked_flag is not None:
                candidate["match_explanation"] = f"review context {self.leaked_flag}"
            self.write_json(handler, 200, {"source_case_id": 6201, "candidate": candidate})
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


def fake_aml1_service(leaked_flag):
    return FakeAML1Service(leaked_flag)


def minimal_wave19_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave19_gate.py",
        "sploits/sentinel_aml/aml_dedup_preview.py",
        "sploits/sentinel_aml/README.md",
        "fixes/sentinel_aml/README.md",
        "Makefile",
        "docs/09_vulnerability_matrix.md",
        "docs/13_roadmap.md",
        "docs/waves.md",
        "docs/15_risk_register.md",
        "docs/14_agent_execution_log.md",
        "docs/wave_reports/wave_19_W19-T01_handoff.md",
        "docs/wave_reports/wave_19_W19-T02_handoff.md",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


if __name__ == "__main__":
    unittest.main()
