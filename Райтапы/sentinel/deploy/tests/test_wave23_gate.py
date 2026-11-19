import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts" / "check_wave23_gate.py"
EXPLOIT_PATH = ROOT / "sploits" / "sentinel_aml" / "aml_network_room.py"

gate_spec = importlib.util.spec_from_file_location("check_wave23_gate", GATE_PATH)
wave23_gate = importlib.util.module_from_spec(gate_spec)
assert gate_spec.loader is not None
gate_spec.loader.exec_module(wave23_gate)

exploit_spec = importlib.util.spec_from_file_location("aml_network_room", EXPLOIT_PATH)
aml_network_room = importlib.util.module_from_spec(exploit_spec)
assert exploit_spec.loader is not None
exploit_spec.loader.exec_module(aml_network_room)


class Wave23AML5ExploitTest(unittest.TestCase):
    def test_wave23_gate_current_branch_has_no_failures(self):
        result = wave23_gate.validate_wave23_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_exploit_cli_help_is_available_without_service_request(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                aml_network_room.parse_args(["--help"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("Exploit AML-5", stdout.getvalue())
        self.assertIn("attack_info", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_attack_data_accepts_json_file_and_nested_place2_payload(self):
        payload = {
            "attack_data": {
                "service": "sentinel_aml",
                "store": "EDDRecord",
                "customer_id": 8801,
                "entity_hint": "aml5-shared-watchlist",
                "typology_hint": "enhanced-due-diligence",
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "attack.json"
            path.write_text(json.dumps(payload), encoding="utf-8")

            loaded = aml_network_room.load_attack_data(str(path))

        self.assertEqual(loaded["customer_id"], 8801)
        self.assertEqual(loaded["entity_hint"], "aml5-shared-watchlist")

    def test_attack_data_rejects_wrong_or_incomplete_locator_data(self):
        bad_inputs = [
            {"service": "sentinel_aml", "store": "CaseNote.body", "customer_id": 1, "entity_hint": "x", "typology_hint": "enhanced-due-diligence"},
            {"service": "other_service", "store": "EDDRecord", "customer_id": 1, "entity_hint": "x", "typology_hint": "enhanced-due-diligence"},
            {"service": "sentinel_aml", "store": "EDDRecord", "entity_hint": "x", "typology_hint": "enhanced-due-diligence"},
            {"service": "sentinel_aml", "store": "EDDRecord", "customer_id": 1, "typology_hint": "enhanced-due-diligence"},
            {"service": "sentinel_aml", "store": "EDDRecord", "customer_id": 1, "entity_hint": "x"},
        ]
        for payload in bad_inputs:
            with self.subTest(payload=payload):
                with self.assertRaises(aml_network_room.ExploitError):
                    aml_network_room.load_attack_data(json.dumps(payload))

    def test_attack_data_rejects_credential_confidential_and_flag_like_public_data(self):
        for key in ("username", "password", "token", "session", "flag", "checker_secret", "private_state", "confidential_comment"):
            payload = valid_attack_data()
            payload[key] = "forbidden"
            with self.subTest(key=key):
                with self.assertRaises(aml_network_room.ExploitError):
                    aml_network_room.load_attack_data(json.dumps(payload))

        payload = valid_attack_data()
        payload["typology_hint"] = "FLAG{should-not-be-public-data}"
        with self.assertRaises(aml_network_room.ExploitError):
            aml_network_room.load_attack_data(json.dumps(payload))

    def test_exploit_extracts_flag_from_vulnerable_network_room_dossier_fields(self):
        with fake_aml5_service(valid_attack_data(), "FLAG{network-room-leak}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_network_room.main([server.host, str(server.port), json.dumps(valid_attack_data()), "--timeout", "2"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{network-room-leak}")
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
            ("GET", "/api/network/rooms"),
            ("POST", "/api/network/rooms/901/join"),
            ("GET", "/api/network/rooms/901/dossier"),
        ):
            self.assertIn(expected, paths)

        forbidden_fragments = (
            "/api/cases/",
            "/api/graph/",
            "/api/exports",
            "/api/disputes",
            "/api/debug",
            "/api/admin",
            "/api/customers/{customer_id}/edd",
        )
        for _method, path in paths:
            for fragment in forbidden_fragments:
                self.assertNotIn(fragment, path)

    def test_exploit_fails_safely_when_dossier_is_redacted(self):
        with fake_aml5_service(valid_attack_data(), None) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = aml_network_room.main([server.host, str(server.port), json.dumps(valid_attack_data()), "--timeout", "2"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found", stderr.getvalue())

    def test_exploit_import_is_safe(self):
        spec = importlib.util.spec_from_file_location("aml_network_room_import_safety", EXPLOIT_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network at import")):
            spec.loader.exec_module(module)

    def test_exploit_text_scope_has_no_owner_and_debug_primitives(self):
        text = EXPLOIT_PATH.read_text(encoding="utf-8")
        required = [
            "argparse",
            "urllib.request",
            "/api/auth/register",
            "/api/auth/login",
            "/api/customers",
            "/api/transactions",
            "/api/alerts/queue",
            "/api/alerts",
            "/api/network/rooms",
            "/api/network/rooms/{room_id}/join",
            "/api/network/rooms/{room_id}/dossier",
            "context_blocks",
            "evaluation_blocks",
            "extract_flag_from_dossier",
            "if __name__ == \"__main__\":",
            "raise SystemExit(main())",
        ]
        for marker in required:
            self.assertIn(marker, text)

        forbidden = [
            "SELECT ",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "os.system",
            "subprocess",
            "sqlite3",
            "DATABASE_URL",
            "/api/debug",
            "/api/admin",
            "/api/graph",
            "/api/exports",
            "/api/disputes",
            "SELECT *",
            "/api/cases/",
            "/api/customers/{customer_id}/edd",
            "/api/cases/{case_id}/timeline",
            "/api/cases/{case_id}/notes",
        ]
        lowered = text.lower()
        for marker in forbidden:
            self.assertNotIn(marker.lower(), lowered)

    def test_wave23_rejects_missing_aml5_exploit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave23_tree(Path(tmp))
            (root / wave23_gate.EXPLOIT_PATH).unlink()

            check = wave23_gate.check_reference_exploits(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("missing=True", check["message"])

    def test_wave23_rejects_extra_exploit_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave23_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_unplanned.py").write_text("print('extra')\n", encoding="utf-8")

            check = wave23_gate.check_reference_exploits(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_unplanned.py", check["message"])

    def test_wave23_rejects_reference_fix_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave23_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_network_room.patch").write_text("fix too early\n", encoding="utf-8")

            check = wave23_gate.check_no_reference_fixes(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_network_room.patch", check["message"])

    def test_wave23_rejects_direct_database_shell_debug_and_cross_surface_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave23_tree(Path(tmp))
            exploit = root / wave23_gate.EXPLOIT_PATH
            exploit.write_text(
                exploit.read_text(encoding="utf-8")
                + "\nimport sqlite3\nfrom subprocess import run\n# /api/debug\n# /api/graph/entities\n# /api/disputes\n",
                encoding="utf-8",
            )

            check = wave23_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("sqlite3", check["message"])
        self.assertIn("subprocess", check["message"])
        self.assertIn("/api/debug", check["message"])
        self.assertIn("/api/graph/entities", check["message"])
        self.assertIn("/api/disputes", check["message"])

    def test_wave23_rejects_wrong_network_room_side_view_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave23_tree(Path(tmp))
            exploit = root / wave23_gate.EXPLOIT_PATH
            exploit.write_text(
                exploit.read_text(encoding="utf-8").replace(
                    "/api/network/rooms/{room_id}/dossier",
                    "/api/network/rooms/{room_id}/cases",
                ),
                encoding="utf-8",
            )

            check = wave23_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("/api/network/rooms/{room_id}/dossier", check["message"])
        self.assertIn("/api/network/rooms/{room_id}/cases", check["message"])

    def test_wave23_rejects_public_attack_data_secret_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave23_tree(Path(tmp))
            exploit = root / wave23_gate.EXPLOIT_PATH
            exploit.write_text(
                exploit.read_text(encoding="utf-8") + "\ndef leak_from_public_data(attack_data):\n    return attack_data.get('session')\n",
                encoding="utf-8",
            )

            check = wave23_gate.check_exploit_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("public attack-data secret lookup", check["message"])

    def test_wave23_rejects_import_time_service_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave23_tree(Path(tmp))
            exploit = root / wave23_gate.EXPLOIT_PATH
            exploit.write_text(exploit.read_text(encoding="utf-8") + "\nrun_exploit('127.0.0.1', '8080', {}, 1.0)\n", encoding="utf-8")

            check = wave23_gate.check_exploit_cli_import_safety(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("run_exploit", check["message"])

    def test_wave23_requires_make_target_and_archive_hygiene(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave23_tree(Path(tmp))
            (root / "Makefile").write_text("competition-matrix-gate:\n\tpython -B scripts/check_competition_matrix_gate.py\n", encoding="utf-8")

            check = wave23_gate.check_makefile_wave23_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("wave23-gate", check["message"])
        self.assertIn("scripts/check_archive_hygiene.py", check["message"])


class FakeAML5Service:
    def __init__(self, attack_data: dict, leaked_flag: str | None):
        self.attack_data = attack_data
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
            ("POST", "/api/customers"): (201, {"id": 101, "entity_hint": body.get("entity_hint", "")}),
            ("POST", "/api/customers/101/accounts"): (201, {"id": 201}),
            ("POST", "/api/transactions"): (201, {"id": 301}),
            ("GET", "/api/alerts/queue"): (200, {"alerts": [{"id": 501, "transaction_id": 301}]}),
            ("POST", "/api/alerts/501/claim"): (200, {"id": 501}),
            ("POST", "/api/alerts/501/case"): (201, {"id": 601}),
        }

        status, payload = responses.get((handler.command, handler.path), (None, None))
        if status is not None:
            self.write_json(handler, status, payload)
            return

        if handler.path.startswith("/api/network/rooms/") and handler.path.endswith("/join") and handler.command == "POST":
            self.write_json(handler, 201, {"id": 701, "room_id": 901, "participant_role": "observer"})
            return

        if handler.path == "/api/network/rooms":
            if handler.command != "GET":
                self.write_json(handler, 405, {"error": "method_not_allowed"})
                return
            self.write_json(
                handler,
                200,
                {
                    "rooms": [
                        {
                            "id": 901,
                            "entity_hint": self.attack_data["entity_hint"],
                            "typology_hint": "counterparty-watchlist",
                            "status": "OPEN",
                            "public_summary": "AML5 counterparty room",
                        }
                    ]
                },
            )
            return

        if handler.path == "/api/network/rooms/901/dossier" and handler.command == "GET":
            if self.leaked_flag is None:
                self.write_json(
                    handler,
                    200,
                    {
                        "room": {"id": 901},
                        "cases": [
                            {
                                "case_id": 401,
                                "customer_id": 999,
                                "owned_by_requester": False,
                                "context_blocks": [],
                                "evaluation_blocks": [],
                                "scope_policy": "participant_room_context",
                                "coverage_policy": "shared_case_context",
                            }
                        ],
                    },
                )
                return

            self.write_json(
                handler,
                200,
                {
                    "room": {"id": 901},
                    "cases": [
                        {
                            "case_id": 401,
                            "customer_id": 999,
                            "owned_by_requester": False,
                            "context_blocks": [
                                {"block_id": 1001, "case_id": 401, "content": "suspicious note"},
                                {"block_id": 1002, "case_id": 401, "content": f"victim note {self.leaked_flag}"},
                            ],
                            "evaluation_blocks": [
                                {"block_id": 2011, "customer_id": 999, "content": f"review {self.leaked_flag}"}
                            ],
                        }
                    ],
                    "scope_policy": "participant_room_context",
                    "coverage_policy": "shared_case_context",
                },
            )
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


def valid_attack_data():
    return {
        "service": "sentinel_aml",
        "store": "EDDRecord",
        "customer_id": 8801,
        "entity_hint": "aml5-shared-watchlist",
        "typology_hint": "enhanced-due-diligence",
    }


def fake_aml5_service(attack_data: dict, leaked_flag):
    return FakeAML5Service(attack_data, leaked_flag)


def minimal_wave23_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave23_gate.py",
        "sploits/sentinel_aml/aml_dedup_preview.py",
        "sploits/sentinel_aml/aml_audit_timeline.py",
        "sploits/sentinel_aml/aml_related_graph.py",
        "sploits/sentinel_aml/aml_export_redaction.py",
        "sploits/sentinel_aml/aml_network_room.py",
        "sploits/sentinel_aml/README.md",
        "fixes/sentinel_aml/README.md",
        "docs/wave_reports/wave_23_W23-T01_handoff.md",
        "docs/wave_reports/wave_23_W23-T02_handoff.md",
        "Makefile",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


if __name__ == "__main__":
    unittest.main()
