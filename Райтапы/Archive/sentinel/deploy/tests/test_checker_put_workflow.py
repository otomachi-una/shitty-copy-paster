import contextlib
import http.server
import io
import json
import os
import sys
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER_DIR = ROOT / "checkers" / "sentinel_aml"
sys.path.insert(0, str(CHECKER_DIR))

import checker  # noqa: E402
import checker_lib  # noqa: E402


SECRET = "put-workflow-secret"
FLAG = "FLAG{place-one-private-note}"
PLACE2_FLAG = "FLAG{place-two-confidential-edd}"


class FakeSentinelAMLHandler(http.server.BaseHTTPRequestHandler):
    server_version = "FakeSentinelAML/1.0"
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.server.handle_request(self)

    def do_GET(self):
        self.server.handle_request(self)

    def log_message(self, format, *args):
        return


class FakeSentinelAMLServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, fail_route=None, fail_status=500, fail_body=None):
        super().__init__(("127.0.0.1", 0), FakeSentinelAMLHandler)
        self.requests = []
        self.fail_route = fail_route
        self.fail_status = fail_status
        self.fail_body = fail_body or {"error": "forced_failure"}
        self.login_token = "login-token-for-put"
        self.customer_id = 101
        self.account_id = 202
        self.transaction_id = 303
        self.alert_id = 404
        self.case_id = 505
        self.note_id = 606
        self.edd_record_id = 707

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(2.0)
        return request, client_address

    @property
    def url(self):
        host, port = self.server_address
        return f"http://{host}:{port}"

    def handle_request(self, handler):
        length = int(handler.headers.get("Content-Length", "0"))
        raw_body = handler.rfile.read(length) if length else b""
        body = json.loads(raw_body.decode("utf-8")) if raw_body else None
        self.requests.append(
            {
                "method": handler.command,
                "path": handler.path,
                "body": body,
                "authorization": handler.headers.get("Authorization", ""),
            }
        )

        if handler.path == self.fail_route:
            self.write_json(handler, self.fail_status, self.fail_body)
            return

        routes = {
            ("POST", "/api/auth/register"): (201, {"session": {"token": "register-token"}}),
            ("POST", "/api/auth/login"): (200, {"session": {"token": self.login_token}}),
            ("POST", "/api/customers"): (
                201,
                {
                    "id": self.customer_id,
                    "entity_hint": body.get("entity_hint") if body else "checker-entity",
                },
            ),
            ("POST", f"/api/customers/{self.customer_id}/accounts"): (201, {"id": self.account_id}),
            ("POST", "/api/transactions"): (201, {"id": self.transaction_id, "risk_score": 100}),
            (
                "GET",
                "/api/alerts/queue",
            ): (
                200,
                {
                    "alerts": [
                        {
                            "id": self.alert_id,
                            "transaction_id": self.transaction_id,
                            "customer_id": self.customer_id,
                            "typology_hint": "counterparty-watchlist",
                        }
                    ]
                },
            ),
            ("POST", f"/api/alerts/{self.alert_id}/claim"): (200, {"id": self.alert_id}),
            ("POST", f"/api/alerts/{self.alert_id}/case"): (
                201,
                {
                    "id": self.case_id,
                    "customer_id": self.customer_id,
                    "typology_hint": "counterparty-watchlist",
                },
            ),
            ("POST", f"/api/cases/{self.case_id}/notes"): (
                201,
                {"id": self.note_id, "case_id": self.case_id, "body": body.get("body") if body else ""},
            ),
            ("POST", f"/api/customers/{self.customer_id}/edd"): (
                201,
                {
                    "id": self.edd_record_id,
                    "customer_id": self.customer_id,
                    "source_of_funds": body.get("source_of_funds") if body else "",
                    "risk_rationale": body.get("risk_rationale") if body else "",
                    "confidential_comment": body.get("confidential_comment") if body else "",
                    "review_status": body.get("review_status") if body else "DRAFT",
                },
            ),
        }
        status, payload = routes.get((handler.command, handler.path), (404, {"error": "not_found"}))
        self.write_json(handler, status, payload)

    def write_json(self, handler, status, payload):
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(raw)
        handler.wfile.flush()
        handler.close_connection = True


def stop_fake_server(server, thread):
    try:
        server.shutdown()
    finally:
        server.server_close()
    thread.join(timeout=2)
    if thread.is_alive():
        raise AssertionError(f"{thread.name} did not stop after server shutdown")


@contextlib.contextmanager
def fake_service(**kwargs):
    server = FakeSentinelAMLServer(**kwargs)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.05),
        daemon=True,
        name="checker-put-fake-httpd",
    )
    server._serve_thread = thread
    thread.start()
    try:
        yield server
    finally:
        stop_fake_server(server, thread)


class CheckerPutWorkflowTest(unittest.TestCase):
    def test_place1_put_full_successful_route_sequence(self):
        with fake_service() as server:
            result = checker_lib.place1_put(server.url, FLAG, secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertEqual(
            paths,
            [
                ("POST", "/api/auth/register"),
                ("POST", "/api/auth/login"),
                ("POST", "/api/customers"),
                ("POST", f"/api/customers/{server.customer_id}/accounts"),
                ("POST", "/api/transactions"),
                ("GET", "/api/alerts/queue"),
                ("POST", f"/api/alerts/{server.alert_id}/claim"),
                ("POST", f"/api/alerts/{server.alert_id}/case"),
                ("POST", f"/api/cases/{server.case_id}/notes"),
            ],
        )

        for request in server.requests[2:]:
            self.assertEqual(request["authorization"], f"Bearer {server.login_token}")

        state = checker_lib.decode_private_state(result.private_state, SECRET)
        self.assertEqual(state.customer_id, server.customer_id)
        self.assertEqual(state.case_id, server.case_id)
        self.assertEqual(state.note_id, server.note_id)
        self.assertEqual(state.schema_version, checker_lib.PRIVATE_STATE_SCHEMA_VERSION)
        self.assert_no_credentials_in_state(result.private_state)
        self.assertEqual(state.typology_hint, "counterparty-watchlist")
        self.assertEqual(result.public_attack_data["entity_ref"], state.entity_hint)
        self.assertEqual(result.public_attack_data["party_ref"], state.entity_hint)
        self.assertEqual(result.public_attack_data["case_id"], server.case_id)
        self.assertEqual(result.public_attack_data["customer_id"], server.customer_id)

    def test_checker_cli_put_outputs_pfr_shape(self):
        previous_secret = os.environ.get(checker_lib.CHECKER_SECRET_ENV)
        os.environ[checker_lib.CHECKER_SECRET_ENV] = SECRET
        stdout = io.StringIO()
        stderr = io.StringIO()
        with fake_service() as server:
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = checker.main(["checker.py", "put", server.url, FLAG, "1"])
            finally:
                if previous_secret is None:
                    os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
                else:
                    os.environ[checker_lib.CHECKER_SECRET_ENV] = previous_secret

        self.assertEqual(exit_code, checker_lib.EXIT_OK, stderr.getvalue())
        public = json.loads(stdout.getvalue())
        private = stderr.getvalue().strip()
        state = checker_lib.decode_private_state(private, SECRET)
        self.assertEqual(state.case_id, server.case_id)
        self.assertEqual(state.note_id, server.note_id)
        self.assertEqual(public["case_id"], server.case_id)
        self.assertEqual(
            set(public),
            {
                "service",
                "case_ref",
                "case_id",
                "customer_ref",
                "customer_id",
                "entity_ref",
                "party_ref",
                "matching_reference",
            },
        )
        self.assert_no_credentials_in_state(private)
        public_text = checker_lib.canonical_json(public).lower()
        for forbidden in (FLAG.lower(), private.lower(), "store", "dedup_hint", "typology_hint", "entity_hint"):
            self.assertNotIn(forbidden, public_text)

    def test_flag_is_sent_only_to_private_case_note_request(self):
        with fake_service() as server:
            result = checker_lib.place1_put(server.url, FLAG, secret=SECRET, timeout=2.0)

        requests_with_flag = [request for request in server.requests if FLAG in json.dumps(request["body"], sort_keys=True)]
        self.assertEqual(len(requests_with_flag), 1)
        self.assertEqual(requests_with_flag[0]["path"], f"/api/cases/{server.case_id}/notes")
        self.assertEqual(requests_with_flag[0]["body"], {"body": FLAG, "visibility": "private"})

        public_text = checker_lib.canonical_json(result.public_attack_data)
        self.assertNotIn(FLAG, public_text)
        self.assertNotIn(result.private_state, public_text)

    def test_public_attack_data_omits_flag_and_credentials(self):
        with fake_service() as server:
            result = checker_lib.place1_put(server.url, FLAG, secret=SECRET, timeout=2.0)

        state = checker_lib.decode_private_state(result.private_state, SECRET)
        public_text = checker_lib.canonical_json(result.public_attack_data).lower()
        checker_lib.assert_public_attack_data_safe(result.public_attack_data)

        self.assert_no_credentials_in_state(result.private_state)
        for forbidden in (FLAG.lower(), SECRET):
            self.assertNotIn(forbidden, public_text)
        self.assertEqual(
            set(result.public_attack_data),
            {
                "service",
                "case_ref",
                "case_id",
                "customer_ref",
                "customer_id",
                "entity_ref",
                "party_ref",
                "matching_reference",
            },
        )

    def test_private_state_not_printed_in_public_attack_data(self):
        with fake_service() as server:
            result = checker_lib.place1_put(server.url, FLAG, secret=SECRET, timeout=2.0)

        state = checker_lib.decode_private_state(result.private_state, SECRET)
        self.assertEqual(state.case_id, server.case_id)
        self.assertNotIn(result.private_state, checker_lib.canonical_json(result.public_attack_data))

    def test_missing_intermediate_id_returns_checker_failure(self):
        with fake_service(fail_route="/api/customers", fail_status=201, fail_body={"display_name": "missing id"}) as server:
            with self.assertRaises(checker_lib.ServiceMumbleError):
                checker_lib.place1_put(server.url, FLAG, secret=SECRET, timeout=2.0)

    def test_failed_intermediate_response_returns_checker_failure(self):
        with fake_service(fail_route="/api/transactions", fail_status=500) as server:
            with self.assertRaises(checker_lib.HTTPStatusError) as caught:
                checker_lib.place1_put(server.url, FLAG, secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.status, 500)

    def test_place2_put_full_successful_route_sequence(self):
        with fake_service() as server:
            result = checker_lib.place2_put(server.url, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertEqual(
            paths,
            [
                ("POST", "/api/auth/register"),
                ("POST", "/api/auth/login"),
                ("POST", "/api/customers"),
                ("POST", f"/api/customers/{server.customer_id}/edd"),
                ("POST", f"/api/customers/{server.customer_id}/accounts"),
                ("POST", "/api/transactions"),
                ("GET", "/api/alerts/queue"),
                ("POST", f"/api/alerts/{server.alert_id}/claim"),
                ("POST", f"/api/alerts/{server.alert_id}/case"),
            ],
        )
        for request in server.requests[2:]:
            self.assertEqual(request["authorization"], f"Bearer {server.login_token}")

        state = checker_lib.decode_private_state(result.private_state, SECRET, expected_place=checker_lib.PLACE_2)
        self.assertEqual(state.customer_id, server.customer_id)
        self.assertEqual(state.edd_record_id, server.edd_record_id)
        self.assert_no_credentials_in_state(result.private_state)
        self.assertEqual(state.store, checker_lib.PLACE_2_STORE)
        self.assertEqual(state.typology_hint, "counterparty-watchlist")
        self.assertEqual(result.public_attack_data["customer_id"], server.customer_id)
        self.assertEqual(result.public_attack_data["entity_ref"], state.entity_hint)
        self.assertEqual(result.public_attack_data["party_ref"], state.entity_hint)

    def test_checker_cli_put_place2_outputs_pfr_shape(self):
        previous_secret = os.environ.get(checker_lib.CHECKER_SECRET_ENV)
        os.environ[checker_lib.CHECKER_SECRET_ENV] = SECRET
        stdout = io.StringIO()
        stderr = io.StringIO()
        with fake_service() as server:
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = checker.main(["checker.py", "put", server.url, PLACE2_FLAG, "2"])
            finally:
                if previous_secret is None:
                    os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
                else:
                    os.environ[checker_lib.CHECKER_SECRET_ENV] = previous_secret

        self.assertEqual(exit_code, checker_lib.EXIT_OK, stderr.getvalue())
        public = json.loads(stdout.getvalue())
        private = stderr.getvalue().strip()
        state = checker_lib.decode_private_state(private, SECRET, expected_place=checker_lib.PLACE_2)
        self.assertEqual(state.edd_record_id, server.edd_record_id)
        self.assertEqual(public["customer_id"], server.customer_id)
        self.assertEqual(set(public), {"service", "customer_ref", "customer_id", "entity_ref", "party_ref"})
        self.assert_no_credentials_in_state(private)
        public_text = checker_lib.canonical_json(public).lower()
        for forbidden in (
            PLACE2_FLAG.lower(),
            SECRET.lower(),
            private.lower(),
            "confidential_comment",
            "store",
            "typology_hint",
            "entity_hint",
        ):
            self.assertNotIn(forbidden, public_text)

    def test_place2_flag_is_sent_only_to_edd_confidential_comment_request(self):
        with fake_service() as server:
            result = checker_lib.place2_put(server.url, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        requests_with_flag = [request for request in server.requests if PLACE2_FLAG in json.dumps(request["body"], sort_keys=True)]
        self.assertEqual(len(requests_with_flag), 1)
        self.assertEqual(requests_with_flag[0]["path"], f"/api/customers/{server.customer_id}/edd")
        self.assertEqual(requests_with_flag[0]["body"]["confidential_comment"], PLACE2_FLAG)
        self.assertNotIn(PLACE2_FLAG, checker_lib.canonical_json(result.public_attack_data))
        self.assertNotIn(result.private_state, checker_lib.canonical_json(result.public_attack_data))

    def test_place2_public_attack_data_omits_flag_and_credentials(self):
        with fake_service() as server:
            result = checker_lib.place2_put(server.url, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        state = checker_lib.decode_private_state(result.private_state, SECRET, expected_place=checker_lib.PLACE_2)
        public_text = checker_lib.canonical_json(result.public_attack_data).lower()
        checker_lib.assert_public_attack_data_safe(result.public_attack_data)

        self.assert_no_credentials_in_state(result.private_state)
        for forbidden in (
            PLACE2_FLAG.lower(),
            SECRET.lower(),
            result.private_state.lower(),
            "session",
            "confidential_comment",
        ):
            self.assertNotIn(forbidden, public_text)
        self.assertEqual(set(result.public_attack_data), {"service", "customer_ref", "customer_id", "entity_ref", "party_ref"})

    def test_place2_missing_customer_hint_returns_checker_failure(self):
        with fake_service(fail_route="/api/customers", fail_status=201, fail_body={"id": 101}) as server:
            with self.assertRaises(checker_lib.ServiceMumbleError):
                checker_lib.place2_put(server.url, PLACE2_FLAG, secret=SECRET, timeout=2.0)

    def test_place2_missing_edd_id_returns_checker_failure(self):
        with fake_service(fail_route="/api/customers/101/edd", fail_status=201, fail_body={"customer_id": 101}) as server:
            with self.assertRaises(checker_lib.ServiceMumbleError):
                checker_lib.place2_put(server.url, PLACE2_FLAG, secret=SECRET, timeout=2.0)

    def test_place2_edd_customer_mismatch_returns_checker_failure(self):
        with fake_service(fail_route="/api/customers/101/edd", fail_status=201, fail_body={"id": 707, "customer_id": 999}) as server:
            with self.assertRaises(checker_lib.ServiceMumbleError):
                checker_lib.place2_put(server.url, PLACE2_FLAG, secret=SECRET, timeout=2.0)

    def test_place2_failed_intermediate_response_returns_checker_failure(self):
        with fake_service(fail_route="/api/customers/101/edd", fail_status=500) as server:
            with self.assertRaises(checker_lib.HTTPStatusError) as caught:
                checker_lib.place2_put(server.url, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.status, 500)

    def test_place2_put_remains_deferred(self):
        """Historical Wave 11 marker; Wave 12 now asserts place 2 dispatch."""
        parsed = checker_lib.parse_checker_args(["checker.py", "put", "127.0.0.1", FLAG, "2"])
        self.assertEqual(parsed.place, checker_lib.PLACE_2)

    def test_unknown_put_place_remains_unsupported(self):
        with self.assertRaises(checker_lib.UnsupportedPlaceError):
            checker_lib.parse_checker_args(["checker.py", "put", "127.0.0.1", FLAG, "3"])

    def assert_no_credentials_in_state(self, encoded_state):
        payload = json.loads(
            __import__("base64").urlsafe_b64decode(encoded_state + "=" * (-len(encoded_state) % 4)).decode("utf-8")
        )["payload"]
        self.assertFalse({"username", "password", "token", "session"} & set(payload))


if __name__ == "__main__":
    unittest.main()
