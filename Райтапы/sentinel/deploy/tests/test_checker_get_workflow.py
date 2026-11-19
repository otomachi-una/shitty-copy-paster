import base64
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


SECRET = "get-workflow-secret"
FLAG = "FLAG{owner-note-get}"
WRONG_FLAG = "FLAG{wrong-owner-note-get}"
PLACE2_FLAG = "FLAG{owner-edd-get}"
CASE_ID = 505
CUSTOMER_ID = 101
NOTE_ID = 606
EDD_RECORD_ID = 909
FRESH_TOKEN = "fresh-owner-token"
P1_FIXTURE = checker_lib._place1_fixture_values(checker_lib.derive_idempotency_key(FLAG, checker_lib.PLACE_1, SECRET), SECRET)
P2_FIXTURE = checker_lib._place2_fixture_values(checker_lib.derive_idempotency_key(PLACE2_FLAG, checker_lib.PLACE_2, SECRET), SECRET)


SIDE_VIEW_PREFIXES = (
    "/api/cases/",
    "/api/graph/",
    "/api/exports",
    "/api/network/",
)
SIDE_VIEW_SUFFIXES = (
    "/duplicates",
    "/timeline",
    "/exports",
    "/merge-preview",
)


class FakeGetHandler(http.server.BaseHTTPRequestHandler):
    server_version = "FakeSentinelAMLGet/1.0"
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.server.handle_request(self)

    def do_GET(self):
        self.server.handle_request(self)

    def log_message(self, format, *args):
        return


class FakeGetServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        *,
        notes=None,
        login_status=200,
        notes_status=200,
        first_notes_status=None,
        notes_error=None,
        edd_record=None,
        edd_status=200,
        first_edd_status=None,
        edd_error=None,
    ):
        super().__init__(("127.0.0.1", 0), FakeGetHandler)
        self.requests = []
        self.notes = notes if notes is not None else [{"id": NOTE_ID, "case_id": CASE_ID, "body": FLAG}]
        self.login_status = login_status
        self.notes_status = notes_status
        self.first_notes_status = first_notes_status
        self.notes_error = notes_error or {"error": "not_found"}
        self.notes_calls = 0
        self.edd_record = edd_record if edd_record is not None else {
            "id": EDD_RECORD_ID,
            "customer_id": CUSTOMER_ID,
            "confidential_comment": PLACE2_FLAG,
            "review_status": "IN_REVIEW",
        }
        self.edd_status = edd_status
        self.first_edd_status = first_edd_status
        self.edd_error = edd_error or {"error": "not_found"}
        self.edd_calls = 0

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
        request = {
            "method": handler.command,
            "path": handler.path,
            "body": body,
            "authorization": handler.headers.get("Authorization", ""),
        }
        self.requests.append(request)

        if _is_side_view(handler.path):
            self.write_json(handler, 500, {"error": "side_view_must_not_be_called"})
            return

        if (handler.command, handler.path) == ("POST", "/api/auth/login"):
            valid_credentials = (
                {"username": P1_FIXTURE["username"], "password": P1_FIXTURE["password"]},
                {"username": P2_FIXTURE["username"], "password": P2_FIXTURE["password"]},
            )
            if self.login_status != 200 or body not in valid_credentials:
                self.write_json(handler, self.login_status, {"error": "invalid_credentials"})
                return
            self.write_json(handler, 200, {"session": {"token": FRESH_TOKEN}})
            return

        if (handler.command, handler.path) == ("GET", f"/api/cases/{CASE_ID}/notes"):
            self.notes_calls += 1
            if self.notes_calls == 1 and self.first_notes_status is not None:
                self.write_json(handler, self.first_notes_status, {"error": "unauthenticated"})
                return
            if handler.headers.get("Authorization") != f"Bearer {FRESH_TOKEN}":
                self.write_json(handler, 401, {"error": "unauthenticated"})
                return
            if self.notes_status != 200:
                self.write_json(handler, self.notes_status, self.notes_error)
                return
            self.write_json(handler, 200, {"notes": self.notes})
            return

        if (handler.command, handler.path) == ("GET", f"/api/customers/{CUSTOMER_ID}/edd"):
            self.edd_calls += 1
            if self.edd_calls == 1 and self.first_edd_status is not None:
                self.write_json(handler, self.first_edd_status, {"error": "unauthenticated"})
                return
            if handler.headers.get("Authorization") != f"Bearer {FRESH_TOKEN}":
                self.write_json(handler, 401, {"error": "unauthenticated"})
                return
            if self.edd_status != 200:
                self.write_json(handler, self.edd_status, self.edd_error)
                return
            self.write_json(handler, 200, self.edd_record)
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
        handler.wfile.flush()
        handler.close_connection = True


def _is_side_view(path):
    if path.startswith("/api/graph/") or path.startswith("/api/network/") or path.startswith("/api/exports"):
        return True
    if path.startswith("/api/customers/") and (
        path.endswith("/timeline") or path.endswith("/exports") or path.endswith("/duplicates")
    ):
        return True
    return path.startswith("/api/cases/") and any(path.endswith(suffix) for suffix in SIDE_VIEW_SUFFIXES)


@contextlib.contextmanager
def fake_get_service(**kwargs):
    server = FakeGetServer(**kwargs)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.05),
        daemon=True,
        name="checker-get-fake-httpd",
    )
    server._serve_thread = thread
    thread.start()
    try:
        yield server
    finally:
        stop_fake_server(server, thread)


def stop_fake_server(server, thread):
    try:
        server.shutdown()
    finally:
        server.server_close()
    thread.join(timeout=2)
    if thread.is_alive():
        raise AssertionError(f"{thread.name} did not stop after server shutdown")


def encoded_state(flag=FLAG, secret=SECRET):
    state = checker_lib.Place1PrivateState(
        schema_version=checker_lib.PRIVATE_STATE_SCHEMA_VERSION,
        service=checker_lib.SERVICE_NAME,
        store=checker_lib.PLACE_1_STORE,
        place=checker_lib.PLACE_1,
        customer_id=CUSTOMER_ID,
        case_id=CASE_ID,
        note_id=NOTE_ID,
        entity_hint="checker-p1-get-entity",
        dedup_hint="checker-p1-get-dedup",
        typology_hint="large-value-transfer",
        idempotency_key=checker_lib.derive_idempotency_key(flag, checker_lib.PLACE_1, secret),
    )
    return checker_lib.encode_private_state(state, secret)


def encoded_place2_state(flag=PLACE2_FLAG, secret=SECRET):
    state = checker_lib.Place2PrivateState(
        schema_version=checker_lib.PRIVATE_STATE_SCHEMA_VERSION,
        service=checker_lib.SERVICE_NAME,
        store=checker_lib.PLACE_2_STORE,
        place=checker_lib.PLACE_2,
        customer_id=CUSTOMER_ID,
        edd_record_id=EDD_RECORD_ID,
        entity_hint="checker-p2-get-entity",
        typology_hint="enhanced-due-diligence",
        idempotency_key=checker_lib.derive_idempotency_key(flag, checker_lib.PLACE_2, secret),
    )
    return checker_lib.encode_private_state(state, secret)


class CheckerGetWorkflowTest(unittest.TestCase):
    def test_successful_get_logs_in_and_reads_owner_notes_only(self):
        state = encoded_state()
        with fake_get_service() as server:
            checker_lib.place1_get(server.url, state, FLAG, secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertEqual(
            paths,
            [
                ("POST", "/api/auth/login"),
                ("GET", f"/api/cases/{CASE_ID}/notes"),
            ],
        )
        self.assertEqual(server.requests[0]["body"], {"username": P1_FIXTURE["username"], "password": P1_FIXTURE["password"]})
        self.assertEqual(server.requests[1]["authorization"], f"Bearer {FRESH_TOKEN}")
        self.assert_no_side_views(server.requests)

    def test_successful_get_does_not_require_stored_owner_token(self):
        state = encoded_state()
        with fake_get_service() as server:
            checker_lib.place1_get(server.url, state, FLAG, secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertEqual(paths, [("POST", "/api/auth/login"), ("GET", f"/api/cases/{CASE_ID}/notes")])
        self.assert_no_side_views(server.requests)

    def test_wrong_flag_is_detected_before_http(self):
        state = encoded_state()
        with fake_get_service() as server:
            with self.assertRaises(checker_lib.StateIntegrityError):
                checker_lib.place1_get(server.url, state, WRONG_FLAG, secret=SECRET, timeout=2.0)

        self.assertEqual(server.requests, [])

    def test_note_body_mismatch_is_corrupt(self):
        state = encoded_state()
        notes = [{"id": NOTE_ID, "case_id": CASE_ID, "body": "not-the-flag"}]
        with fake_get_service(notes=notes) as server:
            with self.assertRaises(checker_lib.ServiceCorruptError):
                checker_lib.place1_get(server.url, state, FLAG, secret=SECRET, timeout=2.0)

        self.assert_no_side_views(server.requests)

    def test_tampered_private_state_fails_before_http(self):
        state = encoded_state()
        envelope = json.loads(base64.urlsafe_b64decode(state + "=" * (-len(state) % 4)).decode("utf-8"))
        envelope["payload"]["note_id"] = NOTE_ID + 1
        tampered = base64.urlsafe_b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")

        with fake_get_service() as server:
            with self.assertRaises(checker_lib.StateIntegrityError):
                checker_lib.place1_get(server.url, tampered, FLAG, secret=SECRET, timeout=2.0)

        self.assertEqual(server.requests, [])

    def test_missing_case_or_note_view_is_corrupt(self):
        state = encoded_state()
        with fake_get_service(notes_status=404) as server:
            with self.assertRaises(checker_lib.ServiceCorruptError):
                checker_lib.place1_get(server.url, state, FLAG, secret=SECRET, timeout=2.0)

        self.assert_no_side_views(server.requests)

    def test_missing_note_is_corrupt(self):
        state = encoded_state()
        with fake_get_service(notes=[]) as server:
            with self.assertRaises(checker_lib.ServiceCorruptError):
                checker_lib.place1_get(server.url, state, FLAG, secret=SECRET, timeout=2.0)

        self.assert_no_side_views(server.requests)

    def test_auth_failure_fails_without_side_views(self):
        state = encoded_state()
        with fake_get_service(first_notes_status=401, login_status=401) as server:
            with self.assertRaises(checker_lib.HTTPStatusError) as caught:
                checker_lib.place1_get(server.url, state, FLAG, secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.status, 401)
        self.assert_no_side_views(server.requests)

    def test_side_view_error_text_does_not_leak_from_checker_output(self):
        state = encoded_state()
        stderr = io.StringIO()
        stdout = io.StringIO()
        previous_secret = os.environ.get(checker_lib.CHECKER_SECRET_ENV)
        os.environ[checker_lib.CHECKER_SECRET_ENV] = SECRET
        with fake_get_service(notes_status=500, notes_error={"error": FLAG}) as server:
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = checker.main(["checker.py", "get", server.url, state, FLAG, "1"])
            finally:
                if previous_secret is None:
                    os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
                else:
                    os.environ[checker_lib.CHECKER_SECRET_ENV] = previous_secret

        self.assertEqual(exit_code, checker_lib.EXIT_MUMBLE)
        self.assertNotIn(FLAG, stderr.getvalue())
        self.assertNotIn(state, stderr.getvalue())
        self.assert_no_side_views(server.requests)

    def test_place2_get_remains_deferred(self):
        """Historical Wave 11 marker; Wave 12 now verifies owner EDD GET."""
        private_state = encoded_place2_state()
        parsed = checker_lib.parse_checker_args(["checker.py", "get", "127.0.0.1", private_state, FLAG, "2"])
        self.assertEqual(parsed.place, checker_lib.PLACE_2)

    def test_successful_place2_get_logs_in_before_owner_edd(self):
        state = encoded_place2_state()
        with fake_get_service() as server:
            checker_lib.place2_get(server.url, state, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertEqual(paths, [("POST", "/api/auth/login"), ("GET", f"/api/customers/{CUSTOMER_ID}/edd")])
        self.assertEqual(server.requests[1]["authorization"], f"Bearer {FRESH_TOKEN}")
        self.assert_no_side_views(server.requests)

    def test_successful_place2_get_reads_owner_edd_only(self):
        state = encoded_place2_state()
        with fake_get_service() as server:
            checker_lib.place2_get(server.url, state, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertEqual(
            paths,
            [
                ("POST", "/api/auth/login"),
                ("GET", f"/api/customers/{CUSTOMER_ID}/edd"),
            ],
        )
        self.assertEqual(server.requests[0]["body"], {"username": P2_FIXTURE["username"], "password": P2_FIXTURE["password"]})
        self.assertEqual(server.requests[1]["authorization"], f"Bearer {FRESH_TOKEN}")
        self.assert_no_side_views(server.requests)

    def test_checker_cli_get_place2_outputs_ok(self):
        state = encoded_place2_state()
        stdout = io.StringIO()
        stderr = io.StringIO()
        previous_secret = os.environ.get(checker_lib.CHECKER_SECRET_ENV)
        os.environ[checker_lib.CHECKER_SECRET_ENV] = SECRET
        with fake_get_service() as server:
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = checker.main(["checker.py", "get", server.url, state, PLACE2_FLAG, "2"])
            finally:
                if previous_secret is None:
                    os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
                else:
                    os.environ[checker_lib.CHECKER_SECRET_ENV] = previous_secret

        self.assertEqual(exit_code, checker_lib.EXIT_OK, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "")
        self.assertEqual(stderr.getvalue().strip(), "")
        self.assert_no_side_views(server.requests)

    def test_place2_get_wrong_flag_fails_before_http(self):
        private_state = encoded_place2_state()
        with fake_get_service() as server:
            with self.assertRaises(checker_lib.StateIntegrityError):
                checker_lib.place2_get(server.url, private_state, WRONG_FLAG, secret=SECRET, timeout=2.0)

        self.assertEqual(server.requests, [])

    def test_place2_get_tampered_state_fails_before_http(self):
        state = encoded_place2_state()
        envelope = json.loads(base64.urlsafe_b64decode(state + "=" * (-len(state) % 4)).decode("utf-8"))
        envelope["payload"]["edd_record_id"] = EDD_RECORD_ID + 1
        tampered = base64.urlsafe_b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")

        with fake_get_service() as server:
            with self.assertRaises(checker_lib.StateIntegrityError):
                checker_lib.place2_get(server.url, tampered, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        self.assertEqual(server.requests, [])

    def test_place2_missing_edd_view_is_corrupt(self):
        state = encoded_place2_state()
        with fake_get_service(edd_status=404) as server:
            with self.assertRaises(checker_lib.ServiceCorruptError):
                checker_lib.place2_get(server.url, state, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        self.assert_no_side_views(server.requests)

    def test_place2_missing_confidential_comment_is_corrupt(self):
        state = encoded_place2_state()
        with fake_get_service(edd_record={"id": EDD_RECORD_ID, "customer_id": CUSTOMER_ID}) as server:
            with self.assertRaises(checker_lib.ServiceCorruptError):
                checker_lib.place2_get(server.url, state, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        self.assert_no_side_views(server.requests)

    def test_place2_wrong_confidential_comment_is_corrupt(self):
        state = encoded_place2_state()
        with fake_get_service(
            edd_record={"id": EDD_RECORD_ID, "customer_id": CUSTOMER_ID, "confidential_comment": "not-the-flag"}
        ) as server:
            with self.assertRaises(checker_lib.ServiceCorruptError):
                checker_lib.place2_get(server.url, state, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        self.assert_no_side_views(server.requests)

    def test_place2_edd_identity_mismatch_is_corrupt(self):
        state = encoded_place2_state()
        with fake_get_service(
            edd_record={"id": EDD_RECORD_ID + 1, "customer_id": CUSTOMER_ID, "confidential_comment": PLACE2_FLAG}
        ) as server:
            with self.assertRaises(checker_lib.ServiceCorruptError):
                checker_lib.place2_get(server.url, state, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        self.assert_no_side_views(server.requests)

    def test_place2_auth_failure_fails_without_side_views(self):
        state = encoded_place2_state()
        with fake_get_service(first_edd_status=401, login_status=401) as server:
            with self.assertRaises(checker_lib.HTTPStatusError) as caught:
                checker_lib.place2_get(server.url, state, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.status, 401)
        self.assert_no_side_views(server.requests)

    def test_place2_bad_http_status_remains_mumble_without_side_views(self):
        state = encoded_place2_state()
        with fake_get_service(edd_status=500, edd_error={"error": PLACE2_FLAG}) as server:
            with self.assertRaises(checker_lib.HTTPStatusError) as caught:
                checker_lib.place2_get(server.url, state, PLACE2_FLAG, secret=SECRET, timeout=2.0)

        self.assertEqual(caught.exception.status, 500)
        self.assert_no_side_views(server.requests)

    def test_checker_cli_get_place2_does_not_leak_error_text(self):
        state = encoded_place2_state()
        stderr = io.StringIO()
        stdout = io.StringIO()
        previous_secret = os.environ.get(checker_lib.CHECKER_SECRET_ENV)
        os.environ[checker_lib.CHECKER_SECRET_ENV] = SECRET
        with fake_get_service(edd_status=500, edd_error={"error": PLACE2_FLAG}) as server:
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = checker.main(["checker.py", "get", server.url, state, PLACE2_FLAG, "2"])
            finally:
                if previous_secret is None:
                    os.environ.pop(checker_lib.CHECKER_SECRET_ENV, None)
                else:
                    os.environ[checker_lib.CHECKER_SECRET_ENV] = previous_secret

        self.assertEqual(exit_code, checker_lib.EXIT_MUMBLE)
        self.assertNotIn(PLACE2_FLAG, stderr.getvalue())
        self.assertNotIn(state, stderr.getvalue())
        self.assert_no_side_views(server.requests)

    def test_unknown_get_place_remains_unsupported(self):
        with self.assertRaises(checker_lib.UnsupportedPlaceError):
            checker_lib.parse_checker_args(["checker.py", "get", "127.0.0.1", "state", FLAG, "3"])

    def assert_no_side_views(self, requests):
        for request in requests:
            path = request["path"]
            self.assertFalse(path.startswith("/api/graph/"), path)
            self.assertFalse(path.startswith("/api/network/"), path)
            self.assertFalse(path.startswith("/api/exports"), path)
            if path.startswith("/api/customers/"):
                self.assertFalse(path.endswith("/timeline"), path)
                self.assertFalse(path.endswith("/exports"), path)
                self.assertFalse(path.endswith("/duplicates"), path)
            if path.startswith("/api/cases/"):
                for suffix in SIDE_VIEW_SUFFIXES:
                    self.assertFalse(path.endswith(suffix), path)


if __name__ == "__main__":
    unittest.main()
