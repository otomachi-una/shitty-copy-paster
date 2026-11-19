import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
sys.path.insert(0, str(TESTS_DIR))

from test_checker_check_workflow import FakeCheckServer, fake_check_service  # noqa: E402
from test_checker_get_workflow import CASE_ID, FRESH_TOKEN, FakeGetServer, fake_get_service  # noqa: E402
from test_checker_put_workflow import FakeSentinelAMLServer, fake_service  # noqa: E402


class CheckerFakeServerLifecycleTest(unittest.TestCase):
    def test_fake_http_servers_use_exit_safe_threading_defaults(self):
        for server_class in (FakeSentinelAMLServer, FakeGetServer, FakeCheckServer):
            with self.subTest(server=server_class.__name__):
                self.assertIs(server_class.daemon_threads, True)
                self.assertIs(server_class.block_on_close, False)

    def test_fake_http_server_contexts_close_serving_threads_after_requests(self):
        cases = (
            (fake_service, lambda server: self._get(f"{server.url}/api/alerts/queue")),
            (
                fake_get_service,
                lambda server: self._get(
                    f"{server.url}/api/cases/{CASE_ID}/notes",
                    headers={"Authorization": f"Bearer {FRESH_TOKEN}"},
                ),
            ),
            (fake_check_service, lambda server: self._get(f"{server.url}/healthz")),
        )

        for service_factory, request in cases:
            with self.subTest(service=service_factory.__name__):
                before_threads = set(threading.enumerate())
                with service_factory() as server:
                    request(server)
                    serve_thread = server._serve_thread
                    self.assertTrue(serve_thread.daemon)
                    self.assertTrue(serve_thread.is_alive())

                deadline = time.monotonic() + 2.0
                while serve_thread.is_alive() and time.monotonic() < deadline:
                    time.sleep(0.01)

                self.assertFalse(serve_thread.is_alive())
                leaked_non_daemon = [
                    thread
                    for thread in threading.enumerate()
                    if thread not in before_threads and thread is not threading.current_thread() and not thread.daemon
                ]
                self.assertEqual([], leaked_non_daemon)

    def _get(self, url, *, headers=None):
        request = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                self.assertEqual(response.headers.get("Connection"), "close")
                response.read()
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.headers.get("Connection"), "close")
            exc.read()
