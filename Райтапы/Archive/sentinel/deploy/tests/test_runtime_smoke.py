import importlib.util
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "runtime_smoke.py"

spec = importlib.util.spec_from_file_location("runtime_smoke", SCRIPT_PATH)
runtime_smoke = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(runtime_smoke)


class RuntimeSmokeTest(unittest.TestCase):
    def test_runtime_env_is_deterministic_and_archive_free(self):
        env = runtime_smoke.runtime_env({}, "postgres://example:5432/db", "/tmp/cache", "/tmp/appdata")

        self.assertEqual(env["DATABASE_URL"], "postgres://example:5432/db")
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["GOFLAGS"], "-mod=vendor")
        self.assertEqual(env["GOTELEMETRY"], "off")
        self.assertEqual(env["GOCACHE"], "/tmp/cache")
        self.assertEqual(env["APPDATA"], "/tmp/appdata")
        self.assertIn("DATABASE_URL", env["WSLENV"])

    def test_base_url_must_include_http_port_for_compose_env(self):
        with self.assertRaises(runtime_smoke.SmokeFailure):
            runtime_smoke.http_port_from_base_url("http://127.0.0.1")

    def test_wslenv_merge_preserves_existing_entries(self):
        merged = runtime_smoke.merge_wslenv("PATH/p:DATABASE_URL", ("DATABASE_URL", "SENTINEL_AML_HTTP_PORT"))

        self.assertEqual(merged, "PATH/p:DATABASE_URL:SENTINEL_AML_HTTP_PORT")

    def test_skip_mode_returns_77_when_docker_is_unavailable(self):
        original_run_command = runtime_smoke.run_command

        def unavailable(command, *, cwd, env, timeout):
            return subprocess.CompletedProcess(command, 1, "", "docker unavailable")

        runtime_smoke.run_command = unavailable
        try:
            with open(os.devnull, "w", encoding="utf-8") as stdout:
                with open(os.devnull, "w", encoding="utf-8") as stderr:
                    result = runtime_smoke.run_runtime_smoke(
                        ROOT,
                        go="go",
                        docker="docker",
                        database_url=runtime_smoke.DEFAULT_DATABASE_URL,
                        base_url=runtime_smoke.DEFAULT_BASE_URL,
                        skip_if_docker_unavailable=True,
                        stdout=stdout,
                        stderr=stderr,
                    )
        finally:
            runtime_smoke.run_command = original_run_command

        self.assertEqual(result, 77)

    def test_docker_unavailable_is_failure_without_skip_mode(self):
        original_run_command = runtime_smoke.run_command

        def unavailable(command, *, cwd, env, timeout):
            return subprocess.CompletedProcess(command, 1, "", "docker unavailable")

        runtime_smoke.run_command = unavailable
        try:
            with open(os.devnull, "w", encoding="utf-8") as stdout:
                with open(os.devnull, "w", encoding="utf-8") as stderr:
                    result = runtime_smoke.run_runtime_smoke(
                        ROOT,
                        go="go",
                        docker="docker",
                        database_url=runtime_smoke.DEFAULT_DATABASE_URL,
                        base_url=runtime_smoke.DEFAULT_BASE_URL,
                        skip_if_docker_unavailable=False,
                        stdout=stdout,
                        stderr=stderr,
                    )
        finally:
            runtime_smoke.run_command = original_run_command

        self.assertEqual(result, 1)

    def test_base_url_must_have_explicit_http_port(self):
        with self.assertRaises(runtime_smoke.SmokeFailure):
            runtime_smoke.bind_host_port("http://127.0.0.1")
        with self.assertRaises(runtime_smoke.SmokeFailure):
            runtime_smoke.bind_host_port("https://127.0.0.1:18080")

    def test_compose_file_can_target_player_candidate_template(self):
        self.assertEqual(
            runtime_smoke.docker_compose_command("docker", Path("deploy/compose.yaml"), "config", "--services", env_file=Path(".env")),
            ["docker", "compose", "--env-file", ".env", "-f", "deploy/compose.yaml", "config", "--services"],
        )
        self.assertEqual(
            runtime_smoke.docker_compose_command("docker", None, "up", "-d", "postgres"),
            ["docker", "compose", "up", "-d", "postgres"],
        )

    def test_script_documents_required_runtime_workflow_without_debug_routes(self):
        text = SCRIPT_PATH.read_text(encoding="utf-8")
        compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        required = [
            "docker compose",
            "./scripts/migrate",
            "./cmd/aml-api",
            "./cmd/aml-worker",
            "--once",
            "worker-network-room-materialize",
            "deterministic network room",
            "/healthz",
            "/api/auth/register",
            "/api/customers",
            "/api/transactions",
            "/api/alerts/queue",
            "/api/cases/{case_id}/notes",
            "/api/customers/{customer_id}/edd",
            "/api/network/rooms",
        ]
        missing = [marker for marker in required if marker not in text]

        self.assertEqual(missing, [])
        self.assertNotIn("SENTINEL_AML_POSTGRES_PORT", compose_text)
        self.assertNotIn(":5432", compose_text)
        self.assertNotIn("/api/debug", text)
        self.assertNotIn("/api/admin", text)


if __name__ == "__main__":
    unittest.main()
