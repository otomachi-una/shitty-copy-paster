import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_player_package_runtime.py"

spec = importlib.util.spec_from_file_location("check_player_package_runtime", SCRIPT_PATH)
player_runtime = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(player_runtime)

HYGIENE_SCRIPT_PATH = ROOT / "scripts" / "check_player_bundle_hygiene.py"
hygiene_spec = importlib.util.spec_from_file_location("check_player_bundle_hygiene", HYGIENE_SCRIPT_PATH)
player_hygiene = importlib.util.module_from_spec(hygiene_spec)
assert hygiene_spec.loader is not None
hygiene_spec.loader.exec_module(player_hygiene)


class PlayerPackageRuntimeTest(unittest.TestCase):
    def test_package_env_uses_offline_vendor_mode(self):
        env = player_runtime.package_env({}, "/tmp/cache", "/tmp/appdata")

        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["GOFLAGS"], "-mod=vendor")
        self.assertEqual(env["GOTELEMETRY"], "off")
        self.assertEqual(env["GOCACHE"], "/tmp/cache")
        self.assertEqual(env["APPDATA"], "/tmp/appdata")

    def test_package_env_bridges_http_gateway_port_to_windows_tools_under_wsl(self):
        env = player_runtime.package_env(
            {"WSLENV": "PATH/p"},
            "/tmp/cache",
            "/tmp/appdata",
            "http://127.0.0.1:18080",
        )

        self.assertEqual(env["SENTINEL_AML_HTTP_PORT"], "18080")
        self.assertIn("DATABASE_URL", env["WSLENV"])
        self.assertIn("SENTINEL_AML_HTTP_PORT", env["WSLENV"])

    def test_runtime_proof_status_satisfies_source_readiness_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            for relative in ("go.mod", "go.sum", "vendor/modules.txt", "Dockerfile", "deploy/compose.yaml"):
                write_file(candidate, relative, "runtime input\n")

            player_runtime.write_runtime_proof(candidate, elapsed=1.25)
            result = player_hygiene.validate_player_bundle(candidate, require_runtime_ready=True)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_runtime_proof_runs_build_compose_smoke_and_readiness_phases(self):
        calls = []
        original_build = player_runtime.build_player_bundle.build_player_candidate
        original_validate = player_runtime.check_player_bundle_hygiene.validate_player_bundle
        original_run_command = player_runtime.run_command
        original_smoke = player_runtime.runtime_smoke.run_runtime_smoke

        def fake_build(output_dir, allowlist_path):
            output_dir.mkdir(parents=True)
            write_file(output_dir, "PACKAGING_STATUS.json", "{}\n")
            return {"file_count": 7}

        def fake_validate(candidate, allowlist_path=None, *, require_runtime_ready=False):
            calls.append(("validate", require_runtime_ready))
            return {"status": "pass", "checks": []}

        def fake_run_command(command, *, cwd, env, timeout):
            if command[:2] == ["docker", "compose"]:
                self.assertTrue((Path(cwd) / ".env").exists())
            calls.append(("run", tuple(command), Path(cwd).name, env["GOFLAGS"], timeout))
            return subprocess.CompletedProcess(command, 0, "", "")

        def fake_smoke(repo_root, **kwargs):
            calls.append(("smoke", Path(repo_root).name, kwargs["migrate_package"], kwargs["compose_file"].as_posix()))
            return 0

        player_runtime.build_player_bundle.build_player_candidate = fake_build
        player_runtime.check_player_bundle_hygiene.validate_player_bundle = fake_validate
        player_runtime.run_command = fake_run_command
        player_runtime.runtime_smoke.run_runtime_smoke = fake_smoke
        try:
            with tempfile.TemporaryDirectory() as tmp:
                with open(Path(tmp) / "stdout.txt", "w", encoding="utf-8") as stdout:
                    with open(Path(tmp) / "stderr.txt", "w", encoding="utf-8") as stderr:
                        result = player_runtime.run_player_package_runtime(
                            Path(tmp) / "candidate",
                            allowlist_path=Path(tmp) / "allow.json",
                            go="go",
                            docker="docker",
                            database_url="postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable",
                            base_url="http://127.0.0.1:18080",
                            skip_if_docker_unavailable=False,
                            stdout=stdout,
                            stderr=stderr,
                        )
        finally:
            player_runtime.build_player_bundle.build_player_candidate = original_build
            player_runtime.check_player_bundle_hygiene.validate_player_bundle = original_validate
            player_runtime.run_command = original_run_command
            player_runtime.runtime_smoke.run_runtime_smoke = original_smoke

        self.assertEqual(result, 0)
        self.assertIn(("validate", False), calls)
        self.assertIn(("validate", True), calls)
        self.assertIn(("run", ("go", "test", "./..."), "candidate", "-mod=vendor", 120), calls)
        self.assertIn(
            ("run", ("go", "build", "./cmd/aml-api", "./cmd/aml-worker", "./cmd/aml-migrate"), "candidate", "-mod=vendor", 120),
            calls,
        )
        self.assertIn(
            ("run", ("docker", "compose", "--env-file", ".env", "-f", "deploy/compose.yaml", "config"), "candidate", "-mod=vendor", 30),
            calls,
        )
        self.assertIn(("smoke", "candidate", "./cmd/aml-migrate", "deploy/compose.yaml"), calls)
        self.assertIn(
            ("run", ("docker", "compose", "--env-file", ".env", "-f", "deploy/compose.yaml", "down", "--remove-orphans", "-v"), "candidate", "-mod=vendor", 30),
            calls,
        )

    def test_temporary_compose_env_is_removed_before_final_hygiene(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            candidate.mkdir()
            env_path = player_runtime.write_compose_env_file(candidate, "http://127.0.0.1:18080")
            self.assertEqual(env_path.read_text(encoding="utf-8"), "SENTINEL_AML_HTTP_PORT=18080\n")

            player_runtime.remove_compose_env_file(env_path)

            self.assertFalse(env_path.exists())


def write_file(candidate: Path, relative: str, content: str) -> None:
    path = candidate / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
