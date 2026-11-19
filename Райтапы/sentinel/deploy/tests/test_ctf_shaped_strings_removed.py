import importlib.util
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_player_source_hygiene.py"

spec = importlib.util.spec_from_file_location("check_player_source_hygiene", SCRIPT_PATH)
player_hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = player_hygiene
spec.loader.exec_module(player_hygiene)


BASE_FILES = {
    "README.md": "Sentinel AML player source package.\n",
    "TROUBLESHOOTING.md": "Build locally with Go.\n",
    "Makefile": "test:\n\tgo test ./...\n",
    "Dockerfile": "FROM scratch\nRUN go build ./cmd/aml-api\nCOPY web/dist /usr/share/nginx/html\n",
    "docker-compose.yml": "services:\n  api:\n    build:\n      context: .\n",
    "go.mod": "module sentinel-aml\n",
    "go.sum": "",
    "cmd/aml-api/main.go": "package main\nfunc main() {}\n",
    "cmd/aml-worker/main.go": "package main\nfunc main() {}\n",
    "cmd/aml-migrate/main.go": "package main\nfunc main() {}\n",
    "internal/httpapi/server.go": "package httpapi\n",
    "migrations/000001_create_users_sessions.sql": "CREATE TABLE users (id bigint);\n",
    "web/dist/index.html": "<title>Sentinel AML</title><script src=\"/runtime-config.js\"></script><script type=\"module\" src=\"/assets/index.js\"></script>\n",
    "web/dist/runtime-config.js": "window.__SENTINEL_CONFIG__ = { apiBaseUrl: \"\" };\n",
    "web/dist/assets/index.js": "console.log('Sentinel AML');\n",
    "deploy/player.env.example": "DATABASE_URL=postgres://example\n",
    "vendor/modules.txt": "# vendored modules\n",
}


class CTFShapedStringsRemovedTest(unittest.TestCase):
    def test_exact_spoiler_labels_fail_player_artifact(self):
        for token in ("flag_value", "secret_for_checker", "checker_private"):
            with self.subTest(token=token):
                with tempfile.TemporaryDirectory() as tmp:
                    artifact = Path(tmp) / "player.tar.gz"
                    write_player_artifact(artifact, {"internal/httpapi/server.go": f"package httpapi\nconst Field = {token!r}\n"})

                    result = player_hygiene.check_player_source_hygiene(artifact)

                self.assertEqual(result["status"], "fail")
                self.assertTrue(any(finding["token"] == token for finding in result["findings"]))

    def test_vendor_and_go_cli_flag_usage_are_the_only_expected_flag_allowlists(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "player.tar.gz"
            write_player_artifact(
                artifact,
                {
                    "cmd/aml-api/main.go": 'package main\nimport "flag"\nfunc main() { _ = flag.String("listen", "", "") }\n',
                    "cmd/aml-worker/main.go": 'package main\nimport "flag"\nfunc main() { _ = flag.String("queue", "", "") }\n',
                    "vendor/example/module.go": 'package example\nconst Name = "flag"\n',
                },
            )

            result = player_hygiene.check_player_source_hygiene(artifact)

        self.assertEqual(result["status"], "pass")
        self.assertGreaterEqual(result["allowlisted_hit_count"], 3)


def write_player_artifact(path: Path, overrides: dict[str, str]) -> None:
    files = dict(BASE_FILES)
    files.update(overrides)
    with tarfile.open(path, "w:gz") as archive:
        for relative, content in sorted(files.items()):
            data = content.encode("utf-8")
            info = tarfile.TarInfo(f"{player_hygiene.ARCHIVE_ROOT}/{relative}")
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    unittest.main()
