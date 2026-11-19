from __future__ import annotations

import gzip
import importlib.util
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


builder = load_script("build_player_source_artifact", ROOT / "scripts" / "build_player_source_artifact.py")
hygiene = load_script("check_player_source_hygiene", ROOT / "scripts" / "check_player_source_hygiene.py")
dual_policy = load_script("check_player_source_no_dual_policy", ROOT / "scripts" / "check_player_source_no_dual_policy.py")


class PlayerSourceHygieneTest(unittest.TestCase):
    ctf_shaped_terms = (
        "flag_value",
        "secret_for_checker",
        "checker_private",
        "flag_store",
        "putflag",
        "getflag",
        "attack_info",
        "public_attack_data",
        "aml1",
        "aml2",
        "aml3",
        "aml4",
        "aml5",
        "AML-1",
        "AML-2",
        "AML-3",
        "AML-4",
        "AML-5",
        "vulnerable",
        "exploit",
        "sploit",
        "reference_fix",
    )

    def test_generated_artifact_passes_hygiene(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sentinel-aml-player-source.tar.gz"
            builder.build_player_source_artifact(artifact)
            result = hygiene.check_player_source_hygiene(artifact)

        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(result["blocking_hit_count"], 0)
        self.assertGreaterEqual(result["allowlisted_hit_count"], 1)

    def test_generated_artifact_omits_ctf_shaped_vocabulary(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sentinel-aml-player-source.tar.gz"
            builder.build_player_source_artifact(artifact)
            hits = archive_token_hits(artifact, self.ctf_shaped_terms)

        self.assertEqual(hits, [])

    def test_hidden_checker_path_fails_hygiene(self):
        artifact, result = scan_fixture({"sentinel-aml-player-source/checkers/sentinel_aml/checker.py": "print('x')\n"})

        self.assertEqual(result["status"], "fail")
        self.assertFinding(result, token="checkers", path="checkers/sentinel_aml/checker.py")

    def test_hidden_sploit_path_fails_hygiene(self):
        artifact, result = scan_fixture({"sentinel-aml-player-source/sploits/sentinel_aml/probe.py": "print('x')\n"})

        self.assertTrue(artifact.is_file())
        self.assertEqual(result["status"], "fail")
        self.assertFinding(result, token="sploits", path="sploits/sentinel_aml/probe.py")

    def test_forbidden_token_in_source_fails_hygiene(self):
        _, result = scan_fixture({"sentinel-aml-player-source/internal/service/service.go": "package service\n\nconst leak = \"aml3 exploit\"\n"})

        self.assertEqual(result["status"], "fail")
        self.assertFinding(result, token="aml3", path="internal/service/service.go")
        self.assertFinding(result, token="exploit", path="internal/service/service.go")

    def test_dual_policy_pair_fails_hygiene_and_dual_checker(self):
        extra = {
            "sentinel-aml-player-source/internal/httpapi/audit_default.go": "package httpapi\n",
            "sentinel-aml-player-source/internal/httpapi/audit_detail.go": "package httpapi\n",
        }
        artifact, result = scan_fixture(extra)
        dual = dual_policy.check_no_dual_policy(artifact)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(dual["status"], "fail")
        self.assertFinding(result, token="default/detail")

    def test_build_tag_leak_fails_hygiene(self):
        _, result = scan_fixture({"sentinel-aml-player-source/internal/httpapi/build.go": "//go:build aml1_vulnerable\npackage httpapi\n"})

        self.assertEqual(result["status"], "fail")
        self.assertFinding(result, token="aml1", path="internal/httpapi/build.go")
        self.assertFinding(result, token="vulnerable", path="internal/httpapi/build.go")

    def test_legacy_redaction_literals_fail_hygiene(self):
        extra = {
            "sentinel-aml-player-source/cmd/aml-api/main.go": "package main\n\nimport \"flag\"\nfunc main() { _ = flag.String(\"addr\", \":8080\", \"listen address\") }\n",
            "sentinel-aml-player-source/internal/audit/repository.go": "package audit\n\nvar sensitive = map[string]struct{}{\"flag_value\": {}, \"secret_for_checker\": {}}\n",
        }
        _, result = scan_fixture(extra)

        self.assertEqual(result["status"], "fail", result)
        self.assertFinding(result, token="flag_value", path="internal/audit/repository.go")
        self.assertFinding(result, token="secret_for_checker", path="internal/audit/repository.go")

    def test_runtime_and_product_redaction_terms_are_reported_not_blocking(self):
        extra = {
            "sentinel-aml-player-source/cmd/aml-api/main.go": "package main\n\nimport \"flag\"\nfunc main() { _ = flag.String(\"addr\", \":8080\", \"listen address\") }\n",
            "sentinel-aml-player-source/internal/audit/repository.go": "package audit\n\nvar sensitive = map[string]struct{}{\"external_reference_value\": {}, \"verification_marker\": {}}\n",
        }
        _, result = scan_fixture(extra)

        self.assertEqual(result["status"], "pass", result)
        self.assertGreaterEqual(result["allowlisted_hit_count"], 2)
        self.assertAllowlisted(result, token="flag", path="cmd/aml-api/main.go")

    def assertFinding(self, result: dict[str, object], *, token: str, path: str | None = None) -> None:
        findings = result["findings"]
        self.assertTrue(
            any(
                finding["token"] == token and finding["allowlisted"] is False and (path is None or finding["path"] == path)
                for finding in findings
            ),
            findings,
        )

    def assertAllowlisted(self, result: dict[str, object], *, token: str, path: str) -> None:
        findings = result["findings"]
        self.assertTrue(
            any(finding["token"] == token and finding["allowlisted"] is True and finding["path"] == path for finding in findings),
            findings,
        )


def scan_fixture(extra_files: dict[str, str]) -> tuple[Path, dict[str, object]]:
    root = Path(tempfile.mkdtemp())
    artifact = root / "fixture.tar.gz"
    files = clean_fixture_files()
    files.update(extra_files)
    write_tar(artifact, files)
    return artifact, hygiene.check_player_source_hygiene(artifact)


def clean_fixture_files() -> dict[str, str]:
    return {
        "sentinel-aml-player-source/README.md": "Player source package\n",
        "sentinel-aml-player-source/TROUBLESHOOTING.md": "Use vendored dependencies.\n",
        "sentinel-aml-player-source/Makefile": "build:\n\tgo build ./cmd/aml-api ./cmd/aml-worker ./cmd/aml-migrate\n",
        "sentinel-aml-player-source/Dockerfile": "FROM alpine:3.20\nRUN go build ./cmd/aml-api\nCOPY web/dist /usr/share/nginx/html\n",
        "sentinel-aml-player-source/docker-compose.yml": "services:\n  api:\n    build:\n      context: .\n",
        "sentinel-aml-player-source/deploy/player.env.example": "DATABASE_URL=postgres://sentinel:sentinel@postgres:5432/sentinel_aml?sslmode=disable\n",
        "sentinel-aml-player-source/go.mod": "module sentinel-aml\n\ngo 1.22\n",
        "sentinel-aml-player-source/go.sum": "",
        "sentinel-aml-player-source/cmd/aml-api/main.go": "package main\n\nfunc main() {}\n",
        "sentinel-aml-player-source/cmd/aml-worker/main.go": "package main\n\nfunc main() {}\n",
        "sentinel-aml-player-source/cmd/aml-migrate/main.go": "package main\n\nfunc main() {}\n",
        "sentinel-aml-player-source/internal/httpapi/server.go": "package httpapi\n",
        "sentinel-aml-player-source/migrations/000001_create_users_sessions.sql": "select 1;\n",
        "sentinel-aml-player-source/web/dist/index.html": "<title>Sentinel AML</title><script src=\"/runtime-config.js\"></script><script type=\"module\" src=\"/assets/index.js\"></script>\n",
        "sentinel-aml-player-source/web/dist/runtime-config.js": "window.__SENTINEL_CONFIG__ = { apiBaseUrl: \"\" };\n",
        "sentinel-aml-player-source/web/dist/assets/index.js": "console.log('Sentinel AML');\n",
        "sentinel-aml-player-source/vendor/modules.txt": "# vendored\n",
    }


def write_tar(path: Path, files: dict[str, str]) -> None:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, text in sorted(files.items()):
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(payload.getvalue())


def archive_token_hits(artifact: Path, terms: tuple[str, ...]) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    text_suffixes = hygiene.TEXT_SUFFIXES + (".py",)
    with gzip.open(artifact, "rb") as raw:
        payload = io.BytesIO(raw.read())
    with tarfile.open(fileobj=payload, mode="r:") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            path = member.name.removeprefix(f"{builder.ARCHIVE_ROOT}/")
            if path.startswith("vendor/") or not path.lower().endswith(text_suffixes):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            text = handle.read().decode("utf-8", errors="ignore")
            for line_no, line in enumerate(text.splitlines(), start=1):
                lowered = line.lower()
                for term in terms:
                    if term.lower() in lowered:
                        hits.append((path, line_no, term))
    return hits


if __name__ == "__main__":
    unittest.main()
