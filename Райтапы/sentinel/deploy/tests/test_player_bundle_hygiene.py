import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_player_bundle_hygiene.py"

spec = importlib.util.spec_from_file_location("check_player_bundle_hygiene", SCRIPT_PATH)
player_hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(player_hygiene)

BUILD_SCRIPT_PATH = ROOT / "scripts" / "build_player_bundle.py"
build_spec = importlib.util.spec_from_file_location("build_player_bundle", BUILD_SCRIPT_PATH)
build_player_bundle = importlib.util.module_from_spec(build_spec)
assert build_spec.loader is not None
build_spec.loader.exec_module(build_player_bundle)

CTF_SCRIPT_PATH = ROOT / "scripts" / "check_ctf_disclosure_hygiene.py"
ctf_spec = importlib.util.spec_from_file_location("check_ctf_disclosure_hygiene", CTF_SCRIPT_PATH)
ctf_hygiene = importlib.util.module_from_spec(ctf_spec)
assert ctf_spec.loader is not None
ctf_spec.loader.exec_module(ctf_hygiene)


class PlayerBundleHygieneTest(unittest.TestCase):
    def test_clean_stub_player_candidate_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            build_result = build_player_bundle.build_stub_player_candidate(candidate)
            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(build_result["status"], "pass")
        self.assertEqual(result["status"], "pass", result["checks"])

    def test_leaking_filename_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            leak = candidate / "bin" / "aml1_vulnerable_helper.txt"
            leak.parent.mkdir(parents=True)
            leak.write_text("runtime placeholder\n", encoding="utf-8")

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("denied token in path: aml1", message)
        self.assertIn("denied token in path: vulnerable", message)

    def test_leaking_content_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            readme = candidate / "README.md"
            readme.parent.mkdir()
            readme.write_text("Set checker_secret before placing a flag.\n", encoding="utf-8")

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("denied token in content: checker_secret", message)
        self.assertIn("denied token in content: flag", message)

    def test_allowed_neutral_business_terms_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            readme = candidate / "README.md"
            readme.parent.mkdir()
            readme.write_text(
                "Customer onboarding, account monitoring, transaction review, "
                "alerts, cases, due diligence, risk scoring, audit events, "
                "entity graph, export, and network rooms are normal business terms.\n",
                encoding="utf-8",
            )

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_source_artifact_allows_go_stdlib_flag_only_in_cli_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(
                candidate,
                "PACKAGING_STATUS.json",
                json.dumps({"artifact_class": "player-service", "delivery_mode": "source"}),
            )
            write_candidate_file(
                candidate,
                "cmd/aml-api/main.go",
                'package main\n\nimport "flag"\n\nfunc main() {\n\taddr := flag.String("addr", ":8080", "HTTP listen address")\n\tflag.Parse()\n\t_ = addr\n}\n',
            )

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_binary_player_delivery_fails_when_required_ui_is_silently_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(
                candidate,
                "PACKAGING_STATUS.json",
                json.dumps(
                    {
                        "artifact_class": "player-service",
                        "artifact_contract": "player-service-with-ui.v1",
                        "delivery_mode": "binary-image",
                        "participant_ui": {"included": False, "required": True, "delivery_path": "ui/"},
                        "delivered_components": [
                            {"key": "backend-runtime", "included": True, "required": True, "delivery_path": "bin/"},
                            {"key": "participant-ui", "included": False, "required": True, "delivery_path": "ui/"},
                        ],
                    }
                ),
            )
            for relative in ("bin/aml-api", "bin/aml-worker", "bin/aml-migrate", "Dockerfile", "deploy/compose.yaml"):
                write_candidate_file(candidate, relative, "runtime input\n")

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("participant_ui.included=true", message)
        self.assertIn("ui/index.html", message)

    def test_go_stdlib_flag_exception_does_not_mask_ctf_flag_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(
                candidate,
                "PACKAGING_STATUS.json",
                json.dumps({"artifact_class": "player-service", "delivery_mode": "source"}),
            )
            write_candidate_file(
                candidate,
                "cmd/aml-worker/main.go",
                'package main\n\nimport "flag"\n\nfunc main() {\n\tonce := flag.Bool("once", false, "run once")\n\tflag.Parse()\n\t_ = once\n\t_ = "flag_value"\n}\n',
            )

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        self.assertIn("denied token in content: flag_value", result["checks"][1]["message"])

    def test_go_stdlib_flag_exception_is_not_global(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(
                candidate,
                "PACKAGING_STATUS.json",
                json.dumps({"artifact_class": "player-service", "delivery_mode": "source"}),
            )
            write_candidate_file(
                candidate,
                "internal/config/flags.go",
                'package config\n\nimport "flag"\n\nfunc configure() {\n\tflag.Parse()\n}\n',
            )

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        self.assertIn("denied token in content: flag", result["checks"][1]["message"])

    def test_allowlist_cannot_suppress_critical_ctf_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(candidate, "README.md", "checker flag_value public_attack_data\n")
            allowlist = Path(tmp) / "allowlist.json"
            allowlist.write_text(
                json.dumps({"allow": [{"type": "content-token", "path": "README.md", "tokens": "*"}]}),
                encoding="utf-8",
            )

            result = player_hygiene.validate_player_bundle(candidate, allowlist)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("denied token in content: checker", message)
        self.assertIn("denied token in content: flag_value", message)
        self.assertIn("denied token in content: public_attack_data", message)

    def test_flag_lifecycle_tokens_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(candidate, "config/service.env", "flag_id=abc\nputflag=true\ngetflag=true\n")

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("denied token in content: flag_id", message)
        self.assertIn("denied token in content: putflag", message)
        self.assertIn("denied token in content: getflag", message)

    def test_source_artifact_ignores_third_party_default_filename_but_not_project_dual_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(
                candidate,
                "PACKAGING_STATUS.json",
                json.dumps({"artifact_class": "player-service", "delivery_mode": "source"}),
            )
            write_candidate_file(candidate, "vendor/example.com/lib/pgtype_default.go", "package lib\n")
            write_candidate_file(candidate, "internal/httpapi/audit_profile_detail.go", "package httpapi\n")

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("internal/httpapi/audit_profile_detail.go", message)
        self.assertNotIn("vendor/example.com/lib/pgtype_default.go", message)

    def test_vendored_third_party_content_is_not_treated_as_project_leakage(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            source = candidate / "vendor" / "example.com" / "library" / "source.go"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package library\n\n// Third-party libraries may mention flags, checkers, or vulnerable ciphers.\n",
                encoding="utf-8",
            )

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_vendored_paths_are_still_checked_for_obvious_map_leaks(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            source = candidate / "vendor" / "aml1_vulnerable" / "source.go"
            source.parent.mkdir(parents=True)
            source.write_text("package source\n", encoding="utf-8")

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        self.assertIn("denied token in path: aml1", result["checks"][1]["message"])

    def test_repository_root_is_rejected_instead_of_scanned_as_player_bundle(self):
        result = player_hygiene.validate_player_bundle(ROOT)

        self.assertEqual(result["status"], "fail")
        self.assertIn("organizer repository root", result["checks"][0]["message"])

    def test_forbidden_organizer_directories_fail_in_candidate(self):
        forbidden_dirs = ("checkers", "sploits", "fixes", "tests", "docs")
        for dirname in forbidden_dirs:
            with self.subTest(dirname=dirname):
                with tempfile.TemporaryDirectory() as tmp:
                    candidate = Path(tmp) / "candidate"
                    path = candidate / dirname / "README.md"
                    path.parent.mkdir(parents=True)
                    path.write_text("placeholder\n", encoding="utf-8")

                    result = player_hygiene.validate_player_bundle(candidate)

                self.assertEqual(result["status"], "fail")
                self.assertIn(f"forbidden player bundle path prefix {dirname}/", result["checks"][1]["message"])

    def test_internal_build_profile_source_vocabulary_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            source = candidate / "internal" / "httpapi" / "audit_profile_detail.go"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package httpapi\n\nfunc auditDetailProfileEnabled() bool { return true }\n",
                encoding="utf-8",
            )

            result = player_hygiene.validate_player_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("build-profile-path", message)
        self.assertIn("build-profile-identifier", message)

    def test_allowlist_can_suppress_intentional_neutral_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            readme = candidate / "README.md"
            readme.parent.mkdir()
            readme.write_text("Operators may describe a red flag in generic AML training text.\n", encoding="utf-8")
            allowlist = Path(tmp) / "allowlist.json"
            allowlist.write_text(
                json.dumps({"allow": [{"type": "content-token", "path": "README.md", "tokens": ["flag"]}]}),
                encoding="utf-8",
            )

            result = player_hygiene.validate_player_bundle(candidate, allowlist)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_archive_member_content_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "candidate.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                data = b"public_attack_data must never appear in a player bundle\n"
                info = tarfile.TarInfo("README.md")
                info.size = len(data)
                archive.addfile(info, fileobj=io.BytesIO(data))

            result = player_hygiene.validate_player_bundle(archive_path)

        self.assertEqual(result["status"], "fail")
        self.assertIn("denied token in content: public_attack_data", result["checks"][1]["message"])

    def test_zip_member_path_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "candidate.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("sploits/sentinel_aml/tool.py", "placeholder\n")

            result = player_hygiene.validate_player_bundle(archive_path)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][1]["message"]
        self.assertIn("forbidden player bundle path prefix sploits/", message)
        self.assertIn("denied token in path: sploit", message)

    def test_archive_path_traversal_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "candidate.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                data = b"placeholder\n"
                info = tarfile.TarInfo("../README.md")
                info.size = len(data)
                archive.addfile(info, fileobj=io.BytesIO(data))

            result = player_hygiene.validate_player_bundle(archive_path)

        self.assertEqual(result["status"], "fail")
        self.assertIn("unsafe archive member path", result["checks"][1]["message"])

    def test_runtime_readiness_guard_requires_source_dependencies_and_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(
                candidate,
                "PACKAGING_STATUS.json",
                json.dumps(
                    {
                        "artifact_class": "player-service",
                        "candidate_state": "final",
                        "delivery_mode": "source",
                        "final_package": True,
                        "source_runtime_ready": True,
                        "runtime_proof": {"command": "go test ./... && docker compose config", "exit_code": 0},
                    }
                ),
            )
            for relative in ("go.mod", "go.sum", "vendor/modules.txt", "Dockerfile", "deploy/compose.yaml"):
                write_candidate_file(candidate, relative, "runtime input\n")

            result = player_hygiene.validate_player_bundle(candidate, require_runtime_ready=True)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_runtime_readiness_guard_accepts_binary_image_without_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(
                candidate,
                "PACKAGING_STATUS.json",
                json.dumps(
                    {
                        "artifact_class": "player-service",
                        "candidate_state": "final",
                        "delivery_mode": "binary-image",
                        "artifact_contract": "player-service-with-ui.v1",
                        "final_package": True,
                        "source_runtime_ready": False,
                        "image_reference": "sentinel-aml-player:review",
                        "participant_ui": {"included": True, "required": True, "delivery_path": "ui/"},
                        "delivered_components": [
                            {"key": "backend-runtime", "included": True, "required": True, "delivery_path": "bin/"},
                            {"key": "participant-ui", "included": True, "required": True, "delivery_path": "ui/"},
                        ],
                        "runtime_proof": {"command": "docker compose config", "exit_code": 0},
                    }
                ),
            )
            write_candidate_file(candidate, "deploy/compose.yaml", "services:\n  api:\n    image: sentinel-aml-player:review\n")
            write_candidate_file(candidate, "migrations/000001.sql", "select 1;\n")
            write_candidate_file(candidate, "ui/index.html", "<!doctype html>\n")
            write_candidate_file(candidate, "ui/runtime-config.js", "window.__SENTINEL_AML_CONFIG__ = { apiBaseUrl: '' };\n")

            result = player_hygiene.validate_player_bundle(candidate, require_runtime_ready=True)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_runtime_readiness_guard_rejects_binary_image_with_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            write_candidate_file(
                candidate,
                "PACKAGING_STATUS.json",
                json.dumps(
                    {
                        "artifact_class": "player-service",
                        "candidate_state": "final",
                        "delivery_mode": "binary-image",
                        "final_package": True,
                        "image_reference": "sentinel-aml-player:review",
                        "runtime_proof": {"command": "docker compose config", "exit_code": 0},
                    }
                ),
            )
            write_candidate_file(candidate, "deploy/compose.yaml", "services:\n")
            write_candidate_file(candidate, "internal/httpapi/server.go", "package httpapi\n")

            result = player_hygiene.validate_player_bundle(candidate, require_runtime_ready=True)

        self.assertEqual(result["status"], "fail")
        self.assertIn("contains source files", result["checks"][-1]["message"])

    def test_cli_fails_on_synthetic_leaking_player_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            leak = candidate / "config" / "attack_info.txt"
            leak.parent.mkdir(parents=True)
            leak.write_text("LEAK_TARGET=MUST_NOT_LEAK\n", encoding="utf-8")

            completed = subprocess.run(
                ["python", "-B", str(SCRIPT_PATH), str(candidate)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertIn("attack_info", completed.stdout)
        self.assertIn("LEAK_TARGET", completed.stdout)
        self.assertIn("MUST_NOT_LEAK", completed.stdout)

    def test_ctf_go_version_metadata_scan_rejects_organizer_terms(self):
        class Completed:
            returncode = 0
            stdout = "build\t-tags=case_match_preview\n"
            stderr = ""

        original_run = ctf_hygiene.subprocess.run
        try:
            ctf_hygiene.subprocess.run = lambda *args, **kwargs: Completed()
            with tempfile.TemporaryDirectory() as tmp:
                candidate = Path(tmp) / "candidate"
                binary = candidate / "bin" / "aml-api"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"binary")

                result = ctf_hygiene.check_go_version_metadata(binary, candidate)
        finally:
            ctf_hygiene.subprocess.run = original_run

        self.assertEqual(result["status"], "fail")
        self.assertIn("case_match_preview", result["message"])

    def test_ctf_binary_strings_scan_rejects_organizer_symbols(self):
        original_which = ctf_hygiene.shutil.which
        try:
            ctf_hygiene.shutil.which = lambda _name: None
            with tempfile.TemporaryDirectory() as tmp:
                candidate = Path(tmp) / "candidate"
                binary = candidate / "bin" / "aml-api"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"\x00FindDuplicatePrivateNotesForPreview\x00private_service_marker\x00source_scope_materialized\x00")

                result = ctf_hygiene.check_binary_strings(binary, candidate)
        finally:
            ctf_hygiene.shutil.which = original_which

        self.assertEqual(result["status"], "fail")
        self.assertIn("FindDuplicatePrivateNotesForPreview", result["message"])
        self.assertIn("private_service_marker", result["message"])
        self.assertIn("source_scope_materialized", result["message"])

    def test_ctf_binary_strings_scan_reports_allowed_runtime_and_product_terms(self):
        original_which = ctf_hygiene.shutil.which
        try:
            ctf_hygiene.shutil.which = lambda _name: None
            with tempfile.TemporaryDirectory() as tmp:
                candidate = Path(tmp) / "candidate"
                binary = candidate / "bin" / "aml-api"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"\x00runtime.main\x00/api/cases\x00candidate\x00DATABASE_URL\x00")

                result = ctf_hygiene.check_binary_strings(binary, candidate)
        finally:
            ctf_hygiene.shutil.which = original_which

        self.assertEqual(result["status"], "pass", result["message"])
        self.assertIn("allowlist=", result["message"])
        self.assertIn("go-runtime", result["message"])
        self.assertIn("product-api", result["message"])

    def test_makefile_target_exists_and_does_not_build_release_archive(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertRegex(makefile, r"(?m)^player-hygiene-gate:")
        target = makefile.split("player-hygiene-gate:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("test_player_bundle_hygiene.py", target)
        self.assertIn("scripts/check_player_bundle_hygiene.py", target)
        self.assertIn("scripts/check_ctf_disclosure_hygiene.py", target)
        self.assertIn("scripts/build_player_bundle.py", target)
        self.assertNotIn("release-archive", target)
        self.assertNotIn("build_release_archive.py", target)


def write_candidate_file(candidate: Path, relative: str, content: str) -> None:
    path = candidate / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
