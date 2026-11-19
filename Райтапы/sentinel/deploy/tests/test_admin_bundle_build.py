import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

BUILD_SCRIPT_PATH = ROOT / "scripts" / "build_admin_bundle.py"
build_spec = importlib.util.spec_from_file_location("build_admin_bundle", BUILD_SCRIPT_PATH)
build_admin_bundle = importlib.util.module_from_spec(build_spec)
assert build_spec.loader is not None
build_spec.loader.exec_module(build_admin_bundle)

HYGIENE_SCRIPT_PATH = ROOT / "scripts" / "check_admin_bundle_hygiene.py"
hygiene_spec = importlib.util.spec_from_file_location("check_admin_bundle_hygiene", HYGIENE_SCRIPT_PATH)
admin_hygiene = importlib.util.module_from_spec(hygiene_spec)
assert hygiene_spec.loader is not None
hygiene_spec.loader.exec_module(admin_hygiene)

ARTIFACT_SCRIPT_PATH = ROOT / "scripts" / "build_artifacts.py"
artifact_spec = importlib.util.spec_from_file_location("build_artifacts", ARTIFACT_SCRIPT_PATH)
build_artifacts = importlib.util.module_from_spec(artifact_spec)
assert artifact_spec.loader is not None
sys.modules[artifact_spec.name] = build_artifacts
artifact_spec.loader.exec_module(build_artifacts)


class AdminBundleBuildTest(unittest.TestCase):
    def test_admin_candidate_contains_operator_checker_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "admin"
            result = build_admin_bundle.build_admin_candidate(candidate)

            files = set(result["files"])
            status = json.loads((candidate / "PACKAGING_STATUS.json").read_text(encoding="utf-8"))

        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            files,
            {
                "README.md",
                "PACKAGING_STATUS.json",
                "config.yml",
                "config/operator.env.example",
                "sentinel_aml/checker.py",
                "sentinel_aml/checker_lib.py",
                "sentinel_aml/requirements.txt",
            },
        )
        self.assertEqual(status["artifact_class"], "admin-checker")
        self.assertIs(status["contains_checker"], True)
        self.assertIs(status["contains_forcad_config"], True)
        self.assertIs(status["contains_reference_attacks"], False)
        self.assertIs(status["contains_reference_patches"], False)
        self.assertIs(status["contains_sample_secrets"], False)
        self.assertIs(status["final_package"], False)

    def test_admin_candidate_checker_copy_has_no_dev_default_secret_or_wave_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "admin"
            build_admin_bundle.build_admin_candidate(candidate)

            checker = (candidate / "sentinel_aml" / "checker.py").read_text(encoding="utf-8")
            checker_lib = (candidate / "sentinel_aml" / "checker_lib.py").read_text(encoding="utf-8")
            env_template = (candidate / "config" / "operator.env.example").read_text(encoding="utf-8")

        self.assertNotIn("sentinel_aml_checker_wave11_dev_secret", checker_lib)
        self.assertNotIn("Wave ", checker)
        self.assertNotIn("Wave ", checker_lib)
        self.assertIn('DEFAULT_CHECKER_SECRET = ""', checker_lib)
        self.assertEqual(env_template, "SENTINEL_AML_CHECKER_SECRET=\n")

    def test_admin_checker_entrypoint_is_executable_in_tree_and_tar_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "admin"
            build_admin_bundle.build_admin_candidate(candidate)
            archive_path = Path(tmp) / "admin.tar"

            checker_path = candidate / "sentinel_aml" / "checker.py"
            build_artifacts.write_archive(
                candidate,
                [Path("sentinel_aml/checker.py")],
                archive_path,
                "sentinel-aml-admin-checker",
            )
            with tarfile.open(archive_path, "r:gz") as archive:
                checker_member = next(member for member in archive.getmembers() if member.name.endswith("sentinel_aml/checker.py"))

            if os.name != "nt":
                self.assertTrue(checker_path.stat().st_mode & 0o111)
            self.assertTrue(checker_member.mode & 0o111)

    def test_admin_candidate_hygiene_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "admin"
            build_admin_bundle.build_admin_candidate(candidate)

            result = admin_hygiene.validate_admin_bundle(candidate)

        self.assertEqual(result["status"], "pass", result["checks"])

    def test_admin_candidate_hygiene_fails_on_reference_attack_or_patch_material(self):
        forbidden_paths = (
            "sploits/sentinel_aml/tool.py",
            "fixes/sentinel_aml/patch.diff",
            "internal/httpapi/aml1_vulnerable.go",
            "docs/wave_reports/report.md",
            "tests/test_checker.py",
        )
        for relative in forbidden_paths:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as tmp:
                    candidate = Path(tmp) / "admin"
                    build_admin_bundle.build_admin_candidate(candidate)
                    leak = candidate / relative
                    leak.parent.mkdir(parents=True, exist_ok=True)
                    leak.write_text("placeholder\n", encoding="utf-8")

                    result = admin_hygiene.validate_admin_bundle(candidate)

                self.assertEqual(result["status"], "fail")
                self.assertIn("unexpected=", result["checks"][1]["message"])

    def test_admin_candidate_hygiene_fails_on_sample_secret_and_map_terms(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "admin"
            build_admin_bundle.build_admin_candidate(candidate)
            checker_lib = candidate / "sentinel_aml" / "checker_lib.py"
            checker_lib.write_text(
                checker_lib.read_text(encoding="utf-8")
                + '\nDEFAULT_CHECKER_SECRET = "sentinel_aml_checker_wave11_dev_secret"\n'
                + "print('AML-1 vulnerable exploit path')\n",
                encoding="utf-8",
            )

            result = admin_hygiene.validate_admin_bundle(candidate)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][3]["message"]
        self.assertIn("dev-secret", message)
        self.assertIn("aml1", message)
        self.assertIn("vulnerable", message)
        self.assertIn("exploit", message)

    def test_admin_candidate_config_is_validated_from_candidate_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "admin"
            build_admin_bundle.build_admin_candidate(candidate)

            completed = subprocess.run(
                [sys.executable, "-B", str(ROOT / "scripts" / "validate_forcad_config.py"), str(candidate / "config.yml")],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ForcAD shape is valid", completed.stdout)

    def test_repo_local_tmp_output_is_allowed_and_replaced(self):
        output = ROOT / "tmp" / "test-admin-candidate-build"
        try:
            output.mkdir(parents=True, exist_ok=True)
            (output / "stale.txt").write_text("stale\n", encoding="utf-8")

            result = build_admin_bundle.build_admin_candidate(output)

            self.assertEqual(result["status"], "pass")
            self.assertFalse((output / "stale.txt").exists())
            self.assertTrue((output / "sentinel_aml" / "checker.py").exists())
        finally:
            if output.exists():
                shutil.rmtree(output)

    def test_makefile_admin_hygiene_target_exists(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertRegex(makefile, r"(?m)^admin-hygiene-gate:")
        target = makefile.split("admin-hygiene-gate:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("test_admin_bundle_build.py", target)
        self.assertIn("scripts/build_admin_bundle.py", target)
        self.assertIn("scripts/check_admin_bundle_hygiene.py", target)
        self.assertIn("scripts/validate_forcad_config.py", target)
        self.assertNotIn("release-archive", target)
        self.assertNotIn("build_release_archive.py", target)


if __name__ == "__main__":
    unittest.main()
