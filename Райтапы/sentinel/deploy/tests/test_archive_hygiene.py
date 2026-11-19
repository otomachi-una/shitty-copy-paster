import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_archive_hygiene.py"

spec = importlib.util.spec_from_file_location("check_archive_hygiene", SCRIPT_PATH)
archive_hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(archive_hygiene)

BUILD_SCRIPT_PATH = ROOT / "scripts" / "build_release_archive.py"
build_spec = importlib.util.spec_from_file_location("build_release_archive", BUILD_SCRIPT_PATH)
build_release_archive = importlib.util.module_from_spec(build_spec)
assert build_spec.loader is not None
build_spec.loader.exec_module(build_release_archive)


class ArchiveHygieneTest(unittest.TestCase):
    def test_current_repository_tree_passes(self):
        result = archive_hygiene.validate_archive_hygiene(ROOT)

        self.assertEqual(result["status"], "pass", result["checks"][0]["message"])

    def test_clean_minimal_tree_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "checkers" / "sentinel_aml").mkdir(parents=True)
            (root / "checkers" / "sentinel_aml" / "checker.py").write_text("print('ok')\n", encoding="utf-8")

            result = archive_hygiene.validate_archive_hygiene(root)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["checks"][0]["status"], "pass")

    def test_forbidden_root_cache_directories_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (".gocache", ".appdata", ".idea"):
                (root / name).mkdir()

            result = archive_hygiene.validate_archive_hygiene(root)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn(".gocache/", message)
        self.assertIn(".appdata/", message)
        self.assertIn(".idea/", message)

    def test_forbidden_cache_directory_prefixes_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (".gocache-p1", ".gocache-test", ".appdata-p1", ".appdata-local"):
                (root / name).mkdir()

            result = archive_hygiene.validate_archive_hygiene(root)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn(".gocache-p1/", message)
        self.assertIn(".gocache-test/", message)
        self.assertIn(".appdata-p1/", message)
        self.assertIn(".appdata-local/", message)

    def test_nested_pycache_and_bytecode_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pycache = root / "checkers" / "sentinel_aml" / "__pycache__"
            pycache.mkdir(parents=True)
            bytecode = root / "scripts" / "gate.pyc"
            bytecode.parent.mkdir()
            bytecode.write_bytes(b"cache")

            result = archive_hygiene.validate_archive_hygiene(root)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn("checkers/sentinel_aml/__pycache__/", message)
        self.assertIn("scripts/gate.pyc", message)

    def test_sploit_pycache_and_optimized_bytecode_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pycache = root / "sploits" / "sentinel_aml" / "__pycache__"
            pycache.mkdir(parents=True)
            (pycache / "aml_audit_timeline.cpython-311.pyc").write_bytes(b"cache")
            optimized = root / "sploits" / "sentinel_aml" / "aml_dedup_preview.pyo"
            optimized.write_bytes(b"optimized")

            result = archive_hygiene.validate_archive_hygiene(root)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn("sploits/sentinel_aml/__pycache__/", message)
        self.assertIn("sploits/sentinel_aml/aml_dedup_preview.pyo", message)

    def test_local_coverage_and_archive_files_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in ("coverage.out", ".coverage", "reports/unit.coverprofile", "sentinel.zip", "bundle.tar.gz"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("local artifact\n", encoding="utf-8")

            result = archive_hygiene.validate_archive_hygiene(root)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn("coverage.out", message)
        self.assertIn(".coverage", message)
        self.assertIn("reports/unit.coverprofile", message)
        self.assertIn("sentinel.zip", message)
        self.assertIn("bundle.tar.gz", message)

    def test_git_directory_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            forbidden_inside_git = root / ".git" / "__pycache__"
            forbidden_inside_git.mkdir(parents=True)

            result = archive_hygiene.validate_archive_hygiene(root)

        self.assertEqual(result["status"], "pass")

    def test_clean_release_archive_passes_with_required_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "release.tar.gz"
            self.write_archive(archive_path, archive_hygiene.REQUIRED_RELEASE_FILES)

            result = archive_hygiene.validate_archive_hygiene(archive_path)

        self.assertEqual(result["status"], "pass", result["checks"][0]["message"])

    def test_release_archive_missing_required_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            members = set(archive_hygiene.REQUIRED_RELEASE_FILES)
            members.remove("checkers/sentinel_aml/checker.py")
            archive_path = Path(tmp) / "release.tar.gz"
            self.write_archive(archive_path, members)

            result = archive_hygiene.validate_archive_hygiene(archive_path)

        self.assertEqual(result["status"], "fail")
        self.assertIn("checkers/sentinel_aml/checker.py", result["checks"][0]["message"])

    def test_release_archive_forbidden_members_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            members = set(archive_hygiene.REQUIRED_RELEASE_FILES)
            members.update(
                {
                    "checkers/sentinel_aml/__pycache__/checker.cpython-311.pyc",
                    "docs/archive/foreign_voltax/legacy.md",
                    ".env.local",
                    "sentinel_aml_release.zip",
                }
            )
            archive_path = Path(tmp) / "release.tar.gz"
            self.write_archive(archive_path, members)

            result = archive_hygiene.validate_archive_hygiene(archive_path)

        self.assertEqual(result["status"], "fail")
        message = result["checks"][0]["message"]
        self.assertIn("__pycache__", message)
        self.assertIn("docs/archive/foreign_voltax/legacy.md", message)
        self.assertIn(".env.local", message)
        self.assertIn("sentinel_aml_release.zip", message)

    def test_release_archive_path_traversal_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            members = set(archive_hygiene.REQUIRED_RELEASE_FILES)
            members.add("../outside.txt")
            archive_path = Path(tmp) / "release.tar.gz"
            self.write_archive(archive_path, members)

            result = archive_hygiene.validate_archive_hygiene(archive_path)

        self.assertEqual(result["status"], "fail")
        self.assertIn("unsafe archive member path", result["checks"][0]["message"])

    def test_release_archive_builder_is_deterministic_and_excludes_foreign_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            for relative in archive_hygiene.REQUIRED_RELEASE_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"{relative}\n", encoding="utf-8")
            (root / "docs" / "archive" / "foreign_voltax").mkdir(parents=True)
            (root / "docs" / "archive" / "foreign_voltax" / "legacy.md").write_text("foreign\n", encoding="utf-8")
            (root / "checkers" / "sentinel_aml" / "__pycache__").mkdir(parents=True)
            (root / "checkers" / "sentinel_aml" / "__pycache__" / "checker.pyc").write_bytes(b"cache")
            (root / ".env.local").write_text("secret=local\n", encoding="utf-8")

            first = build_release_archive.build_release_archive(root, Path(tmp) / "out-a")
            second = build_release_archive.build_release_archive(root, Path(tmp) / "out-b")

        self.assertEqual(first["status"], "pass", first["checks"])
        self.assertEqual(second["status"], "pass", second["checks"])
        self.assertEqual(first["sha256"], second["sha256"])

    def test_release_archive_builder_rejects_output_inside_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()

            with self.assertRaises(ValueError):
                build_release_archive.build_release_archive(root, root / "dist")

    @staticmethod
    def write_archive(path: Path, members: set[str]) -> None:
        with tarfile.open(path, "w:gz") as archive:
            for member in sorted(members):
                data = f"{member}\n".encode("utf-8")
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, fileobj=io.BytesIO(data))


if __name__ == "__main__":
    unittest.main()
