import contextlib
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave26_gate.py"

spec = importlib.util.spec_from_file_location("check_wave26_gate", SCRIPT_PATH)
wave26_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave26_gate)

WAVE21_TEST_PATH = ROOT / "tests" / "test_wave21_gate.py"
wave21_spec = importlib.util.spec_from_file_location("test_wave21_gate_for_wave26", WAVE21_TEST_PATH)
wave21_tests = importlib.util.module_from_spec(wave21_spec)
assert wave21_spec.loader is not None
wave21_spec.loader.exec_module(wave21_tests)

GO_RELEASE_RUNNER_PATH = ROOT / "scripts" / "run_go_release_tests.py"
go_runner_spec = importlib.util.spec_from_file_location("run_go_release_tests_for_wave26", GO_RELEASE_RUNNER_PATH)
go_release_runner = importlib.util.module_from_spec(go_runner_spec)
assert go_runner_spec.loader is not None
go_runner_spec.loader.exec_module(go_release_runner)


class Wave26GateTest(unittest.TestCase):
    def test_wave26_gate_current_branch_has_no_failures(self):
        result = wave26_gate.validate_wave26_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_missing_aml3_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_related_graph.patch").unlink()

            check = wave26_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_related_graph.patch", check["message"])

    def test_missing_later_fix_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            (root / "fixes" / "sentinel_aml" / "aml_export_redaction.patch").unlink()

            check = wave26_gate.check_reference_fix_inventory(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_export_redaction.patch", check["message"])

    def test_missing_exploit_inventory_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            (root / "sploits" / "sentinel_aml" / "aml_related_graph.py").unlink()

            check = wave26_gate.check_reference_exploits(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("aml_related_graph.py", check["message"])

    def test_patch_scope_rejects_docs_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            patch = root / wave26_gate.AML3_PATCH
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/docs/wave_reports/wave_26_W26-T01_handoff.md b/docs/wave_reports/wave_26_W26-T01_handoff.md",
                        "--- a/docs/wave_reports/wave_26_W26-T01_handoff.md",
                        "+++ b/docs/wave_reports/wave_26_W26-T01_handoff.md",
                        "@@ -1,1 +1,1 @@",
                        "-# Wave 26 W26-T01 Handoff",
                        "+# Wave 26 W26-T01 Handoff",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave26_gate.check_aml3_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("docs/wave_reports/wave_26_W26-T01_handoff.md", check["message"])

    def test_patch_scope_rejects_gate_only_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            patch = root / wave26_gate.AML3_PATCH
            patch.write_text(
                "\n".join(
                    [
                        "diff --git a/scripts/check_wave26_gate.py b/scripts/check_wave26_gate.py",
                        "--- a/scripts/check_wave26_gate.py",
                        "+++ b/scripts/check_wave26_gate.py",
                        "@@ -1,1 +1,1 @@",
                        "-#!/usr/bin/env python3",
                        "+#!/usr/bin/env python3",
                    ]
                ),
                encoding="utf-8",
            )

            check = wave26_gate.check_aml3_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("scripts/check_wave26_gate.py", check["message"])

    def test_patch_scope_rejects_outside_aml3_graph_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            patch = root / wave26_gate.AML3_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\ndiff --git a/internal/httpapi/server.go b/internal/httpapi/server.go\n--- a/internal/httpapi/server.go\n+++ b/internal/httpapi/server.go\n@@ -1,1 +1,1 @@\n-package httpapi\n+package httpapi\n",
                encoding="utf-8",
            )

            check = wave26_gate.check_aml3_patch_scope(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("internal/httpapi/server.go", check["message"])

    def test_patch_blocks_leak_rejects_raw_confidential_comment_reintroduction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            patch = root / wave26_gate.AML3_PATCH
            patch.write_text(patch.read_text(encoding="utf-8") + "\n+\tConfidentialComment string `json:\"confidential_comment\"`\n", encoding="utf-8")

            check = wave26_gate.check_aml3_patch_blocks_graph_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("ConfidentialComment", check["message"])

    def test_patch_blocks_leak_rejects_case_note_direct_db_debug_and_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            patch = root / wave26_gate.AML3_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n+\t_ = \"CaseNote.body\"\n+\timport \"database/sql\"\n+\texec.Command(\"sh\")\n+\t_ = \"/api/admin\"\n",
                encoding="utf-8",
            )

            check = wave26_gate.check_aml3_patch_blocks_graph_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("CaseNote.body", check["message"])
        self.assertIn("database/sql", check["message"])
        self.assertIn("exec.Command", check["message"])
        self.assertIn("/api/admin", check["message"])

    def test_patch_anti_coarse_fix_rejects_graph_endpoint_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            patch = root / wave26_gate.AML3_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n-\t/api/graph/entities/{entity_hint}\n-\t/related-cases\n-\t/edd-summaries\n-\thandleGraphEDDSummaries\n",
                encoding="utf-8",
            )

            check = wave26_gate.check_aml3_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("/api/graph/entities", check["message"])
        self.assertIn("/related-cases", check["message"])
        self.assertIn("/edd-summaries", check["message"])

    def test_patch_anti_coarse_fix_rejects_graph_repository_or_proof_test_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            patch = root / wave26_gate.AML3_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n-\tinternal/graph/repository.go\n-\tgraph_profile_default.go\n-\tgraph_profile_entity_review_test.go\n",
                encoding="utf-8",
            )

            check = wave26_gate.check_aml3_patch_anti_coarse_fix(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("internal/graph/repository.go", check["message"])
        self.assertIn("graph_profile_default.go", check["message"])
        self.assertIn("graph_profile_entity_review_test.go", check["message"])

    def test_patch_anti_coarse_fix_rejects_graph_disablement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            patch = root / wave26_gate.AML3_PATCH
            patch.write_text(patch.read_text(encoding="utf-8") + "\n+\tconst DisableGraph = true\n", encoding="utf-8")

            check = wave26_gate.check_aml3_patch_blocks_graph_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("DisableGraph", check["message"])

    def test_patch_blocks_leak_rejects_renamed_comments_hashes_and_raw_diffs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            patch = root / wave26_gate.AML3_PATCH
            patch.write_text(
                patch.read_text(encoding="utf-8")
                + "\n+\tEDDComment string `json:\"edd_comment\"`\n+\tCommentHash string `json:\"comment_hash\"`\n+\tDiffJSON string `json:\"diff_json\"`\n+\tRawDiff string\n",
                encoding="utf-8",
            )

            check = wave26_gate.check_aml3_patch_blocks_graph_leak(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("EDDComment", check["message"])
        self.assertIn("CommentHash", check["message"])
        self.assertIn("DiffJSON", check["message"])
        self.assertIn("RawDiff", check["message"])

    def test_aml3_exploit_parser_extracts_from_vulnerable_assessment_summary(self):
        response = {
            "summaries": [
                {
                    "customer_id": 2201,
                    "entity_hint": "aml3-shared-entity",
                    "review_status": "in_review",
                    "risk_tags": ["risk_level:high"],
                    "assessment_summary": "analyst note FLAG{wave26-parser-vulnerable}",
                }
            ]
        }

        values = list(wave21_tests.aml_related_graph.iter_assessment_summary_values(response))
        flags = [wave21_tests.aml_related_graph.extract_flag(value) for value in values]

        self.assertEqual(flags, ["FLAG{wave26-parser-vulnerable}"])

    def test_aml3_exploit_parser_fails_safely_on_fixed_public_summary_payload(self):
        response = {
            "summaries": [
                {
                    "customer_id": 2201,
                    "entity_hint": "aml3-shared-entity",
                    "review_status": "in_review",
                    "risk_tags": ["risk_level:high"],
                    "created_at": "1970-01-01T00:00:00Z",
                    "updated_at": "1970-01-01T00:00:00Z",
                }
            ]
        }

        values = list(wave21_tests.aml_related_graph.iter_assessment_summary_values(response))

        self.assertEqual(values, [])
        self.assertNotIn("FLAG{", json.dumps(response))
        self.assertNotIn("confidential_comment", json.dumps(response))

    def test_aml3_exploit_succeeds_on_vulnerable_fixture(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "EDDRecord",
            "customer_id": 2201,
            "entity_hint": "aml3-shared-entity",
            "typology_hint": "counterparty-watchlist",
        }
        with wave21_tests.fake_aml3_service("FLAG{wave26-vulnerable-evidence}") as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave21_tests.aml_related_graph.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue().strip(), "FLAG{wave26-vulnerable-evidence}")
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("GET", "/api/graph/entities/aml3-shared-entity/edd-summaries"), paths)
        self.assertNotIn(("GET", "/api/customers/2201/edd"), paths)

    def test_aml3_exploit_fails_safely_on_fixed_public_graph_output(self):
        attack_data = {
            "service": "sentinel_aml",
            "store": "EDDRecord",
            "customer_id": 2201,
            "entity_hint": "aml3-shared-entity",
        }
        with wave21_tests.fake_aml3_service(None) as server:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wave21_tests.aml_related_graph.main([server.host, str(server.port), json.dumps(attack_data), "--timeout", "2"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("flag-like token not found", stderr.getvalue())

    def test_fixed_graph_fixture_preserves_public_evidence_and_owner_edd_only(self):
        with fake_fixed_aml3_graph_service("FLAG{wave26-owner-edd-only}") as server:
            client = wave21_tests.aml_related_graph.Client(server.host, str(server.port), timeout=2)
            entity = client.request_json("GET", "/api/graph/entities/aml3-shared-entity", token="attacker-token")
            related = client.request_json("GET", "/api/graph/entities/aml3-shared-entity/related-cases", token="attacker-token")
            summaries = client.request_json("GET", "/api/graph/entities/aml3-shared-entity/edd-summaries", token="attacker-token")
            owner_edd = client.request_json("GET", "/api/customers/2201/edd", token="owner-token")

            with self.assertRaises(wave21_tests.aml_related_graph.HTTPStatusError):
                client.request_json("GET", "/api/customers/2201/edd", token="attacker-token")

        public_payload = json.dumps({"entity": entity, "related": related, "summaries": summaries}, sort_keys=True)
        self.assertIn("aml3-shared-entity", public_payload)
        self.assertIn("related_case_count", public_payload)
        self.assertIn("risk_level:high", public_payload)
        self.assertIn("related_cases", json.dumps(related))
        self.assertIn("summaries", json.dumps(summaries))
        self.assertNotIn("FLAG{wave26-owner-edd-only}", public_payload)
        self.assertNotIn("confidential_comment", public_payload)
        self.assertNotIn("body", public_payload)
        self.assertEqual(owner_edd["edd_records"][0]["confidential_comment"], "owner private FLAG{wave26-owner-edd-only}")
        paths = [(request["method"], request["path"]) for request in server.requests]
        self.assertIn(("GET", "/api/graph/entities/aml3-shared-entity"), paths)
        self.assertIn(("GET", "/api/graph/entities/aml3-shared-entity/related-cases"), paths)
        self.assertIn(("GET", "/api/graph/entities/aml3-shared-entity/edd-summaries"), paths)
        self.assertIn(("GET", "/api/customers/2201/edd"), paths)

    def test_makefile_target_requires_full_gate_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            (root / "Makefile").write_text("wave26-gate:\n\tpython -B scripts/check_wave26_gate.py\n", encoding="utf-8")

            check = wave26_gate.check_makefile_wave26_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("test_checker_*.py", check["message"])
        self.assertIn("aml_related_graph.patch", check["message"])
        self.assertIn("check_archive_hygiene.py", check["message"])

    def test_makefile_target_rejects_unbounded_go_test_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            makefile = (root / "Makefile").read_text(encoding="utf-8")
            makefile = makefile.replace(
                "$(PYTHON) -B scripts/run_go_release_tests.py --go $(GO) --package-timeout 120",
                "$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...",
            )
            (root / "Makefile").write_text(makefile, encoding="utf-8")

            check = wave26_gate.check_makefile_wave26_gate(root)

        self.assertEqual(check["status"], "fail")
        self.assertIn("forbidden unbounded", check["message"])

    def test_makefile_target_invokes_package_by_package_go_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = minimal_wave26_tree(Path(tmp))
            target = wave26_gate.make_target_block((root / "Makefile").read_text(encoding="utf-8"), "wave26-gate")

        self.assertIn("scripts/run_go_release_tests.py --go $(GO) --package-timeout 120", target)
        self.assertNotIn("$(GO_RELEASE_ENV) $(GO) test -p 1 -timeout 120s -count=1 ./...", target)

    def test_go_release_runner_sorts_packages_and_runs_each_with_isolated_release_env(self):
        calls = []

        def fake_runner(command, *, cwd, env, timeout):
            calls.append({"command": command, "cwd": cwd, "env": env, "timeout": timeout})
            if command[1] == "list":
                return subprocess.CompletedProcess(command, 0, "example.com/sentinel/b\nexample.com/sentinel/a\n", "")
            return subprocess.CompletedProcess(command, 0, f"ok {command[-1]}\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = io.StringIO()
            stderr = io.StringIO()
            exit_code = go_release_runner.run_release_tests(
                root,
                go="go",
                package_timeout=120,
                runner=fake_runner,
                stdout=stdout,
                stderr=stderr,
            )

        self.assertEqual(exit_code, 0, stderr.getvalue())
        test_commands = [call for call in calls if call["command"][1] == "test"]
        self.assertEqual([call["command"][-1] for call in test_commands], ["example.com/sentinel/a", "example.com/sentinel/b"])
        package_lines = [line for line in stdout.getvalue().splitlines() if line.startswith("go test package: ")]
        self.assertEqual(package_lines[0], "go test package: example.com/sentinel/a")
        for call in test_commands:
            self.assertEqual(call["env"]["GOTOOLCHAIN"], "local")
            self.assertEqual(call["env"]["GOFLAGS"], "-mod=vendor")
            self.assertEqual(call["env"]["GOTELEMETRY"], "off")
            self.assertNotIn(str(root), call["env"]["GOCACHE"])
            self.assertNotIn(str(root), call["env"]["APPDATA"])
            self.assertEqual(call["timeout"], 150)


def minimal_wave26_tree(root: Path) -> Path:
    for dirname in ("scripts", "tests", "docs/wave_reports", "sploits/sentinel_aml", "fixes/sentinel_aml", "internal/httpapi", "internal/graph"):
        (root / dirname).mkdir(parents=True, exist_ok=True)
    for relative in (
        "scripts/check_wave26_gate.py",
        "scripts/run_go_release_tests.py",
        "sploits/sentinel_aml/aml_dedup_preview.py",
        "sploits/sentinel_aml/aml_audit_timeline.py",
        "sploits/sentinel_aml/aml_related_graph.py",
        "sploits/sentinel_aml/aml_export_redaction.py",
        "sploits/sentinel_aml/aml_network_room.py",
        "fixes/sentinel_aml/README.md",
        "fixes/sentinel_aml/aml_dedup_preview.patch",
        "fixes/sentinel_aml/aml_audit_timeline.patch",
        "fixes/sentinel_aml/aml_related_graph.patch",
        "fixes/sentinel_aml/aml_export_redaction.patch",
        "fixes/sentinel_aml/aml_network_room.patch",
        "docs/wave_reports/wave_26_W26-T01_handoff.md",
        "docs/wave_reports/wave_26_W26-T02_handoff.md",
        "docs/wave_reports/wave_26_W26-T03_handoff.md",
        "Makefile",
        "internal/httpapi/graph_profile_entity_review.go",
        "internal/graph/repository_entity_review.go",
        "internal/httpapi/graph_profile_entity_review_test.go",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


class FakeFixedAML3GraphService:
    def __init__(self, private_flag: str):
        self.private_flag = private_flag
        self.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.host = "127.0.0.1"
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _handler(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                parent.handle(self)

            def do_POST(self):
                parent.handle(self)

            def log_message(self, _format, *args):
                return

        return Handler

    def handle(self, handler):
        length = int(handler.headers.get("Content-Length", "0") or "0")
        raw_body = handler.rfile.read(length) if length else b""
        body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        self.requests.append({"method": handler.command, "path": handler.path, "body": body})

        if (handler.command, handler.path) == ("POST", "/api/auth/register"):
            self.write_json(handler, 201, {"user": {"id": 1}, "session": {"token": "registration-token"}})
            return
        if (handler.command, handler.path) == ("POST", "/api/auth/login"):
            self.write_json(handler, 200, {"user": {"id": 1}, "session": {"token": "attacker-token"}})
            return
        if (handler.command, handler.path) == ("POST", "/api/customers"):
            self.write_json(handler, 201, {"id": 42, "entity_hint": body.get("entity_hint", "")})
            return
        if (handler.command, handler.path) == ("GET", "/api/graph/entities/aml3-shared-entity"):
            self.write_json(
                handler,
                200,
                {
                    "entity_hint": "aml3-shared-entity",
                    "customer_count": 2,
                    "related_case_count": 2,
                    "risk_tags": ["risk_level:high", "edd_status:in_review"],
                },
            )
            return
        if (handler.command, handler.path) == ("GET", "/api/graph/entities/aml3-shared-entity/related-cases"):
            self.write_json(
                handler,
                200,
                {
                    "related_cases": [
                        {
                            "case_id": 5201,
                            "public_summary": "public graph case shell",
                            "relation_type": "shared_entity_hint",
                            "risk_tags": ["risk_level:high"],
                        }
                    ]
                },
            )
            return
        if (handler.command, handler.path) == ("GET", "/api/graph/entities/aml3-shared-entity/edd-summaries"):
            self.write_json(
                handler,
                200,
                {
                    "summaries": [
                        {
                            "customer_id": 2201,
                            "entity_hint": "aml3-shared-entity",
                            "review_status": "in_review",
                            "risk_tags": ["risk_level:high"],
                            "assessment_summary": "public risk rationale",
                            "created_at": "1970-01-01T00:00:00Z",
                            "updated_at": "1970-01-01T00:00:00Z",
                        }
                    ]
                },
            )
            return
        if (handler.command, handler.path) == ("GET", "/api/customers/2201/edd"):
            if handler.headers.get("Authorization") != "Bearer owner-token":
                self.write_json(handler, 404, {"error": "not_found"})
                return
            self.write_json(
                handler,
                200,
                {"edd_records": [{"id": 3301, "confidential_comment": f"owner private {self.private_flag}"}]},
            )
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


def fake_fixed_aml3_graph_service(private_flag: str):
    return FakeFixedAML3GraphService(private_flag)


if __name__ == "__main__":
    unittest.main()
