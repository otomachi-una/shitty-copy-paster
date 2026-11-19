import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave02_gate.py"

spec = importlib.util.spec_from_file_location("check_wave02_gate", SCRIPT_PATH)
wave02_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave02_gate)


class Wave02GateTest(unittest.TestCase):
    def test_wave02_gate_has_no_unexpected_failures(self):
        result = wave02_gate.validate_wave02_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        if (ROOT / "migrations" / "000002_create_customers_accounts_transactions.sql").is_file():
            self.assertEqual(
                {check["name"] for check in failures},
                {"migrations-present-ordered", "wave02-tables-only", "registered-routes-in-scope"},
            )
            messages = "\n".join(check["message"] for check in failures)
            self.assertIn("000002_create_customers_accounts_transactions.sql", messages)
            self.assertIn("customers", messages)
            self.assertIn("/api/transactions", messages)
            return

        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_docs_and_forcad_subgates_are_clean(self):
        result = wave02_gate.validate_wave02_gate(ROOT)
        checks = {check["name"]: check for check in result["checks"]}

        self.assertEqual(checks["docs-tree"]["status"], "pass")
        self.assertEqual(checks["forcad-config"]["status"], "pass")

    def test_live_postgres_gate_is_present(self):
        result = wave02_gate.validate_wave02_gate(ROOT)
        checks = {check["name"]: check for check in result["checks"]}

        self.assertEqual(checks["live-postgres-integration-test-present"]["status"], "pass")
        self.assertEqual(checks["live-postgres-compose-present"]["status"], "pass")
        self.assertEqual(checks["live-postgres-make-target-present"]["status"], "pass")

    def test_domain_tables_beyond_users_and_sessions_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            migrations = root / "migrations"
            migrations.mkdir()
            (migrations / "000001_create_users_sessions.sql").write_text(
                textwrap.dedent(
                    """
                    CREATE TABLE users (id bigserial PRIMARY KEY);
                    CREATE TABLE sessions (id bigserial PRIMARY KEY);
                    CREATE TABLE customers (id bigserial PRIMARY KEY);
                    """
                ),
                encoding="utf-8",
            )

            checks = wave02_gate.check_migrations(root)

        table_check = next(check for check in checks if check["name"] == "wave02-tables-only")
        self.assertEqual(table_check["status"], "fail")
        self.assertIn("customers", table_check["message"])

    def test_out_of_scope_api_routes_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            (api_dir / "server.go").write_text(
                textwrap.dedent(
                    """
                    package httpapi

                    func routes() {
                        mux.HandleFunc("/healthz", HealthHandler)
                        mux.HandleFunc("/readyz", HealthHandler)
                        mux.HandleFunc("/api/auth/register", s.handleRegister)
                        mux.HandleFunc("/api/auth/login", s.handleLogin)
                        mux.HandleFunc("/api/auth/me", s.requireAuth(s.handleMe))
                        mux.HandleFunc("/api/cases", s.handleCases)
                    }
                    """
                ),
                encoding="utf-8",
            )

            checks = wave02_gate.check_routes(root)

        route_check = next(check for check in checks if check["name"] == "registered-routes-in-scope")
        self.assertEqual(route_check["status"], "fail")
        self.assertIn("/api/cases", route_check["message"])

    def test_sensitive_auth_response_fields_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            auth_dir = root / "internal" / "auth"
            api_dir.mkdir(parents=True)
            auth_dir.mkdir(parents=True)
            (api_dir / "server.go").write_text(
                'package httpapi\ntype UserResponse struct { PasswordHash string `json:"password_hash"` }\n',
                encoding="utf-8",
            )
            (auth_dir / "service.go").write_text("package auth\n", encoding="utf-8")

            checks = wave02_gate.check_response_visibility(root)

        visibility_check = checks[0]
        self.assertEqual(visibility_check["status"], "fail")
        self.assertIn("password_hash", visibility_check["message"])

    def test_exploit_scripts_fail_wave02_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sploit_dir = root / "sploits" / "sentinel_aml"
            sploit_dir.mkdir(parents=True)
            (sploit_dir / "aml_dedup_preview.py").write_text("# future exploit must not exist in Wave 02\n", encoding="utf-8")

            checks = wave02_gate.check_no_exploit_scripts(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("aml_dedup_preview.py", checks[0]["message"])

    def test_missing_live_integration_target_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "internal" / "httpapi").mkdir(parents=True)
            (root / "internal" / "httpapi" / "live_postgres_integration_test.go").write_text(
                "package httpapi\n",
                encoding="utf-8",
            )
            (root / "Makefile").write_text("test:\n\tgo test ./...\n", encoding="utf-8")
            (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

            checks = wave02_gate.check_live_integration_gate(root)

        self.assertEqual({check["status"] for check in checks}, {"fail"})


if __name__ == "__main__":
    unittest.main()
