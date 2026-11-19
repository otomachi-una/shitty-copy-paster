import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave05_gate.py"

spec = importlib.util.spec_from_file_location("check_wave05_gate", SCRIPT_PATH)
wave05_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave05_gate)


class Wave05GateTest(unittest.TestCase):
    def test_wave05_gate_is_historical_after_wave07_expansion(self):
        result = wave05_gate.validate_wave05_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        if (ROOT / "migrations" / "000006_create_audit_events.sql").exists():
            self.assertEqual(
                {check["name"] for check in failures},
                {
                    "wave05-migrations-present-ordered",
                    "wave05-tables-in-scope",
                    "wave05-routes-present",
                    "no-out-of-scope-routes-or-handlers",
                },
            )
            self.assertEqual(result["status"], "fail")
        elif (ROOT / "migrations" / "000005_add_case_dedup_hint.sql").exists():
            self.assertEqual(
                {check["name"] for check in failures},
                {
                    "wave05-migrations-present-ordered",
                    "no-out-of-scope-routes-or-handlers",
                },
            )
            self.assertEqual(result["status"], "fail")
        else:
            self.assertEqual(failures, [])
            self.assertEqual(result["status"], "pass")

    def test_wave05_migrations_reject_future_subsystems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            migrations = root / "migrations"
            migrations.mkdir()
            for name in wave05_gate.EXPECTED_MIGRATIONS:
                (migrations / name).write_text(
                    textwrap.dedent(
                        """
                        CREATE TABLE users (id bigserial PRIMARY KEY);
                        CREATE TABLE sessions (id bigserial PRIMARY KEY);
                        CREATE TABLE customers (id bigserial PRIMARY KEY);
                        CREATE TABLE accounts (id bigserial PRIMARY KEY);
                        CREATE TABLE transactions (id bigserial PRIMARY KEY);
                        CREATE TABLE alerts (id bigserial PRIMARY KEY);
                        CREATE TABLE cases (id bigserial PRIMARY KEY);
                        CREATE TABLE case_notes (id bigserial PRIMARY KEY);
                        CREATE TABLE edd_records (id bigserial PRIMARY KEY);
                        CREATE TABLE exports (id bigserial PRIMARY KEY);
                        """
                    ),
                    encoding="utf-8",
                )

            checks = wave05_gate.check_migrations(root)

        table_check = next(check for check in checks if check["name"] == "wave05-tables-in-scope")
        self.assertEqual(table_check["status"], "fail")
        self.assertIn("exports", table_check["message"])

    def test_wave05_routes_reject_out_of_scope_routes(self):
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
                        mux.HandleFunc("/api/customers", s.requireAuth(s.handleCustomersRoot))
                        mux.HandleFunc("/api/customers/", s.requireAuth(s.handleCustomersSubtree))
                        mux.HandleFunc("/api/accounts/", s.requireAuth(s.handleAccountsSubtree))
                        mux.HandleFunc("/api/transactions", s.requireAuth(s.handleTransactionsRoot))
                        mux.HandleFunc("/api/transactions/", s.requireAuth(s.handleTransactionsSubtree))
                        mux.HandleFunc("/api/alerts/queue", s.requireAuth(s.handleAlertsQueue))
                        mux.HandleFunc("/api/alerts/", s.requireAuth(s.handleAlertsSubtree))
                        mux.HandleFunc("/api/cases/", s.requireAuth(s.handleCasesSubtree))
                        mux.HandleFunc("/api/exports", s.requireAuth(s.handleExport))
                    }
                    type EDDRepository interface{}
                    type CreateEDDRequest struct{}
                    type UpdateEDDRequest struct{}
                    type EDDOwnerView struct{}
                    func WithEDDRepository() {}
                    func handleCustomerEDD() {}
                    const duplicate_edd_record = "duplicate_edd_record"
                    const marker = "parts[1] == \\"edd\\""
                    const marker2 = "eddOwnerView(record)"
                    const marker3 = "edd.ErrInvalidInput"
                    const marker4 = "edd.ErrEDDRecordNotFound"
                    """
                ),
                encoding="utf-8",
            )

            checks = wave05_gate.check_routes(root)

        route_check = next(check for check in checks if check["name"] == "no-out-of-scope-routes-or-handlers")
        self.assertEqual(route_check["status"], "fail")
        self.assertIn("/api/exports", route_check["message"])

    def test_confidential_comment_in_non_edd_dto_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            (api_dir / "server.go").write_text(
                textwrap.dedent(
                    """
                    package httpapi
                    type CreateEDDRequest struct { ConfidentialComment string `json:"confidential_comment"` }
                    type UpdateEDDRequest struct { ConfidentialComment string `json:"confidential_comment"` }
                    type EDDOwnerView struct { ConfidentialComment string `json:"confidential_comment"` }
                    type CaseResponse struct { ConfidentialComment string `json:"confidential_comment"` }
                    """
                ),
                encoding="utf-8",
            )
            (api_dir / "domain_server_test.go").write_text("", encoding="utf-8")
            (api_dir / "live_postgres_integration_test.go").write_text("", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs" / "06_visibility_and_projections.md").write_text("", encoding="utf-8")

            checks = wave05_gate.check_edd_confidential_visibility(root)

        dto_check = next(check for check in checks if check["name"] == "edd-confidential-comment-owner-dto-only")
        self.assertEqual(dto_check["status"], "fail")
        self.assertIn("CaseResponse", dto_check["message"])

    def test_missing_live_wave05_target_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "internal" / "httpapi").mkdir(parents=True)
            (root / "internal" / "httpapi" / "live_postgres_integration_test.go").write_text(
                "package httpapi\n",
                encoding="utf-8",
            )
            (root / "Makefile").write_text("wave05-gate:\n\tpython -B scripts/check_wave05_gate.py\n", encoding="utf-8")

            checks = wave05_gate.check_live_gate(root)

        self.assertEqual({check["status"] for check in checks}, {"fail", "pass"})
        live_check = next(check for check in checks if check["name"] == "wave05-live-edd-api-gate-present")
        self.assertEqual(live_check["status"], "fail")

    def test_missing_wave05_status_docs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            docs.mkdir()
            (root / "README.md").write_text("Wave 04 | needs fixes\n", encoding="utf-8")
            (docs / "13_roadmap.md").write_text("Wave 04 | needs fixes\n", encoding="utf-8")
            (docs / "waves.md").write_text("W05 | EDD workflow | planned\n", encoding="utf-8")
            (docs / "source_of_truth_map.md").write_text("old map\n", encoding="utf-8")
            (docs / "12_testing_strategy.md").write_text("old testing\n", encoding="utf-8")

            checks = wave05_gate.check_docs_status(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("Wave 05 | needs fixes", checks[0]["message"])


if __name__ == "__main__":
    unittest.main()
