import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave06_gate.py"

spec = importlib.util.spec_from_file_location("check_wave06_gate", SCRIPT_PATH)
wave06_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave06_gate)


class Wave06GateTest(unittest.TestCase):
    def test_wave06_gate_is_historical_after_wave07_expansion(self):
        result = wave06_gate.validate_wave06_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        if (ROOT / "migrations" / "000006_create_audit_events.sql").exists():
            self.assertEqual(
                {check["name"] for check in failures},
                {
                    "wave06-migrations-retained",
                    "wave06-no-out-of-scope-tables",
                    "wave06-route-surface-retained",
                    "wave06-no-out-of-scope-routes-or-handlers",
                    "wave06-projection-contracts-present",
                    "wave06-http-leak-regression-tests-present",
                },
            )
            self.assertEqual(result["status"], "fail")
        elif (ROOT / "migrations" / "000005_add_case_dedup_hint.sql").exists():
            self.assertEqual(
                {check["name"] for check in failures},
                {
                    "wave06-migrations-retained",
                    "wave06-no-out-of-scope-routes-or-handlers",
                    "wave06-http-leak-regression-tests-present",
                },
            )
            self.assertEqual(result["status"], "fail")
        else:
            self.assertEqual(failures, [])
            self.assertEqual(result["status"], "pass")

    def test_wave06_migrations_reject_future_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            migrations = root / "migrations"
            migrations.mkdir()
            for name in wave06_gate.EXPECTED_MIGRATIONS:
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
                        CREATE TABLE audit_events (id bigserial PRIMARY KEY);
                        """
                    ),
                    encoding="utf-8",
                )

            checks = wave06_gate.check_migrations(root)

        table_check = next(check for check in checks if check["name"] == "wave06-no-out-of-scope-tables")
        self.assertEqual(table_check["status"], "fail")
        self.assertIn("audit_events", table_check["message"])

    def test_wave06_routes_reject_out_of_scope_route(self):
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
                        mux.HandleFunc("/api/graph", s.requireAuth(s.handleGraph))
                    }
                    """
                ),
                encoding="utf-8",
            )

            checks = wave06_gate.check_routes(root)

        route_check = next(check for check in checks if check["name"] == "wave06-no-out-of-scope-routes-or-handlers")
        self.assertEqual(route_check["status"], "fail")
        self.assertIn("/api/graph", route_check["message"])

    def test_wave06_projection_rejects_future_confidential_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            projection_dir = root / "internal" / "projection"
            projection_dir.mkdir(parents=True)
            (projection_dir / "contracts.go").write_text(
                textwrap.dedent(
                    """
                    package projection
                    type OwnerCustomerView struct{}
                    type OwnerAccountView struct{}
                    type OwnerTransactionView struct{}
                    type OwnerAlertView struct{}
                    type OwnerCaseView struct{}
                    type OwnerCaseNoteView struct { Body string `json:"body"` }
                    type OwnerEDDView struct { ConfidentialComment string `json:"confidential_comment"` }
                    type FuturePublicCaseShell struct { ConfidentialComment string `json:"confidential_comment"` }
                    type FutureDuplicatePreview struct{}
                    type FutureAuditSummary struct{}
                    type FutureExportSummary struct{}
                    type FutureGraphSummary struct{}
                    type FutureNetworkSummary struct{}
                    func CurrentOwnerContracts() {}
                    func FutureSafeContracts() {}
                    """
                ),
                encoding="utf-8",
            )
            (projection_dir / "contracts_test.go").write_text("", encoding="utf-8")

            checks = wave06_gate.check_projection_contracts(root)

        private_check = next(check for check in checks if check["name"] == "wave06-projection-private-fields-owner-only")
        self.assertEqual(private_check["status"], "fail")
        self.assertIn("FuturePublicCaseShell", private_check["message"])

    def test_wave06_missing_http_leak_regression_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            (api_dir / "visibility_leak_test.go").write_text("package httpapi\n", encoding="utf-8")

            checks = wave06_gate.check_http_visibility_tests(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("TestVisibilitySentinelStringsStayOnOwnerOnlyEndpoints", checks[0]["message"])

    def test_wave06_missing_authz_matrix_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "internal" / "authz").mkdir(parents=True)
            (root / "internal" / "httpapi").mkdir(parents=True)
            (root / "internal" / "authz" / "scope_contract.go").write_text("package authz\n", encoding="utf-8")
            (root / "internal" / "authz" / "scope_contract_test.go").write_text("package authz\n", encoding="utf-8")
            (root / "internal" / "httpapi" / "authz_matrix_test.go").write_text("package httpapi\n", encoding="utf-8")

            checks = wave06_gate.check_authz_matrix(root)

        self.assertEqual({check["status"] for check in checks}, {"fail"})

    def test_wave06_missing_docs_status_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            docs.mkdir()
            for path in (
                root / "README.md",
                docs / "03_api_contract.md",
                docs / "05_authentication_authorization.md",
                docs / "06_visibility_and_projections.md",
                docs / "12_testing_strategy.md",
                docs / "13_roadmap.md",
                docs / "waves.md",
                docs / "source_of_truth_map.md",
            ):
                path.write_text("Wave 05 | needs fixes\n", encoding="utf-8")

            checks = wave06_gate.check_docs_status(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("Wave 06 | needs fixes", checks[0]["message"])


if __name__ == "__main__":
    unittest.main()
