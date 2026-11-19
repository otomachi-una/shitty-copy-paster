import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave03_gate.py"

spec = importlib.util.spec_from_file_location("check_wave03_gate", SCRIPT_PATH)
wave03_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave03_gate)


class Wave03GateTest(unittest.TestCase):
    def test_wave03_gate_is_historical_after_wave04_expansion(self):
        result = wave03_gate.validate_wave03_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        if (ROOT / "migrations" / "000003_create_alerts_cases_notes.sql").exists():
            self.assertEqual(
                {check["name"] for check in failures},
                {
                    "wave03-migrations-present-ordered",
                    "wave03-tables-only",
                    "wave03-routes-present",
                    "no-side-view-or-later-routes",
                    "wave01-scope",
                },
            )
            self.assertEqual(result["status"], "fail")
        else:
            self.assertEqual(failures, [])
            self.assertEqual(result["status"], "pass")

    def test_wave03_migrations_reject_later_subsystems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            migrations = root / "migrations"
            migrations.mkdir()
            (migrations / "000001_create_users_sessions.sql").write_text(
                textwrap.dedent(
                    """
                    CREATE TABLE users (id bigserial PRIMARY KEY);
                    CREATE TABLE sessions (id bigserial PRIMARY KEY);
                    """
                ),
                encoding="utf-8",
            )
            (migrations / "000002_create_customers_accounts_transactions.sql").write_text(
                textwrap.dedent(
                    """
                    CREATE TABLE customers (
                        id bigserial PRIMARY KEY,
                        owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE
                    );
                    CREATE TABLE accounts (
                        id bigserial PRIMARY KEY,
                        customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE
                    );
                    CREATE TABLE transactions (
                        id bigserial PRIMARY KEY,
                        account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE
                    );
                    CREATE TABLE alerts (id bigserial PRIMARY KEY);
                    CREATE INDEX customers_owner_user_id_idx ON customers(owner_user_id);
                    CREATE INDEX accounts_customer_id_idx ON accounts(customer_id);
                    CREATE INDEX transactions_account_id_idx ON transactions(account_id);
                    """
                ),
                encoding="utf-8",
            )

            checks = wave03_gate.check_migrations(root)

        table_check = next(check for check in checks if check["name"] == "wave03-tables-only")
        self.assertEqual(table_check["status"], "fail")
        self.assertIn("alerts", table_check["message"])

    def test_wave03_routes_require_auth_and_reject_side_views(self):
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
                        mux.HandleFunc("/api/customers", s.handleCustomersRoot)
                        mux.HandleFunc("/api/customers/", s.requireAuth(s.handleCustomersSubtree))
                        mux.HandleFunc("/api/accounts/", s.requireAuth(s.handleAccountsSubtree))
                        mux.HandleFunc("/api/transactions", s.requireAuth(s.handleTransactionsRoot))
                        mux.HandleFunc("/api/transactions/", s.requireAuth(s.handleTransactionsSubtree))
                        mux.HandleFunc("/api/cases", s.requireAuth(s.handleCases))
                    }
                    type CreateCustomerRequest struct{}
                    type CustomerResponse struct{}
                    type CreateAccountRequest struct{}
                    type AccountResponse struct{}
                    type CreateTransactionRequest struct{}
                    type TransactionResponse struct{}
                    func WithDomainRepositories() {}
                    const invalid_path = "invalid_path"
                    const not_found = "not_found"
                    func ListByCustomerOwner() {}
                    """
                ),
                encoding="utf-8",
            )

            checks = wave03_gate.check_routes(root)

        protection = next(check for check in checks if check["name"] == "wave03-product-routes-require-auth")
        side_views = next(check for check in checks if check["name"] == "no-side-view-or-later-routes")
        self.assertEqual(protection["status"], "fail")
        self.assertIn("handleCustomersRoot", protection["message"])
        self.assertEqual(side_views["status"], "fail")
        self.assertIn("/api/cases", side_views["message"])

    def test_wave03_dto_visibility_rejects_internal_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            (api_dir / "server.go").write_text(
                'package httpapi\ntype CustomerResponse struct { OwnerUserID int64 `json:"owner_user_id"` }\n',
                encoding="utf-8",
            )

            checks = wave03_gate.check_response_visibility(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("owner_user_id", checks[0]["message"])

    def test_missing_live_wave03_target_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "internal" / "httpapi").mkdir(parents=True)
            (root / "internal" / "httpapi" / "live_postgres_integration_test.go").write_text(
                "package httpapi\n",
                encoding="utf-8",
            )
            (root / "Makefile").write_text("test:\n\tgo test ./...\n", encoding="utf-8")

            checks = wave03_gate.check_live_gate(root)

        self.assertEqual({check["status"] for check in checks}, {"fail"})

    def test_missing_vendor_modules_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "vendor").mkdir()
            (root / "vendor" / "modules.txt").write_text(
                "# github.com/jackc/pgx/v5 v5.6.0\n",
                encoding="utf-8",
            )
            (root / "go.mod").write_text("module test\n\ngo 1.22.0\n", encoding="utf-8")
            (root / "Makefile").write_text("GO_OFFLINE_ENV = GOTOOLCHAIN=local GOFLAGS=-mod=vendor\n", encoding="utf-8")

            checks = wave03_gate.check_vendor(root)

        vendor_check = next(check for check in checks if check["name"] == "offline-vendor-tree-present")
        self.assertEqual(vendor_check["status"], "fail")
        self.assertIn("golang.org/x/crypto", vendor_check["message"])

    def test_missing_vendor_makefile_policy_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vendor = root / "vendor"
            for module in wave03_gate.EXPECTED_VENDOR_MODULES:
                (vendor / Path(module)).mkdir(parents=True)
            modules_text = "\n".join(
                f"# {module} {version}" for module, version in wave03_gate.EXPECTED_VENDOR_MODULES.items()
            )
            (vendor / "modules.txt").write_text(modules_text, encoding="utf-8")
            (root / "go.mod").write_text("module test\n\ngo 1.22.0\n", encoding="utf-8")
            (root / "Makefile").write_text("test:\n\tgo test ./...\n", encoding="utf-8")

            checks = wave03_gate.check_vendor(root)

        policy_check = next(check for check in checks if check["name"] == "offline-go-mod-and-makefile-policy")
        self.assertEqual(policy_check["status"], "fail")
        self.assertIn("makefile_uses_vendor=False", policy_check["message"])


if __name__ == "__main__":
    unittest.main()
