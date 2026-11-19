import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave04_gate.py"

spec = importlib.util.spec_from_file_location("check_wave04_gate", SCRIPT_PATH)
wave04_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave04_gate)


class Wave04GateTest(unittest.TestCase):
    def test_wave04_gate_is_historical_after_wave05_expansion(self):
        result = wave04_gate.validate_wave04_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        if (ROOT / "migrations" / "000004_create_edd_records.sql").exists():
            self.assertEqual(
                {check["name"] for check in failures},
                {
                    "wave04-migrations-present-ordered",
                    "wave04-tables-in-scope",
                    "wave04-routes-present",
                    "no-out-of-scope-routes-or-handlers",
                    "wave01-scope",
                    "wave03-invariants-retained-with-wave04-expansion",
                    "wave04-doc-status-and-command-surface",
                },
            )
            self.assertEqual(result["status"], "fail")
        else:
            self.assertEqual(failures, [])
            self.assertEqual(result["status"], "pass")

    def test_wave04_migrations_reject_future_subsystems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            migrations = root / "migrations"
            migrations.mkdir()
            for name in wave04_gate.EXPECTED_MIGRATIONS:
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
                        """
                    ),
                    encoding="utf-8",
                )

            checks = wave04_gate.check_migrations(root)

        table_check = next(check for check in checks if check["name"] == "wave04-tables-in-scope")
        self.assertEqual(table_check["status"], "fail")
        self.assertIn("edd_records", table_check["message"])

    def test_wave04_routes_require_auth_and_reject_later_routes(self):
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
                        mux.HandleFunc("/api/alerts/queue", s.handleAlertsQueue)
                        mux.HandleFunc("/api/alerts/", s.requireAuth(s.handleAlertsSubtree))
                        mux.HandleFunc("/api/cases/", s.requireAuth(s.handleCasesSubtree))
                        mux.HandleFunc("/api/export", s.requireAuth(s.handleExport))
                    }
                    type AlertResponse struct{}
                    type CaseResponse struct{}
                    type CaseNoteResponse struct{ Body string `json:"body"` }
                    type TriageAlertRequest struct{}
                    type CreateCaseRequest struct{}
                    type UpdateCaseStatusRequest struct{}
                    type CreateCaseNoteRequest struct{ Body string `json:"body"` }
                    func WithInvestigationRepositories() {}
                    func handleClaimAlert() {}
                    func handleTriageAlert() {}
                    func handleCreateCaseFromAlert() {}
                    func handleCaseNotes() {}
                    func handleUpdateCaseStatus() {}
                    const invalid_transition = "invalid_transition"
                    const duplicate_case = "duplicate_case"
                    """
                ),
                encoding="utf-8",
            )

            checks = wave04_gate.check_routes(root)

        auth_check = next(check for check in checks if check["name"] == "wave04-routes-require-auth")
        route_check = next(check for check in checks if check["name"] == "no-out-of-scope-routes-or-handlers")
        self.assertEqual(auth_check["status"], "fail")
        self.assertIn("handleAlertsQueue", auth_check["message"])
        self.assertEqual(route_check["status"], "fail")
        self.assertIn("/api/export", route_check["message"])

    def test_note_body_in_alert_or_case_response_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            (api_dir / "server.go").write_text(
                textwrap.dedent(
                    """
                    package httpapi
                    type CreateCaseNoteRequest struct { Body string `json:"body"` }
                    type CaseNoteResponse struct { Body string `json:"body"` }
                    type AlertResponse struct { Body string `json:"body"` }
                    func handleCaseNotes() { caseNoteResponse(note); caseNoteResponses(notes) }
                    """
                ),
                encoding="utf-8",
            )
            (api_dir / "domain_server_test.go").write_text("", encoding="utf-8")
            (api_dir / "live_postgres_integration_test.go").write_text("", encoding="utf-8")

            checks = wave04_gate.check_note_body_containment(root)

        containment = next(check for check in checks if check["name"] == "case-note-body-owner-view-only")
        tests = next(check for check in checks if check["name"] == "case-note-body-non-owner-regression-tests")
        self.assertEqual(containment["status"], "fail")
        self.assertIn("alert_case_body_leak=True", containment["message"])
        self.assertEqual(tests["status"], "fail")

    def test_missing_wave04_live_targets_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "internal" / "httpapi").mkdir(parents=True)
            (root / "internal" / "httpapi" / "live_postgres_integration_test.go").write_text(
                "package httpapi\n",
                encoding="utf-8",
            )
            (root / "tests").mkdir()
            (root / "tests" / "wave03_live_postgres_test.go").write_text("package tests\n", encoding="utf-8")
            (root / "Makefile").write_text("test:\n\tgo test ./...\n", encoding="utf-8")

            checks = wave04_gate.check_live_gate(root)

        self.assertEqual({check["status"] for check in checks}, {"fail"})


if __name__ == "__main__":
    unittest.main()
