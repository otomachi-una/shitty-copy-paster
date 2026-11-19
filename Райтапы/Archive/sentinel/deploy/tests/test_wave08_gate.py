import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave08_gate.py"

spec = importlib.util.spec_from_file_location("check_wave08_gate", SCRIPT_PATH)
wave08_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave08_gate)


class Wave08GateTest(unittest.TestCase):
    def test_wave08_gate_is_historical_after_wave09_expansion(self):
        result = wave08_gate.validate_wave08_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        if (ROOT / "migrations" / "000007_create_entity_graph.sql").exists():
            self.assertEqual(
                {check["name"] for check in failures},
                {
                    "wave08-migrations-present-ordered",
                    "wave08-tables-in-scope",
                    "wave08-route-surface-retained",
                    "wave08-no-out-of-scope-routes-or-handlers",
                },
            )
            self.assertEqual(result["status"], "fail")
        else:
            self.assertEqual(failures, [])
            self.assertEqual(result["status"], "pass")

    def test_wave08_migrations_reject_missing_audit_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            migrations = root / "migrations"
            migrations.mkdir()
            for name in wave08_gate.EXPECTED_MIGRATIONS[:-1]:
                (migrations / name).write_text("CREATE TABLE users (id bigserial PRIMARY KEY);\n", encoding="utf-8")

            checks = wave08_gate.check_migrations(root)

        ordered = next(check for check in checks if check["name"] == "wave08-migrations-present-ordered")
        contract = next(check for check in checks if check["name"] == "wave08-audit-migration-contract")
        self.assertEqual(ordered["status"], "fail")
        self.assertEqual(contract["status"], "fail")
        self.assertIn("000006_create_audit_events.sql", ordered["message"])

    def test_wave08_audit_repository_missing_redaction_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            audit_dir = root / "internal" / "audit"
            audit_dir.mkdir(parents=True)
            (audit_dir / "repository.go").write_text(
                textwrap.dedent(
                    """
                    package audit
                    type Repository struct{}
                    func (r Repository) Create(ctx context.Context, params CreateParams) {}
                    func (r Repository) ListCaseTimelineByOwner(ctx context.Context, ownerUserID, caseID int64) {}
                    """
                ),
                encoding="utf-8",
            )

            checks = wave08_gate.check_audit_repository(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("RedactedDiffJSON", checks[0]["message"])

    def test_wave08_audit_presenter_rejects_raw_private_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            (api_dir / "server.go").write_text(
                textwrap.dedent(
                    """
                    package httpapi
                    type CaseAuditChangeResponse struct {
                        Field string `json:"field"`
                        Old string `json:"old"`
                        New string `json:"new"`
                        Redacted bool `json:"redacted"`
                    }
                    type CaseAuditView struct {
                        ID int64 `json:"id"`
                        ObjectType string `json:"object_type"`
                        ObjectID int64 `json:"object_id"`
                        EventType string `json:"event_type"`
                        PublicMessage string `json:"public_message"`
                        Changes []CaseAuditChangeResponse `json:"changes"`
                        CreatedAt string `json:"created_at"`
                        VisibilityScope string `json:"visibility_scope"`
                        Body string `json:"body"`
                    }
                    type ErrorResponse struct{}
                    func caseAuditViews() {
                        _ = event.DiffJSON
                        writeJSON(w, http.StatusOK, events)
                    }
                    func duplicatePreviewViews() {}
                    """
                ),
                encoding="utf-8",
            )

            checks = wave08_gate.check_audit_presenters(root)

        shape = next(check for check in checks if check["name"] == "wave08-audit-dto-safe-shape")
        presenter = next(check for check in checks if check["name"] == "wave08-audit-presenters-omit-private-fields")
        self.assertEqual(shape["status"], "fail")
        self.assertEqual(presenter["status"], "fail")
        self.assertIn("body", presenter["message"])

    def test_wave08_missing_anti_aml2_tests_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "internal" / "httpapi").mkdir(parents=True)
            (root / "internal" / "projection").mkdir(parents=True)
            (root / "tests").mkdir()
            (root / "internal" / "httpapi" / "audit_timeline_test.go").write_text("package httpapi\n", encoding="utf-8")
            (root / "internal" / "httpapi" / "visibility_leak_test.go").write_text("package httpapi\n", encoding="utf-8")
            (root / "internal" / "projection" / "contracts_test.go").write_text("package projection\n", encoding="utf-8")
            (root / "tests" / "projection_visibility_test.go").write_text("package tests\n", encoding="utf-8")

            checks = wave08_gate.check_anti_aml2_tests(root)

        self.assertEqual({check["status"] for check in checks}, {"fail"})
        self.assertIn("TestAntiAML2AuditTimelineDoesNotExposePrivateStores", checks[0]["message"])

    def test_wave08_routes_reject_out_of_scope_expansion(self):
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
                        mux.HandleFunc("/api/graph", s.handleGraph)
                        mux.HandleFunc("/api/attack-data", s.handleAttackData)
                    }
                    type AuditRepository interface{}
                    func WithAuditRepository() {}
                    type CaseAuditChangeResponse struct{}
                    type CaseAuditView struct{}
                    type CaseTimelineResponse struct{}
                    func handleCaseTimeline() {}
                    func recordAudit() {}
                    func caseAuditViews() { field = "restricted_field" }
                    func caseAuditChangeResponses() {}
                    const marker = "parts[1] == \\"timeline\\""
                    """
                ),
                encoding="utf-8",
            )

            checks = wave08_gate.check_routes(root)

        route_check = next(check for check in checks if check["name"] == "wave08-no-out-of-scope-routes-or-handlers")
        self.assertEqual(route_check["status"], "fail")
        self.assertIn("/api/graph", route_check["message"])
        self.assertIn("/api/attack-data", route_check["message"])

    def test_wave08_exploit_or_fix_scripts_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sploit_dir = root / "sploits" / "sentinel_aml"
            sploit_dir.mkdir(parents=True)
            (sploit_dir / "aml_audit_timeline.py").write_text("# forbidden in Wave 08\n", encoding="utf-8")

            checks = wave08_gate.check_no_exploit_or_fix_scripts(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("aml_audit_timeline.py", checks[0]["message"])

    def test_wave08_missing_status_docs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            reports = docs / "wave_reports"
            reports.mkdir(parents=True)
            for path in (
                root / "README.md",
                docs / "03_api_contract.md",
                docs / "04_database_model.md",
                docs / "06_visibility_and_projections.md",
                docs / "09_vulnerability_matrix.md",
                docs / "12_testing_strategy.md",
                docs / "13_roadmap.md",
                docs / "waves.md",
                docs / "source_of_truth_map.md",
                reports / "wave_08_validation_summary.md",
            ):
                path.write_text("Wave 07 | needs fixes\n", encoding="utf-8")

            checks = wave08_gate.check_docs_status(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("Wave 08 | needs fixes", checks[0]["message"])

    def test_wave08_missing_make_target_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Makefile").write_text("wave07-gate:\n\tpython -B scripts/check_wave07_gate.py\n", encoding="utf-8")

            checks = wave08_gate.check_makefile(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("wave08-gate", checks[0]["message"])


if __name__ == "__main__":
    unittest.main()
