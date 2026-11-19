import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave09_gate.py"

spec = importlib.util.spec_from_file_location("check_wave09_gate", SCRIPT_PATH)
wave09_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave09_gate)


class Wave09GateTest(unittest.TestCase):
    def test_wave09_gate_is_historical_after_wave10_expansion(self):
        result = wave09_gate.validate_wave09_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        if (ROOT / "migrations" / "000008_create_exports_disputes.sql").exists():
            self.assertEqual(
                {check["name"] for check in failures},
                {
                    "wave09-migrations-present-ordered",
                    "wave09-tables-in-scope",
                    "wave09-route-surface-retained",
                    "wave09-no-out-of-scope-routes-or-handlers",
                },
            )
            self.assertEqual(result["status"], "fail")
        else:
            self.assertEqual(failures, [])
            self.assertEqual(result["status"], "pass")

    def test_wave09_migrations_reject_missing_graph_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            migrations = root / "migrations"
            migrations.mkdir()
            for name in wave09_gate.EXPECTED_MIGRATIONS[:-1]:
                (migrations / name).write_text("CREATE TABLE users (id bigserial PRIMARY KEY);\n", encoding="utf-8")

            checks = wave09_gate.check_migrations(root)

        ordered = next(check for check in checks if check["name"] == "wave09-migrations-present-ordered")
        contract = next(check for check in checks if check["name"] == "wave09-graph-migration-contract")
        self.assertEqual(ordered["status"], "fail")
        self.assertEqual(contract["status"], "fail")
        self.assertIn("000007_create_entity_graph.sql", ordered["message"])

    def test_wave09_graph_repository_rejects_private_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_dir = root / "internal" / "graph"
            graph_dir.mkdir(parents=True)
            (graph_dir / "repository.go").write_text(
                textwrap.dedent(
                    """
                    package graph
                    type EntitySummary struct{}
                    type RelatedCaseSummary struct { Body string }
                    type EDDSummary struct { ConfidentialComment string }
                    func NewRepository() {}
                    func (r *Repository) HasEntityAccess(ctx context.Context, ownerUserID int64, entityHint string) {}
                    func (r *Repository) GetEntitySummary(ctx context.Context, ownerUserID int64, entityHint string) {}
                    func (r *Repository) ListRelatedCases(ctx context.Context, ownerUserID int64, entityHint string) {
                        q := "SELECT cn.body FROM case_notes cn"
                        _ = q
                    }
                    func (r *Repository) ListEDDSummaries(ctx context.Context, ownerUserID int64, entityHint string) {}
                    const exists = "WHERE owner_user_id = $1 AND lower(btrim(entity_hint)) = $2 EXISTS ("
                    func normalizeEntityHint(value string) string { return value }
                    """
                ),
                encoding="utf-8",
            )

            checks = wave09_gate.check_graph_repository(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("ConfidentialComment", checks[0]["message"])
        self.assertIn("case_notes", checks[0]["message"])

    def test_wave09_routes_reject_out_of_scope_expansion(self):
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
                        mux.HandleFunc("/api/graph/entities/", s.requireAuth(s.handleGraphEntitiesSubtree))
                        mux.HandleFunc("/api/graph", s.handleGraphRoot)
                        mux.HandleFunc("/api/exports", s.handleExport)
                    }
                    type GraphRepository interface{}
                    func WithGraphRepository() {}
                    func graphReady() {}
                    func handleGraphEntitiesSubtree() { HasEntityAccess(ctx, user.ID, entityHint) }
                    func handleGraphEntity() {}
                    func handleGraphRelatedCases() {}
                    func handleGraphEDDSummaries() {}
                    type GraphEntityView struct{}
                    type GraphRelatedCaseView struct{}
                    type EDDGraphSummaryView struct{}
                    func graphEntityView(summary any) {}
                    func graphRelatedCaseViews(cases any) {}
                    func eddGraphSummaryViews(summaries any) {}
                    """
                ),
                encoding="utf-8",
            )

            checks = wave09_gate.check_routes(root)

        route_check = next(check for check in checks if check["name"] == "wave09-no-out-of-scope-routes-or-handlers")
        self.assertEqual(route_check["status"], "fail")
        self.assertIn("/api/graph", route_check["message"])
        self.assertIn("/api/exports", route_check["message"])

    def test_wave09_graph_presenter_rejects_private_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            (api_dir / "server.go").write_text(
                textwrap.dedent(
                    """
                    package httpapi
                    type GraphEntityView struct {
                        EntityHint string `json:"entity_hint"`
                        RelationType string `json:"relation_type"`
                        CustomerCount int `json:"customer_count"`
                        CaseCount int `json:"case_count"`
                        HighestRisk int `json:"highest_risk"`
                        RiskTags []string `json:"risk_tags"`
                        UpdatedAt string `json:"updated_at"`
                        Body string `json:"body"`
                    }
                    type GraphRelatedCaseView struct {
                        CaseID int64 `json:"case_id"`
                        CustomerID int64 `json:"customer_id"`
                        EntityHint string `json:"entity_hint"`
                        DisplayName string `json:"display_name"`
                        Country string `json:"country"`
                        Status string `json:"status"`
                        PublicSummary string `json:"public_summary"`
                        RiskScore int `json:"risk_score"`
                        TypologyHint string `json:"typology_hint"`
                        CreatedAt string `json:"created_at"`
                        UpdatedAt string `json:"updated_at"`
                    }
                    type EDDGraphSummaryView struct {
                        CustomerID int64 `json:"customer_id"`
                        EntityHint string `json:"entity_hint"`
                        ReviewStatus string `json:"review_status"`
                        RiskTags []string `json:"risk_tags"`
                        CreatedAt string `json:"created_at"`
                        UpdatedAt string `json:"updated_at"`
                    }
                    type ErrorResponse struct{}
                    func graphEntityView(summary any) { _ = summary.ConfidentialComment }
                    func eddOwnerView() {}
                    """
                ),
                encoding="utf-8",
            )

            checks = wave09_gate.check_graph_presenters(root)

        shape = next(check for check in checks if check["name"] == "wave09-graph-dto-safe-shape")
        presenter = next(check for check in checks if check["name"] == "wave09-graph-presenters-omit-private-fields")
        self.assertEqual(shape["status"], "fail")
        self.assertEqual(presenter["status"], "fail")
        self.assertIn("body", shape["message"])
        self.assertIn("ConfidentialComment", presenter["message"])

    def test_wave09_missing_anti_aml3_tests_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "internal" / "httpapi").mkdir(parents=True)
            (root / "internal" / "projection").mkdir(parents=True)
            (root / "tests").mkdir()
            (root / "internal" / "httpapi" / "graph_server_test.go").write_text("package httpapi\n", encoding="utf-8")
            (root / "internal" / "httpapi" / "visibility_leak_test.go").write_text("package httpapi\n", encoding="utf-8")
            (root / "tests" / "projection_visibility_test.go").write_text("package tests\n", encoding="utf-8")

            checks = wave09_gate.check_anti_aml3_tests(root)

        self.assertEqual({check["status"] for check in checks}, {"fail"})
        self.assertIn("TestAntiAML3RelatedGraphDoesNotExposePrivateStores", checks[0]["message"])

    def test_wave09_exploit_or_fix_scripts_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sploit_dir = root / "sploits" / "sentinel_aml"
            sploit_dir.mkdir(parents=True)
            (sploit_dir / "aml_related_graph.py").write_text("# forbidden in Wave 09\n", encoding="utf-8")

            checks = wave09_gate.check_no_exploit_or_fix_scripts(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("aml_related_graph.py", checks[0]["message"])

    def test_wave09_missing_status_docs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            reports = docs / "wave_reports"
            reports.mkdir(parents=True)
            for path in (
                root / "README.md",
                docs / "03_api_contract.md",
                docs / "04_database_model.md",
                docs / "05_authentication_authorization.md",
                docs / "06_visibility_and_projections.md",
                docs / "09_vulnerability_matrix.md",
                docs / "12_testing_strategy.md",
                docs / "13_roadmap.md",
                docs / "waves.md",
                docs / "source_of_truth_map.md",
                reports / "wave_09_validation_summary.md",
            ):
                path.write_text("Wave 08 | needs fixes\n", encoding="utf-8")

            checks = wave09_gate.check_docs_status(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("Wave 09 | needs fixes", checks[0]["message"])

    def test_wave09_missing_make_target_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Makefile").write_text("wave08-gate:\n\tpython -B scripts/check_wave08_gate.py\n", encoding="utf-8")

            checks = wave09_gate.check_makefile(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("wave09-gate", checks[0]["message"])


if __name__ == "__main__":
    unittest.main()
