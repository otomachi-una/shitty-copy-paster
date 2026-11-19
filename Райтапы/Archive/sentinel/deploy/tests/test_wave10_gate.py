import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave10_gate.py"

spec = importlib.util.spec_from_file_location("check_wave10_gate", SCRIPT_PATH)
wave10_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave10_gate)


class Wave10GateTest(unittest.TestCase):
    def test_wave10_gate_current_branch_has_no_failures(self):
        result = wave10_gate.validate_wave10_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        self.assertEqual(failures, [])
        self.assertEqual(result["status"], "pass")

    def test_wave10_migrations_reject_missing_export_and_network_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            migrations = root / "migrations"
            migrations.mkdir()
            for name in wave10_gate.EXPECTED_MIGRATIONS[:-2]:
                (migrations / name).write_text("CREATE TABLE users (id bigserial PRIMARY KEY);\n", encoding="utf-8")

            checks = wave10_gate.check_migrations(root)

        ordered = next(check for check in checks if check["name"] == "wave10-migrations-present-ordered")
        export_contract = next(check for check in checks if check["name"] == "wave10-export-migration-contract")
        network_contract = next(check for check in checks if check["name"] == "wave10-network-migration-contract")
        self.assertEqual(ordered["status"], "fail")
        self.assertEqual(export_contract["status"], "fail")
        self.assertEqual(network_contract["status"], "fail")
        self.assertIn("000008_create_exports_disputes.sql", ordered["message"])
        self.assertIn("000009_create_network_rooms.sql", ordered["message"])

    def test_wave10_export_dto_rejects_private_notes_and_edd_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            (api_dir / "server.go").write_text(
                textwrap.dedent(
                    """
                    package httpapi
                    type ExportBundleView struct {
                        Purpose string `json:"purpose"`
                        RedactionPolicy string `json:"redaction_policy"`
                        GeneratedAt string `json:"generated_at"`
                        RootCase ExportCaseShellView `json:"root_case"`
                        LinkedCases []ExportCaseShellView `json:"linked_cases"`
                        AuditSummaries []ExportAuditSummaryView `json:"audit_summaries"`
                        EDDSummaries []ExportEDDSummaryView `json:"edd_summaries"`
                        Items []ExportItemMetadataView `json:"items"`
                    }
                    type ExportCaseShellView struct {
                        CaseID int64 `json:"case_id"`
                        CustomerID int64 `json:"customer_id"`
                        Status string `json:"status"`
                        PublicSummary string `json:"public_summary"`
                        RiskScore int `json:"risk_score"`
                        TypologyHint string `json:"typology_hint"`
                        CreatedAt string `json:"created_at"`
                        UpdatedAt string `json:"updated_at"`
                        Body string `json:"body"`
                    }
                    type ExportAuditSummaryView struct {
                        EventID int64 `json:"event_id"`
                        ObjectType string `json:"object_type"`
                        ObjectID int64 `json:"object_id"`
                        EventType string `json:"event_type"`
                        PublicMessage string `json:"public_message"`
                        ChangedFields []string `json:"changed_fields"`
                        CreatedAt string `json:"created_at"`
                    }
                    type ExportEDDSummaryView struct {
                        RecordID int64 `json:"record_id"`
                        CustomerID int64 `json:"customer_id"`
                        ReviewStatus string `json:"review_status"`
                        RiskTags []string `json:"risk_tags"`
                        CreatedAt string `json:"created_at"`
                        UpdatedAt string `json:"updated_at"`
                        ConfidentialComment string `json:"confidential_comment"`
                    }
                    type ExportItemMetadataView struct {
                        ItemType string `json:"item_type"`
                        ObjectType string `json:"object_type"`
                        ObjectID int64 `json:"object_id"`
                        Relation string `json:"relation"`
                        RedactionPolicy string `json:"redaction_policy"`
                    }
                    type NetworkRoomsResponse struct{}
                    type NetworkRoomSummaryView struct{}
                    type NetworkRoomParticipantView struct{}
                    type NetworkRoomDossierView struct{}
                    type NetworkRoomCaseView struct{}
                    type ErrorResponse struct{}
                    func exportResponse(record any, bundle any) { _ = record }
                    func exportBundleView(bundle any) {}
                    func exportCaseShellView(shell any) { _ = shell.Body }
                    func disputeResponse() {}
                    func networkRoomSummaryViews() {}
                    func writeDomainError() {}
                    """
                ),
                encoding="utf-8",
            )

            checks = wave10_gate.check_export_network_presenters(root)

        shape = next(check for check in checks if check["name"] == "wave10-export-network-dto-safe-shape")
        presenter = next(check for check in checks if check["name"] == "wave10-export-network-presenters-omit-private-fields")
        self.assertEqual(shape["status"], "fail")
        self.assertEqual(presenter["status"], "fail")
        self.assertIn("body", shape["message"])
        self.assertIn(".Body", presenter["message"])

    def test_wave10_export_redaction_rejects_root_only_linked_case_leak_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export_dir = root / "internal" / "exporting"
            export_dir.mkdir(parents=True)
            (export_dir / "redaction.go").write_text(
                textwrap.dedent(
                    """
                    package exporting
                    const RedactionPolicyPublic = "public_redacted"
                    type ExportContext struct{}
                    type ExportBundle struct { Purpose string `json:"purpose"` }
                    func BuildBundle() {
                        appendSafeCaseData(&bundle, root, scopes, "root")
                    }
                    func safeCaseShell() {}
                    func safeAuditSummary() {}
                    func safeEDDSummary() {}
                    func validateExportContext() {}
                    """
                ),
                encoding="utf-8",
            )
            (export_dir / "repository_test.go").write_text(
                "package exporting\nconst onlyRoot = `ROOT_PRIVATE_NOTE_SENTINEL ROOT_EDD_CONFIDENTIAL_SENTINEL`\n",
                encoding="utf-8",
            )

            checks = wave10_gate.check_export_repository(root)

        primitives = next(check for check in checks if check["name"] == "wave10-export-redaction-primitives-present")
        tests = next(check for check in checks if check["name"] == "wave10-export-recursive-redaction-tests-present")
        self.assertEqual(primitives["status"], "fail")
        self.assertEqual(tests["status"], "fail")
        self.assertIn("flattenLinkedCases", primitives["message"])
        self.assertIn("LINKED_PRIVATE_NOTE_SENTINEL", tests["message"])

    def test_wave10_network_dossier_rejects_private_source_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            network_dir = root / "internal" / "networkroom"
            network_dir.mkdir(parents=True)
            (network_dir / "repository.go").write_text(
                textwrap.dedent(
                    """
                    package networkroom
                    type RoomSummary struct{}
                    type CaseDossierInput struct{}
                    type SafeDossier struct{}
                    func (r *Repository) CreateOrFindRoom(ctx context.Context) {}
                    func (r *Repository) AttachCase(ctx context.Context) {}
                    func (r *Repository) JoinRoom(ctx context.Context) {}
                    func (r *Repository) ListRoomsForUser(ctx context.Context) {}
                    func (r *Repository) GetRoomForUser(ctx context.Context) {}
                    func (r *Repository) ListDossierCases(ctx context.Context) {
                        q := "SELECT cn.body, er.confidential_comment FROM case_notes cn JOIN edd_records er ON true JOIN network_room_participants owned ON true"
                        _ = q
                    }
                    func (r *Repository) ListRoomsForUserAgain() {}
                    func BuildSafeDossier() {
                        _ = PrivateDataOmitted
                        _ = "private_data_policy"
                    }
                    func deterministicRoomKey() {}
                    """
                ),
                encoding="utf-8",
            )
            (network_dir / "repository_test.go").write_text("package networkroom\n", encoding="utf-8")

            checks = wave10_gate.check_network_repository(root)

        references = next(check for check in checks if check["name"] == "wave10-network-dossier-references-only")
        tests = next(check for check in checks if check["name"] == "wave10-network-private-data-tests-present")
        self.assertEqual(references["status"], "fail")
        self.assertIn("case_notes", references["message"])
        self.assertIn("confidential_comment", references["message"])
        self.assertEqual(tests["status"], "fail")

    def test_wave10_routes_reject_checker_and_public_attack_data(self):
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
                        mux.HandleFunc("/api/exports", s.requireAuth(s.handleExportsRoot))
                        mux.HandleFunc("/api/exports/", s.requireAuth(s.handleExportsSubtree))
                        mux.HandleFunc("/api/disputes", s.requireAuth(s.handleDisputesRoot))
                        mux.HandleFunc("/api/disputes/", s.requireAuth(s.handleDisputesSubtree))
                        mux.HandleFunc("/api/network/rooms", s.requireAuth(s.handleNetworkRoomsRoot))
                        mux.HandleFunc("/api/network/rooms/", s.requireAuth(s.handleNetworkRoomsSubtree))
                        mux.HandleFunc("/api/checker", s.handleChecker)
                        mux.HandleFunc("/api/public/attack-data", s.handleAttackData)
                    }
                    func WithExportRepository() {}
                    func handleExportsRoot() {}
                    func handleExportsSubtree() {}
                    func handleDisputesRoot() {}
                    func handleDisputesSubtree() {}
                    const exportAuth = "s.requireAuth(s.handleExportsRoot) s.requireAuth(s.handleDisputesRoot)"
                    func WithNetworkRoomRepository() {}
                    func handleNetworkRoomsRoot() {}
                    func handleNetworkRoomsSubtree() {}
                    const networkAuth = "s.requireAuth(s.handleNetworkRoomsRoot) s.requireAuth(s.handleNetworkRoomsSubtree)"
                    """
                ),
                encoding="utf-8",
            )

            checks = wave10_gate.check_routes(root)

        route_surface = next(check for check in checks if check["name"] == "wave10-route-surface-retained")
        forbidden = next(check for check in checks if check["name"] == "wave10-no-out-of-scope-routes")
        self.assertEqual(route_surface["status"], "fail")
        self.assertEqual(forbidden["status"], "fail")
        self.assertIn("/api/checker", forbidden["message"])
        self.assertIn("/api/public/attack-data", forbidden["message"])

    def test_wave10_exploit_or_fix_scripts_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sploit_dir = root / "sploits" / "sentinel_aml"
            sploit_dir.mkdir(parents=True)
            (sploit_dir / "aml_export_redaction.py").write_text("# forbidden in Wave 10\n", encoding="utf-8")

            checks = wave10_gate.check_no_exploit_or_fix_scripts(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("aml_export_redaction.py", checks[0]["message"])

    def test_wave10_missing_status_docs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            reports = docs / "wave_reports"
            reports.mkdir(parents=True)
            for path in (
                root / "README.md",
                docs / "03_api_contract.md",
                docs / "05_authentication_authorization.md",
                docs / "06_visibility_and_projections.md",
                docs / "12_testing_strategy.md",
                docs / "13_roadmap.md",
                docs / "waves.md",
                docs / "source_of_truth_map.md",
                reports / "wave_10_validation_summary.md",
            ):
                path.write_text("Wave 09 | needs fixes\n", encoding="utf-8")

            checks = wave10_gate.check_docs_status(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("Wave 10 | needs fixes", checks[0]["message"])

    def test_wave10_missing_make_target_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Makefile").write_text("wave09-gate:\n\tpython -B scripts/check_wave09_gate.py\n", encoding="utf-8")

            checks = wave10_gate.check_makefile(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("wave10-gate", checks[0]["message"])


if __name__ == "__main__":
    unittest.main()
