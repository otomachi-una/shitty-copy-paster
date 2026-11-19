import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check_wave07_gate.py"

spec = importlib.util.spec_from_file_location("check_wave07_gate", SCRIPT_PATH)
wave07_gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wave07_gate)


class Wave07GateTest(unittest.TestCase):
    def test_wave07_gate_is_historical_after_wave08_expansion(self):
        result = wave07_gate.validate_wave07_gate(ROOT)

        failures = [check for check in result["checks"] if check["status"] == "fail"]
        if (ROOT / "migrations" / "000006_create_audit_events.sql").exists():
            self.assertEqual(
                {check["name"] for check in failures},
                {
                    "wave07-migrations-present-ordered",
                    "wave07-tables-in-scope",
                    "wave07-route-surface-retained",
                    "wave07-no-out-of-scope-routes-or-handlers",
                    "wave07-dedup-repository-secure-shape",
                },
            )
            self.assertEqual(result["status"], "fail")
        else:
            self.assertEqual(failures, [])
            self.assertEqual(result["status"], "pass")

    def test_wave07_migrations_reject_missing_dedup_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            migrations = root / "migrations"
            migrations.mkdir()
            for name in wave07_gate.EXPECTED_MIGRATIONS[:-1]:
                (migrations / name).write_text("CREATE TABLE users (id bigserial PRIMARY KEY);\n", encoding="utf-8")

            checks = wave07_gate.check_migrations(root)

        ordered = next(check for check in checks if check["name"] == "wave07-migrations-present-ordered")
        metadata = next(check for check in checks if check["name"] == "wave07-dedup-metadata-contract")
        self.assertEqual(ordered["status"], "fail")
        self.assertEqual(metadata["status"], "fail")
        self.assertIn("000005_add_case_dedup_hint.sql", ordered["message"])

    def test_wave07_routes_reject_checker_and_attack_data(self):
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
                        mux.HandleFunc("/api/checker", s.handleChecker)
                        mux.HandleFunc("/api/attack-data", s.handleAttackData)
                    }
                    type CaseDuplicatePreviewView struct{}
                    type CaseDuplicateCandidatesResponse struct{}
                    type CaseDuplicateMergePreviewResponse struct{}
                    func handleCasesSubtree() { parts[1] == "duplicates"; parts[3] == "merge-preview" }
                    func handleCaseDuplicateCandidates() {}
                    func handleCaseDuplicateMergePreview() {}
                    func FindDuplicateCandidatesByOwner() {}
                    func duplicatePreviewView(candidate any) {}
                    const explanation = "shared_dedup_hint"
                    """
                ),
                encoding="utf-8",
            )

            checks = wave07_gate.check_routes(root)

        route_check = next(check for check in checks if check["name"] == "wave07-no-out-of-scope-routes-or-handlers")
        self.assertEqual(route_check["status"], "fail")
        self.assertIn("/api/checker", route_check["message"])
        self.assertIn("/api/attack-data", route_check["message"])

    def test_wave07_dedup_presenter_rejects_private_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            (api_dir / "server.go").write_text(
                textwrap.dedent(
                    """
                    package httpapi
                    type CaseDuplicatePreviewView struct {
                        CaseID int64 `json:"case_id"`
                        PublicSummary string `json:"public_summary"`
                        RiskTags []string `json:"risk_tags"`
                        OverlapScore int `json:"overlap_score"`
                        MatchExplanation string `json:"match_explanation"`
                        Body string `json:"body"`
                    }
                    type CaseDuplicateCandidatesResponse struct{}
                    func duplicatePreviewViews() {
                        _ = CaseNote{}
                    }
                    func eddOwnerView() {}
                    type CaseNote struct{}
                    """
                ),
                encoding="utf-8",
            )

            checks = wave07_gate.check_dedup_presenters(root)

        shape = next(check for check in checks if check["name"] == "wave07-dedup-dto-public-shape")
        presenter = next(check for check in checks if check["name"] == "wave07-dedup-presenters-omit-private-fields")
        self.assertEqual(shape["status"], "fail")
        self.assertEqual(presenter["status"], "fail")
        self.assertIn("body", presenter["message"])
        self.assertIn("CaseNote", presenter["message"])

    def test_wave07_missing_anti_aml1_tests_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_dir = root / "internal" / "httpapi"
            api_dir.mkdir(parents=True)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (api_dir / "domain_server_test.go").write_text("package httpapi\n", encoding="utf-8")
            (api_dir / "visibility_leak_test.go").write_text("package httpapi\n", encoding="utf-8")
            (tests_dir / "projection_visibility_test.go").write_text("package tests\n", encoding="utf-8")

            checks = wave07_gate.check_anti_aml1_tests(root)

        self.assertEqual({check["status"] for check in checks}, {"fail"})
        self.assertIn("TestAntiAML1DedupMergePreviewDoesNotLeakCandidatePrivateData", checks[0]["message"])

    def test_wave07_exploit_or_fix_scripts_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sploit_dir = root / "sploits" / "sentinel_aml"
            sploit_dir.mkdir(parents=True)
            (sploit_dir / "aml_dedup_preview.py").write_text("# forbidden in Wave 07\n", encoding="utf-8")

            checks = wave07_gate.check_no_exploit_or_fix_scripts(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("aml_dedup_preview.py", checks[0]["message"])

    def test_wave07_missing_status_docs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            docs.mkdir()
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
            ):
                path.write_text("Wave 06 | needs fixes\n", encoding="utf-8")

            checks = wave07_gate.check_docs_status(root)

        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("Wave 07 | needs fixes", checks[0]["message"])


if __name__ == "__main__":
    unittest.main()
