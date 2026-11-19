package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinel-aml/internal/projection"
)

func TestProjectionContractsCoverCurrentAndFutureSurfaces(t *testing.T) {
	current := projection.CurrentOwnerContracts()
	sideViews := projection.CurrentSideViewContracts()
	future := projection.FutureSafeContracts()
	if len(current) != 8 {
		t.Fatalf("expected 8 current owner projection contracts, got %d", len(current))
	}
	if len(sideViews) != 12 {
		t.Fatalf("expected 12 current side-view projection contracts, got %d", len(sideViews))
	}
	if len(future) != 4 {
		t.Fatalf("expected 4 future safe projection contracts, got %d", len(future))
	}
	for _, contract := range current {
		if !contract.OwnerOnly {
			t.Fatalf("current projection %s must be owner-only", contract.Name)
		}
	}
	for _, contract := range future {
		if contract.OwnerOnly {
			t.Fatalf("future safe projection %s must not be marked owner-only", contract.Name)
		}
	}
	for _, contract := range sideViews {
		if contract.OwnerOnly {
			t.Fatalf("current side-view projection %s must not be marked owner-only", contract.Name)
		}
	}
}

func TestHTTPHandlersDoNotWriteDomainModelsDirectly(t *testing.T) {
	sourcePath := filepath.Join("..", "internal", "httpapi", "server.go")
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	source := string(data)

	for _, forbidden := range []string{
		"writeJSON(w, http.StatusOK, customer)",
		"writeJSON(w, http.StatusCreated, customer)",
		"writeJSON(w, http.StatusOK, account)",
		"writeJSON(w, http.StatusCreated, account)",
		"writeJSON(w, http.StatusOK, transaction)",
		"writeJSON(w, http.StatusCreated, transaction)",
		"writeJSON(w, http.StatusOK, alert)",
		"writeJSON(w, http.StatusCreated, investigationCase)",
		"writeJSON(w, http.StatusOK, investigationCase)",
		"writeJSON(w, http.StatusCreated, note)",
		"writeJSON(w, http.StatusOK, record)",
		"writeJSON(w, http.StatusCreated, record)",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("HTTP handler appears to serialize a domain model directly: %s", forbidden)
		}
	}

	if strings.Count(source, "json.NewEncoder(w).Encode(payload)") != 1 {
		t.Fatalf("expected JSON encoder to be centralized behind writeJSON")
	}
}

func TestDedupHTTPDTOAndPresenterStayPublicOnly(t *testing.T) {
	sourcePath := filepath.Join("..", "internal", "httpapi", "server.go")
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	source := string(data)

	dto := sourceSection(t, source, "type CaseDuplicatePreviewView struct", "type CaseDuplicateCandidatesResponse struct")
	presenter := sourceSection(t, source, "func duplicatePreviewViews", "func eddOwnerView")
	for _, section := range []struct {
		name   string
		source string
	}{
		{name: "CaseDuplicatePreviewView DTO", source: dto},
		{name: "dedup presenter", source: presenter},
	} {
		for _, forbidden := range []string{
			"body",
			"Body",
			"CaseNote",
			"case_notes",
			"confidential_comment",
			"ConfidentialComment",
			"EDDRecord",
			"source_of_funds",
			"SourceOfFunds",
			"risk_rationale",
			"RiskRationale",
			"private_notes",
			"audit",
			"diff",
			"password_hash",
			"token_hash",
			"session",
			"checker_private",
			"flag_value",
			"owner_user_id",
			"analyst_user_id",
			"author_user_id",
			"assigned_user_id",
		} {
			if strings.Contains(section.source, forbidden) {
				t.Fatalf("%s references private or internal marker %q:\n%s", section.name, forbidden, section.source)
			}
		}
	}
}

func TestAuditHTTPDTOAndPresenterRejectAML2RawExposure(t *testing.T) {
	sourcePath := filepath.Join("..", "internal", "httpapi", "server.go")
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	source := string(data)

	dto := sourceSection(t, source, "type CaseAuditChangeResponse struct", "type ErrorResponse struct")
	presenter := sourceSection(t, source, "func caseAuditViews", "func duplicatePreviewViews")
	for _, section := range []struct {
		name   string
		source string
	}{
		{name: "Case audit DTOs", source: dto},
		{name: "case audit presenter", source: presenter},
	} {
		for _, forbidden := range []string{
			"`json:\"body",
			"`json:\"confidential_comment",
			"`json:\"diff_json",
			"`json:\"old_hash",
			"`json:\"new_hash",
			"`json:\"password_hash",
			"`json:\"token_hash",
			"`json:\"session",
			"`json:\"checker_private",
			"`json:\"flag_value",
			"`json:\"actor_user_id",
			"`json:\"owner_user_id",
			"`json:\"analyst_user_id",
			"`json:\"author_user_id",
			".ActorUserID",
			".OldHash",
			".NewHash",
			".DiffJSON,",
			"writeJSON(w, http.StatusOK, event)",
			"writeJSON(w, http.StatusOK, events)",
		} {
			if strings.Contains(section.source, forbidden) {
				t.Fatalf("%s contains AML-2 raw-exposure marker %q:\n%s", section.name, forbidden, section.source)
			}
		}
	}

	if !strings.Contains(presenter, `field = "restricted_field"`) {
		t.Fatalf("case audit presenter must collapse sensitive field labels:\n%s", presenter)
	}
}

func TestGraphHTTPDTOAndPresenterStayPublicOnly(t *testing.T) {
	sourcePath := filepath.Join("..", "internal", "httpapi", "server.go")
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	source := string(data)

	dto := sourceSection(t, source, "type GraphEntityView struct", "type ErrorResponse struct")
	presenter := sourceSection(t, source, "func graphEntityView", "func eddOwnerView")
	for _, section := range []struct {
		name   string
		source string
	}{
		{name: "graph DTOs", source: dto},
		{name: "graph presenters", source: presenter},
	} {
		for _, forbidden := range []string{
			"`json:\"body",
			"`json:\"confidential_comment",
			"`json:\"diff_json",
			"`json:\"password_hash",
			"`json:\"token_hash",
			"`json:\"session",
			"`json:\"owner_user_id",
			"`json:\"analyst_user_id",
			"`json:\"author_user_id",
			"`json:\"assigned_user_id",
			"`json:\"counterparty_fingerprint",
			"`json:\"trace_id",
			"`json:\"checker_private",
			"`json:\"flag_value",
			".EDDRecordID",
			".ActorUserID",
			".OwnerUserID",
			".DiffJSON",
			"writeJSON(w, http.StatusOK, summary)",
			"writeJSON(w, http.StatusOK, cases)",
			"writeJSON(w, http.StatusOK, summaries)",
		} {
			if strings.Contains(section.source, forbidden) {
				t.Fatalf("%s contains graph raw-exposure marker %q:\n%s", section.name, forbidden, section.source)
			}
		}
	}
}

func TestAntiAML3GraphRepositorySummariesStayMetadataOnly(t *testing.T) {
	sourcePath := filepath.Join("..", "internal", "graph", "repository.go")
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	source := string(data)

	structs := sourceSection(t, source, "type EntitySummary struct", "func NewRepository")
	queries := sourceSection(t, source, "func (r *Repository) HasEntityAccess", "func normalizeEntityHint")
	for _, section := range []struct {
		name   string
		source string
	}{
		{name: "graph repository summary structs", source: structs},
		{name: "graph repository query methods", source: queries},
	} {
		for _, forbidden := range []string{
			"CaseNote",
			"case_notes",
			".Body",
			" body",
			"confidential_comment",
			"ConfidentialComment",
			"source_of_funds",
			"SourceOfFunds",
			"risk_rationale",
			"RiskRationale",
			"diff_json",
			"DiffJSON",
			"password_hash",
			"token_hash",
			"session",
			"checker_private",
			"flag_value",
			"owner_user_id AS",
			"OwnerUserID",
			"actor_user_id",
			"ActorUserID",
			"analyst_user_id AS",
			"AnalystUserID",
			"author_user_id",
			"AuthorUserID",
		} {
			if strings.Contains(section.source, forbidden) {
				t.Fatalf("%s contains AML-3 graph exposure marker %q:\n%s", section.name, forbidden, section.source)
			}
		}
	}
}

func TestExportingRedactionOutputStaysPublicOnly(t *testing.T) {
	sourcePath := filepath.Join("..", "internal", "exporting", "redaction.go")
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	source := string(data)

	outputs := sourceSection(t, source, "type ExportBundle struct", "func BuildBundle")
	for _, forbidden := range []string{
		"`json:\"body",
		"`json:\"confidential_comment",
		"`json:\"source_of_funds",
		"`json:\"risk_rationale",
		"`json:\"diff_json",
		"`json:\"old_hash",
		"`json:\"new_hash",
		"`json:\"value_hash",
		"`json:\"owner_user_id",
		"`json:\"analyst_user_id",
		"`json:\"author_user_id",
		"`json:\"assigned_user_id",
		"`json:\"password_hash",
		"`json:\"token_hash",
		"`json:\"session",
		"`json:\"checker_private",
		"`json:\"flag_value",
	} {
		if strings.Contains(outputs, forbidden) {
			t.Fatalf("export output struct contains AML-4 forbidden JSON marker %q:\n%s", forbidden, outputs)
		}
	}

	builders := sourceSection(t, source, "func BuildBundle", "func validateExportContext")
	for _, forbidden := range []string{
		".Body",
		".ConfidentialComment",
		".SourceOfFunds",
		".RiskRationale",
		".DiffJSON",
		".OldHash",
		".NewHash",
	} {
		if strings.Contains(builders, forbidden) {
			t.Fatalf("export redaction builder reads forbidden raw private marker %q:\n%s", forbidden, builders)
		}
	}
}

func sourceSection(t *testing.T, source, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("missing source marker %q", startMarker)
	}
	end := strings.Index(source[start:], endMarker)
	if end < 0 {
		t.Fatalf("missing source marker %q after %q", endMarker, startMarker)
	}
	return source[start : start+end]
}
