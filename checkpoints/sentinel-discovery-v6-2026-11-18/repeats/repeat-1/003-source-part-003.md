Review turn 3514562e9524
SOURCE PART 3/4. This is source material from the file map already provided. Inspect each file or fragment now and add it to your working map. Note API/command entry points, cross-file calls, sensitive sources, output sinks, and the checks between them. Track split files across parts without drawing conclusions from an incomplete fragment. Keep this part for the final review.

### `internal/httpapi/server.go (part 1, lines 1-2586)`
```
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	acct "sentinel-aml/internal/account"
	alertrepo "sentinel-aml/internal/alert"
	auditrepo "sentinel-aml/internal/audit"
	"sentinel-aml/internal/auth"
	"sentinel-aml/internal/authz"
	casework "sentinel-aml/internal/casework"
	cust "sentinel-aml/internal/customer"
	"sentinel-aml/internal/edd"
	exportrepo "sentinel-aml/internal/exporting"
	graphrepo "sentinel-aml/internal/graph"
	networkrepo "sentinel-aml/internal/networkroom"
	"sentinel-aml/internal/risk"
	txn "sentinel-aml/internal/transaction"
)

const (
	requestTimeout          = 5 * time.Second
	maxJSONRequestBodyBytes = 1 << 20
)

type AuthService interface {
	Register(context.Context, string, string) (auth.AuthResult, error)
	Login(context.Context, string, string) (auth.AuthResult, error)
	CurrentUser(context.Context, string) (auth.User, error)
}

type CustomerRepository interface {
	Create(context.Context, cust.CreateParams) (cust.Customer, error)
	GetByOwner(context.Context, int64, int64) (cust.Customer, error)
}

type AccountRepository interface {
	Create(context.Context, acct.CreateParams) (acct.Account, error)
	GetByOwner(context.Context, int64, int64) (acct.Account, error)
	ListByCustomerOwner(context.Context, int64, int64) ([]acct.Account, error)
}

type TransactionRepository interface {
	Create(context.Context, txn.CreateParams) (txn.Transaction, error)
	GetByOwner(context.Context, int64, int64) (txn.Transaction, error)
	ListByCustomerOwner(context.Context, int64, int64) ([]txn.Transaction, error)
}

type TransactionRiskService interface {
	ScoreTransaction(context.Context, int64, int64) (risk.Decision, error)
}

type AlertRepository interface {
	ListByOwner(context.Context, int64) ([]alertrepo.Alert, error)
	GetByOwner(context.Context, int64, int64) (alertrepo.Alert, error)
	Claim(context.Context, alertrepo.ClaimParams) (alertrepo.Alert, error)
	Triage(context.Context, alertrepo.TriageParams) (alertrepo.Alert, error)
}

type CaseworkRepository interface {
	CreateFromAlert(context.Context, casework.CreateCaseParams) (casework.Case, error)
	GetByOwner(context.Context, int64, int64) (casework.Case, error)
	UpdateStatus(context.Context, casework.UpdateCaseStatusParams) (casework.Case, error)
	FindDuplicateCandidatesByOwner(context.Context, int64, int64) ([]casework.DuplicateCandidate, error)
	CreateNote(context.Context, casework.CreateNoteParams) (casework.CaseNote, error)
	ListNotesByOwner(context.Context, int64, int64) ([]casework.CaseNote, error)
}

type EDDRepository interface {
	Create(context.Context, edd.CreateParams) (edd.EDDRecord, error)
	GetByOwnerCustomer(context.Context, int64, int64) (edd.EDDRecord, error)
	UpdateByOwnerCustomer(context.Context, edd.UpdateParams) (edd.EDDRecord, error)
}

type AuditRepository interface {
	Create(context.Context, auditrepo.CreateParams) (auditrepo.Event, error)
	ListCaseTimelineByOwner(context.Context, int64, int64) ([]auditrepo.Event, error)
	ListEntityActivityByRequester(context.Context, int64, string) ([]auditrepo.EntityActivityEvent, error)
}

type GraphRepository interface {
	HasEntityAccess(context.Context, int64, string) (bool, error)
	GetEntitySummary(context.Context, int64, string) (graphrepo.EntitySummary, error)
	ListRelatedCases(context.Context, int64, string) ([]graphrepo.RelatedCaseSummary, error)
	ListEDDSummaries(context.Context, int64, string) ([]graphrepo.EDDSummary, error)
}

type ExportRepository interface {
	CreateDispute(context.Context, exportrepo.CreateDisputeParams) (exportrepo.Dispute, error)
	GetDisputeByOwner(context.Context, int64, int64) (exportrepo.Dispute, error)
	CreateExport(context.Context, exportrepo.CreateExportParams) (exportrepo.ExportRecord, error)
	GetExportByOwner(context.Context, int64, int64) (exportrepo.ExportRecord, error)
	CreateExportItem(context.Context, exportrepo.CreateExportItemParams) (exportrepo.ExportItem, error)
}

type NetworkRoomRepository interface {
	JoinRoom(context.Context, networkrepo.JoinRoomParams) (networkrepo.Participant, error)
	ListParticipants(context.Context, int64) ([]networkrepo.Participant, error)
	ListRoomsForUser(context.Context, int64) ([]networkrepo.RoomSummary, error)
	GetRoomForUser(context.Context, int64, int64) (networkrepo.RoomSummary, error)
	ListDossierCases(context.Context, int64, int64) ([]networkrepo.CaseDossierInput, error)
}

type NetworkRoomDirtyCandidateQueue interface {
	EnqueueCaseCandidate(context.Context, string) error
}

type Server struct {
	auth         AuthService
	customers    CustomerRepository
	accounts     AccountRepository
	transactions TransactionRepository
	risk         TransactionRiskService
	alerts       AlertRepository
	cases        CaseworkRepository
	edd          EDDRepository
	audit        AuditRepository
	graph        GraphRepository
	exports      ExportRepository
	networkRooms NetworkRoomRepository
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	User    UserResponse    `json:"user"`
	Session SessionResponse `json:"session"`
}

type MeResponse struct {
	User UserResponse `json:"user"`
}

type UserResponse struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type SessionResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CreateCustomerRequest struct {
	DisplayName        string `json:"display_name"`
	CustomerType       string `json:"customer_type"`
	Country            string `json:"country"`
	RegistrationNumber string `json:"registration_number"`
	RiskLevel          string `json:"risk_level,omitempty"`
	EntityHint         string `json:"entity_hint,omitempty"`
	Status             string `json:"status,omitempty"`
}

type CustomerResponse struct {
	ID                 int64     `json:"id"`
	DisplayName        string    `json:"display_name"`
	CustomerType       string    `json:"customer_type"`
	Country            string    `json:"country"`
	RegistrationNumber string    `json:"registration_number"`
	RiskLevel          string    `json:"risk_level"`
	EntityHint         string    `json:"entity_hint"`
	CreatedAt          time.Time `json:"created_at"`
	Status             string    `json:"status"`
}

type CreateAccountRequest struct {
	IBANLike string `json:"iban_like"`
	Currency string `json:"currency"`
	Status   string `json:"status,omitempty"`
}

type AccountResponse struct {
	ID         int64     `json:"id"`
	CustomerID int64     `json:"customer_id"`
	IBANLike   string    `json:"iban_like"`
	Currency   string    `json:"currency"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

type AccountsResponse struct {
	Accounts []AccountResponse `json:"accounts"`
}

type CreateTransactionRequest struct {
	AccountID               int64  `json:"account_id"`
	CounterpartyName        string `json:"counterparty_name"`
	CounterpartyCountry     string `json:"counterparty_country"`
	CounterpartyFingerprint string `json:"counterparty_fingerprint"`
	Amount                  string `json:"amount"`
	Currency                string `json:"currency"`
	Direction               string `json:"direction"`
	Purpose                 string `json:"purpose"`
	TraceID                 string `json:"trace_id"`
}

type TransactionResponse struct {
	ID                      int64     `json:"id"`
	AccountID               int64     `json:"account_id"`
	CounterpartyName        string    `json:"counterparty_name"`
	CounterpartyCountry     string    `json:"counterparty_country"`
	CounterpartyFingerprint string    `json:"counterparty_fingerprint"`
	Amount                  string    `json:"amount"`
	Currency                string    `json:"currency"`
	Direction               string    `json:"direction"`
	Purpose                 string    `json:"purpose"`
	TraceID                 string    `json:"trace_id"`
	CreatedAt               time.Time `json:"created_at"`
	RiskScore               int       `json:"risk_score"`
}

type TransactionsResponse struct {
	Transactions []TransactionResponse `json:"transactions"`
}

type AlertResponse struct {
	ID             int64     `json:"id"`
	TransactionID  int64     `json:"transaction_id"`
	CustomerID     int64     `json:"customer_id"`
	RuleCode       string    `json:"rule_code"`
	RiskScore      int       `json:"risk_score"`
	Status         string    `json:"status"`
	AssignedUserID *int64    `json:"assigned_user_id,omitempty"`
	TypologyHint   string    `json:"typology_hint"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type AlertsResponse struct {
	Alerts []AlertResponse `json:"alerts"`
}

type TriageAlertRequest struct {
	Status string `json:"status"`
}

type CreateCaseRequest struct {
	PublicSummary string `json:"public_summary,omitempty"`
	Status        string `json:"status,omitempty"`
	DedupHint     string `json:"dedup_hint,omitempty"`
}

type CaseResponse struct {
	ID            int64     `json:"id"`
	CustomerID    int64     `json:"customer_id"`
	AlertID       int64     `json:"alert_id"`
	Status        string    `json:"status"`
	PublicSummary string    `json:"public_summary"`
	RiskScore     int       `json:"risk_score"`
	TypologyHint  string    `json:"typology_hint"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type UpdateCaseStatusRequest struct {
	Status string `json:"status"`
}

type CreateCaseNoteRequest struct {
	Visibility string `json:"visibility,omitempty"`
	Body       string `json:"body"`
}

type CaseNoteResponse struct {
	ID           int64     `json:"id"`
	CaseID       int64     `json:"case_id"`
	AuthorUserID int64     `json:"author_user_id"`
	Visibility   string    `json:"visibility"`
	Body         string    `json:"body"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CaseNotesResponse struct {
	Notes []CaseNoteResponse `json:"notes"`
}

type CaseDuplicatePreviewView struct {
	CaseID           int64    `json:"case_id"`
	PublicSummary    string   `json:"public_summary"`
	RiskTags         []string `json:"risk_tags"`
	OverlapScore     int      `json:"overlap_score"`
	MatchExplanation string   `json:"match_explanation"`
}

type CaseDuplicateCandidatesResponse struct {
	Candidates []CaseDuplicatePreviewView `json:"candidates"`
}

type CaseDuplicateMergePreviewResponse struct {
	SourceCaseID int64                    `json:"source_case_id"`
	Candidate    CaseDuplicatePreviewView `json:"candidate"`
}

type CreateEDDRequest struct {
	SourceOfFunds       string `json:"source_of_funds"`
	RiskRationale       string `json:"risk_rationale"`
	ConfidentialComment string `json:"confidential_comment"`
	ReviewStatus        string `json:"review_status,omitempty"`
}

type UpdateEDDRequest struct {
	SourceOfFunds       string `json:"source_of_funds"`
	RiskRationale       string `json:"risk_rationale"`
	ConfidentialComment string `json:"confidential_comment"`
	ReviewStatus        string `json:"review_status"`
}

type EDDOwnerView struct {
	ID                  int64     `json:"id"`
	CustomerID          int64     `json:"customer_id"`
	AnalystUserID       int64     `json:"analyst_user_id"`
	SourceOfFunds       string    `json:"source_of_funds"`
	RiskRationale       string    `json:"risk_rationale"`
	ConfidentialComment string    `json:"confidential_comment"`
	ReviewStatus        string    `json:"review_status"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type CaseAuditChangeResponse struct {
	Field    string `json:"field"`
	Old      string `json:"old,omitempty"`
	New      string `json:"new,omitempty"`
	Redacted bool   `json:"redacted"`
}

type CaseAuditView struct {
	ID              int64                     `json:"id"`
	ObjectType      string                    `json:"object_type"`
	ObjectID        int64                     `json:"object_id"`
	EventType       string                    `json:"event_type"`
	PublicMessage   string                    `json:"public_message"`
	Changes         []CaseAuditChangeResponse `json:"changes"`
	CreatedAt       time.Time                 `json:"created_at"`
	VisibilityScope string                    `json:"visibility_scope"`
}

type CaseTimelineResponse struct {
	Events []CaseAuditView `json:"events"`
}

type EntityActivityView struct {
	CaseID          int64                     `json:"case_id"`
	CustomerID      int64                     `json:"customer_id"`
	EntityHint      string                    `json:"entity_hint"`
	PublicSummary   string                    `json:"public_summary"`
	ActivitySubject string                    `json:"activity_subject,omitempty"`
	ActivityLevel   string                    `json:"activity_detail_level,omitempty"`
	ActivityText    string                    `json:"activity_narrative,omitempty"`
	ActivitySource  string                    `json:"activity_provenance,omitempty"`
	ObjectType      string                    `json:"object_type"`
	ObjectID        int64                     `json:"object_id"`
	EventType       string                    `json:"event_type"`
	PublicMessage   string                    `json:"public_message"`
	Changes         []CaseAuditChangeResponse `json:"changes"`
	CreatedAt       time.Time                 `json:"created_at"`
	VisibilityScope string                    `json:"visibility_scope"`
}

type EntityActivityResponse struct {
	Activities []EntityActivityView `json:"activities"`
}

type GraphEntityView struct {
	EntityHint    string    `json:"entity_hint"`
	RelationType  string    `json:"relation_type"`
	CustomerCount int       `json:"customer_count"`
	CaseCount     int       `json:"case_count"`
	HighestRisk   int       `json:"highest_risk"`
	RiskTags      []string  `json:"risk_tags"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type GraphRelatedCaseView struct {
	CaseID        int64     `json:"case_id"`
	CustomerID    int64     `json:"customer_id"`
	EntityHint    string    `json:"entity_hint"`
	DisplayName   string    `json:"display_name"`
	Country       string    `json:"country"`
	Status        string    `json:"status"`
	PublicSummary string    `json:"public_summary"`
	RiskScore     int       `json:"risk_score"`
	TypologyHint  string    `json:"typology_hint"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type GraphRelatedCasesResponse struct {
	Cases []GraphRelatedCaseView `json:"cases"`
}

type EDDGraphSummaryView struct {
	CustomerID   int64     `json:"customer_id"`
	EntityHint   string    `json:"entity_hint"`
	ReviewStatus string    `json:"review_status"`
	RiskTags     []string  `json:"risk_tags"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type EDDGraphSummariesResponse struct {
	Summaries []EDDGraphSummaryView `json:"summaries"`
}

type CreateExportRequest struct {
	Purpose       string   `json:"purpose"`
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
}

type CreateDisputeRequest struct {
	CaseID int64  `json:"case_id"`
	Reason string `json:"reason"`
	Status string `json:"status,omitempty"`
}

type DisputeResponse struct {
	ID                int64     `json:"id"`
	CaseID            int64     `json:"case_id"`
	Status            string    `json:"status"`
	Reason            string    `json:"reason"`
	ResolutionSummary string    `json:"resolution_summary"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type ExportResponse struct {
	ID              int64            `json:"id"`
	RootCaseID      int64            `json:"root_case_id"`
	DisputeID       int64            `json:"dispute_id,omitempty"`
	Purpose         string           `json:"purpose"`
	Status          string           `json:"status"`
	RedactionPolicy string           `json:"redaction_policy"`
	Bundle          ExportBundleView `json:"bundle"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	ExpiresAt       time.Time        `json:"expires_at"`
}

type ExportBundleView struct {
	Purpose         string                   `json:"purpose"`
	RedactionPolicy string                   `json:"redaction_policy"`
	GeneratedAt     time.Time                `json:"generated_at"`
	RootCase        ExportCaseShellView      `json:"root_case"`
	LinkedCases     []ExportCaseShellView    `json:"linked_cases"`
	LinkedEvidence  []map[string]any         `json:"linked_evidence,omitempty"`
	AuditSummaries  []ExportAuditSummaryView `json:"audit_summaries"`
	EDDSummaries    []ExportEDDSummaryView   `json:"edd_summaries"`
	Items           []ExportItemMetadataView `json:"items"`
}

type ExportCaseShellView struct {
	CaseID        int64     `json:"case_id"`
	CustomerID    int64     `json:"customer_id"`
	Status        string    `json:"status"`
	PublicSummary string    `json:"public_summary"`
	RiskScore     int       `json:"risk_score"`
	TypologyHint  string    `json:"typology_hint"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type ExportAuditSummaryView struct {
	EventID       int64     `json:"event_id"`
	ObjectType    string    `json:"object_type"`
	ObjectID      int64     `json:"object_id"`
	EventType     string    `json:"event_type"`
	PublicMessage string    `json:"public_message"`
	ChangedFields []string  `json:"changed_fields"`
	CreatedAt     time.Time `json:"created_at"`
}

type ExportEDDSummaryView struct {
	RecordID     int64     `json:"record_id"`
	CustomerID   int64     `json:"customer_id"`
	ReviewStatus string    `json:"review_status"`
	RiskTags     []string  `json:"risk_tags"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ExportItemMetadataView struct {
	ItemType        string `json:"item_type"`
	ObjectType      string `json:"object_type"`
	ObjectID        int64  `json:"object_id"`
	Relation        string `json:"relation"`
	RedactionPolicy string `json:"redaction_policy"`
}

type NetworkRoomsResponse struct {
	Rooms []NetworkRoomSummaryView `json:"rooms"`
}

type NetworkRoomDetailResponse struct {
	Room         NetworkRoomSummaryView       `json:"room"`
	Participants []NetworkRoomParticipantView `json:"participants"`
}

type NetworkRoomSummaryView struct {
	ID               int64     `json:"id"`
	RoomKey          string    `json:"room_key"`
	EntityHint       string    `json:"entity_hint"`
	TypologyHint     string    `json:"typology_hint"`
	Status           string    `json:"status"`
	PublicSummary    string    `json:"public_summary"`
	PublicRiskTags   []string  `json:"public_risk_tags"`
	CaseCount        int       `json:"case_count"`
	ParticipantCount int       `json:"participant_count"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type NetworkRoomParticipantView struct {
	ID              int64     `json:"id"`
	RoomID          int64     `json:"room_id"`
	UserID          int64     `json:"user_id"`
	ParticipantRole string    `json:"participant_role"`
	JoinedAt        time.Time `json:"joined_at"`
}

type NetworkRoomDossierView struct {
	Room           NetworkRoomSummaryView `json:"room"`
	Cases          []NetworkRoomCaseView  `json:"cases"`
	ScopePolicy    string                 `json:"scope_policy"`
	CoveragePolicy string                 `json:"coverage_policy"`
}

type NetworkRoomCaseView struct {
	CaseID                int64     `json:"case_id"`
	CustomerID            int64     `json:"customer_id"`
	OwnedByRequester      bool      `json:"owned_by_requester"`
	Status                string    `json:"status"`
	PublicSummary         string    `json:"public_summary"`
	RiskScore             int       `json:"risk_score"`
	TypologyHint          string    `json:"typology_hint"`
	PublicRiskTags        []string  `json:"public_risk_tags"`
	ScopeCoverageComplete bool      `json:"scope_coverage_complete"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type Option func(*Server)

func WithDomainRepositories(customers CustomerRepository, accounts AccountRepository, transactions TransactionRepository) Option {
	return func(s *Server) {
		s.customers = customers
		s.accounts = accounts
		s.transactions = transactions
	}
}

func WithTransactionRiskService(transactionRisk TransactionRiskService) Option {
	return func(s *Server) {
		s.risk = transactionRisk
	}
}

func WithInvestigationRepositories(alerts AlertRepository, cases CaseworkRepository) Option {
	return func(s *Server) {
		s.alerts = alerts
		s.cases = cases
	}
}

func WithEDDRepository(repository EDDRepository) Option {
	return func(s *Server) {
		s.edd = repository
	}
}

func WithAuditRepository(repository AuditRepository) Option {
	return func(s *Server) {
		s.audit = repository
	}
}

func WithGraphRepository(repository GraphRepository) Option {
	return func(s *Server) {
		s.graph = repository
	}
}

func WithExportRepository(repository ExportRepository) Option {
	return func(s *Server) {
		s.exports = repository
	}
}

func WithNetworkRoomRepository(repository NetworkRoomRepository) Option {
	return func(s *Server) {
		s.networkRooms = repository
	}
}

func NewServer(authService AuthService, options ...Option) *Server {
	server := &Server{auth: authService}
	for _, option := range options {
		option(server)
	}
	return server
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", HealthHandler)
	mux.HandleFunc("/readyz", HealthHandler)
	mux.HandleFunc("/api/auth/register", s.handleRegister)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/me", s.requireAuth(s.handleMe))
	if s.domainReady() {
		mux.HandleFunc("/api/customers", s.requireAuth(s.handleCustomersRoot))
		mux.HandleFunc("/api/customers/", s.requireAuth(s.handleCustomersSubtree))
		mux.HandleFunc("/api/accounts/", s.requireAuth(s.handleAccountsSubtree))
		mux.HandleFunc("/api/transactions", s.requireAuth(s.handleTransactionsRoot))
		mux.HandleFunc("/api/transactions/", s.requireAuth(s.handleTransactionsSubtree))
	}
	if s.investigationReady() {
		mux.HandleFunc("/api/alerts/queue", s.requireAuth(s.handleAlertsQueue))
		mux.HandleFunc("/api/alerts/", s.requireAuth(s.handleAlertsSubtree))
		mux.HandleFunc("/api/cases/", s.requireAuth(s.handleCasesSubtree))
	}
	if s.audit != nil {
		mux.HandleFunc("/api/entities/", s.requireAuth(s.handleEntitiesSubtree))
	}
	if s.graphReady() {
		mux.HandleFunc("/api/graph/entities/", s.requireAuth(s.handleGraphEntitiesSubtree))
	}
	if s.exportReady() {
		mux.HandleFunc("/api/exports", s.requireAuth(s.handleExportsRoot))
		mux.HandleFunc("/api/exports/", s.requireAuth(s.handleExportsSubtree))
		mux.HandleFunc("/api/disputes", s.requireAuth(s.handleDisputesRoot))
		mux.HandleFunc("/api/disputes/", s.requireAuth(s.handleDisputesSubtree))
	}
	if s.networkRoomReady() {
		mux.HandleFunc("/api/network/rooms", s.requireAuth(s.handleNetworkRoomsRoot))
		mux.HandleFunc("/api/network/rooms/", s.requireAuth(s.handleNetworkRoomsSubtree))
	}
	return mux
}

func (s *Server) domainReady() bool {
	return s.customers != nil && s.accounts != nil && s.transactions != nil
}

func (s *Server) investigationReady() bool {
	return s.alerts != nil && s.cases != nil
}

func (s *Server) graphReady() bool {
	return s.graph != nil
}

func (s *Server) exportReady() bool {
	return s.exports != nil && s.cases != nil
}

func (s *Server) networkRoomReady() bool {
	return s.networkRooms != nil
}

func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "sentinel-aml",
		"status":  "ok",
		"scope":   "operational-health-only",
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}
	req, ok := decodeAuthRequest(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	result, err := s.auth.Register(ctx, req.Username, req.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, authResultResponse(result))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}
	req, ok := decodeAuthRequest(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	result, err := s.auth.Login(ctx, req.Username, req.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, authResultResponse(result))
}

func (s *Server) requireAuth(next func(http.ResponseWriter, *http.Request, auth.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthenticated"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		user, err := s.auth.CurrentUser(ctx, token)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		principal := authz.Principal{
			UserID:   user.ID,
			Username: user.Username,
			Role:     user.Role,
			Status:   user.Status,
		}
		next(w, r.WithContext(authz.WithPrincipal(r.Context(), principal)), user)
	}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}
	if _, ok := authz.PrincipalFromContext(r.Context()); !ok {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthenticated"})
		return
	}
	writeJSON(w, http.StatusOK, MeResponse{User: userResponse(user)})
}

func (s *Server) handleCustomersRoot(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.URL.Path != "/api/customers" {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	var req CreateCustomerRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	customer, err := s.customers.Create(ctx, cust.CreateParams{
		OwnerUserID:        user.ID,
		DisplayName:        req.DisplayName,
		CustomerType:       req.CustomerType,
		Country:            req.Country,
		RegistrationNumber: req.RegistrationNumber,
		RiskLevel:          req.RiskLevel,
		EntityHint:         req.EntityHint,
		Status:             req.Status,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, customerResponse(customer))
}

func (s *Server) handleCustomersSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/customers/"))
	if len(parts) == 0 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}

	customerID, ok := parseID(w, parts[0])
	if !ok {
		return
	}

	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
			return
		}
		s.handleGetCustomer(w, r, user, customerID)
	case len(parts) == 2 && parts[1] == "accounts":
		s.handleCustomerAccounts(w, r, user, customerID)
	case len(parts) == 2 && parts[1] == "transactions":
		s.handleCustomerTransactions(w, r, user, customerID)
	case len(parts) == 2 && parts[1] == "edd" && s.edd != nil:
		s.handleCustomerEDD(w, r, user, customerID)
	case len(parts) == 2 && parts[1] == "activity":
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
	default:
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
	}
}

func (s *Server) handleGetCustomer(w http.ResponseWriter, r *http.Request, user auth.User, customerID int64) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	customer, err := s.customers.GetByOwner(ctx, user.ID, customerID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, customerResponse(customer))
}

func (s *Server) handleCustomerAccounts(w http.ResponseWriter, r *http.Request, user auth.User, customerID int64) {
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		accounts, err := s.accounts.ListByCustomerOwner(ctx, user.ID, customerID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, AccountsResponse{Accounts: accountResponses(accounts)})
	case http.MethodPost:
		var req CreateAccountRequest
		if !decodeJSONRequest(w, r, &req) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		account, err := s.accounts.Create(ctx, acct.CreateParams{
			OwnerUserID: user.ID,
			CustomerID:  customerID,
			IBANLike:    req.IBANLike,
			Currency:    req.Currency,
			Status:      req.Status,
		})
		if err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, accountResponse(account))
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
	}
}

func (s *Server) handleCustomerTransactions(w http.ResponseWriter, r *http.Request, user auth.User, customerID int64) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	transactions, err := s.transactions.ListByCustomerOwner(ctx, user.ID, customerID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, TransactionsResponse{Transactions: transactionResponses(transactions)})
}

func (s *Server) handleCustomerEDD(w http.ResponseWriter, r *http.Request, user auth.User, customerID int64) {
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		record, err := s.edd.GetByOwnerCustomer(ctx, user.ID, customerID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, eddOwnerView(record))
	case http.MethodPost:
		var req CreateEDDRequest
		if !decodeJSONRequest(w, r, &req) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		record, err := s.edd.Create(ctx, edd.CreateParams{
			OwnerUserID:         user.ID,
			CustomerID:          customerID,
			AnalystUserID:       user.ID,
			SourceOfFunds:       req.SourceOfFunds,
			RiskRationale:       req.RiskRationale,
			ConfidentialComment: req.ConfidentialComment,
			ReviewStatus:        req.ReviewStatus,
		})
		if err != nil {
			writeDomainError(w, err)
			return
		}
		if err := s.recordAudit(ctx, auditrepo.CreateParams{
			ActorUserID:   user.ID,
			ObjectType:    "edd_record",
			ObjectID:      record.ID,
			EventType:     "created",
			PublicMessage: "edd record created",
			FieldChanges: []auditrepo.FieldChange{
				{Field: "source_of_funds", NewValue: record.SourceOfFunds},
				{Field: "risk_rationale", NewValue: record.RiskRationale},
				{Field: "edd_record.confidential_comment", NewValue: record.ConfidentialComment},
				{Field: "review_status", NewValue: record.ReviewStatus},
			},
		}); err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, eddOwnerView(record))
	case http.MethodPatch:
		var req UpdateEDDRequest
		if !decodeJSONRequest(w, r, &req) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		var previous edd.EDDRecord
		if s.audit != nil {
			var err error
			previous, err = s.edd.GetByOwnerCustomer(ctx, user.ID, customerID)
			if err != nil {
				writeDomainError(w, err)
				return
			}
		}
		record, err := s.edd.UpdateByOwnerCustomer(ctx, edd.UpdateParams{
			OwnerUserID:         user.ID,
			CustomerID:          customerID,
			AnalystUserID:       user.ID,
			SourceOfFunds:       req.SourceOfFunds,
			RiskRationale:       req.RiskRationale,
			ConfidentialComment: req.ConfidentialComment,
			ReviewStatus:        req.ReviewStatus,
		})
		if err != nil {
			writeDomainError(w, err)
			return
		}
		if err := s.recordAudit(ctx, auditrepo.CreateParams{
			ActorUserID:   user.ID,
			ObjectType:    "edd_record",
			ObjectID:      record.ID,
			EventType:     "updated",
			PublicMessage: "edd record updated",
			FieldChanges: []auditrepo.FieldChange{
				{Field: "source_of_funds", OldValue: previous.SourceOfFunds, NewValue: record.SourceOfFunds},
				{Field: "risk_rationale", OldValue: previous.RiskRationale, NewValue: record.RiskRationale},
				{Field: "edd_record.confidential_comment", OldValue: previous.ConfidentialComment, NewValue: record.ConfidentialComment},
				{Field: "review_status", OldValue: previous.ReviewStatus, NewValue: record.ReviewStatus},
			},
		}); err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, eddOwnerView(record))
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
	}
}

func (s *Server) handleAccountsSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/accounts/"))
	if len(parts) != 1 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	accountID, ok := parseID(w, parts[0])
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	account, err := s.accounts.GetByOwner(ctx, user.ID, accountID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accountResponse(account))
}

func (s *Server) handleTransactionsRoot(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.URL.Path != "/api/transactions" {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	var req CreateTransactionRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	transaction, err := s.transactions.Create(ctx, txn.CreateParams{
		OwnerUserID:             user.ID,
		AccountID:               req.AccountID,
		CounterpartyName:        req.CounterpartyName,
		CounterpartyCountry:     req.CounterpartyCountry,
		CounterpartyFingerprint: req.CounterpartyFingerprint,
		Amount:                  req.Amount,
		Currency:                req.Currency,
		Direction:               req.Direction,
		Purpose:                 req.Purpose,
		TraceID:                 req.TraceID,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if s.risk != nil {
		decision, err := s.risk.ScoreTransaction(ctx, user.ID, transaction.ID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		if decision.Transaction.ID != 0 {
			transaction = decision.Transaction
		}
	}
	writeJSON(w, http.StatusCreated, transactionResponse(transaction))
}

func (s *Server) handleTransactionsSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/transactions/"))
	if len(parts) != 1 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	transactionID, ok := parseID(w, parts[0])
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	transaction, err := s.transactions.GetByOwner(ctx, user.ID, transactionID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, transactionResponse(transaction))
}

func (s *Server) handleAlertsQueue(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.URL.Path != "/api/alerts/queue" {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	alerts, err := s.alerts.ListByOwner(ctx, user.ID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, AlertsResponse{Alerts: alertResponses(alerts)})
}

func (s *Server) handleAlertsSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/alerts/"))
	if len(parts) == 0 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}

	alertID, ok := parseID(w, parts[0])
	if !ok {
		return
	}

	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
			return
		}
		s.handleGetAlert(w, r, user, alertID)
	case len(parts) == 2 && parts[1] == "claim":
		s.handleClaimAlert(w, r, user, alertID)
	case len(parts) == 2 && parts[1] == "triage":
		s.handleTriageAlert(w, r, user, alertID)
	case len(parts) == 2 && parts[1] == "case":
		s.handleCreateCaseFromAlert(w, r, user, alertID)
	default:
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
	}
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request, user auth.User, alertID int64) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	alert, err := s.alerts.GetByOwner(ctx, user.ID, alertID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, alertResponse(alert))
}

func (s *Server) handleClaimAlert(w http.ResponseWriter, r *http.Request, user auth.User, alertID int64) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	alert, err := s.alerts.Claim(ctx, alertrepo.ClaimParams{
		OwnerUserID:    user.ID,
		AlertID:        alertID,
		AssignedUserID: user.ID,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, alertResponse(alert))
}

func (s *Server) handleTriageAlert(w http.ResponseWriter, r *http.Request, user auth.User, alertID int64) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	var req TriageAlertRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	alert, err := s.alerts.Triage(ctx, alertrepo.TriageParams{
		OwnerUserID: user.ID,
		AlertID:     alertID,
		Status:      req.Status,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, alertResponse(alert))
}

func (s *Server) handleCreateCaseFromAlert(w http.ResponseWriter, r *http.Request, user auth.User, alertID int64) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	var req CreateCaseRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	investigationCase, err := s.cases.CreateFromAlert(ctx, casework.CreateCaseParams{
		OwnerUserID:   user.ID,
		AlertID:       alertID,
		PublicSummary: req.PublicSummary,
		Status:        req.Status,
		DedupHint:     req.DedupHint,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if err := s.recordAudit(ctx, auditrepo.CreateParams{
		ActorUserID:   user.ID,
		ObjectType:    "case",
		ObjectID:      investigationCase.ID,
		EventType:     "created",
		PublicMessage: "case created",
		FieldChanges: []auditrepo.FieldChange{
			{Field: "status", NewValue: investigationCase.Status},
			{Field: "public_summary", NewValue: investigationCase.PublicSummary},
		},
	}); err != nil {
		writeDomainError(w, err)
		return
	}
	if queue, ok := s.networkRooms.(NetworkRoomDirtyCandidateQueue); ok {
		if err := queue.EnqueueCaseCandidate(ctx, strconv.FormatInt(investigationCase.ID, 10)); err != nil {
			slog.Default().Warn("network-room dirty candidate enqueue failed", "case_id", investigationCase.ID, "error", err)
		}
	}
	writeJSON(w, http.StatusCreated, caseResponse(investigationCase))
}

func (s *Server) handleCasesSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/cases/"))
	if len(parts) == 0 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}

	caseID, ok := parseID(w, parts[0])
	if !ok {
		return
	}

	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
			return
		}
		s.handleGetCase(w, r, user, caseID)
	case len(parts) == 2 && parts[1] == "notes":
		s.handleCaseNotes(w, r, user, caseID)
	case len(parts) == 2 && parts[1] == "status":
		s.handleUpdateCaseStatus(w, r, user, caseID)
	case len(parts) == 2 && parts[1] == "duplicates":
		s.handleCaseDuplicateCandidates(w, r, user, caseID)
	case len(parts) == 2 && parts[1] == "timeline" && s.audit != nil:
		s.handleCaseTimeline(w, r, user, caseID)
	case len(parts) == 2 && parts[1] == "exports" && s.exports != nil:
		s.handleCreateCaseExport(w, r, user, caseID, 0)
	case len(parts) == 4 && parts[1] == "duplicates" && parts[3] == "merge-preview":
		duplicateCaseID, ok := parseID(w, parts[2])
		if !ok {
			return
		}
		s.handleCaseDuplicateMergePreview(w, r, user, caseID, duplicateCaseID)
	default:
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
	}
}

func (s *Server) handleGetCase(w http.ResponseWriter, r *http.Request, user auth.User, caseID int64) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	investigationCase, err := s.cases.GetByOwner(ctx, user.ID, caseID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, caseResponse(investigationCase))
}

func (s *Server) handleCaseTimeline(w http.ResponseWriter, r *http.Request, user auth.User, caseID int64) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	if _, err := s.cases.GetByOwner(ctx, user.ID, caseID); err != nil {
		writeDomainError(w, err)
		return
	}
	events, err := s.audit.ListCaseTimelineByOwner(ctx, user.ID, caseID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, CaseTimelineResponse{Events: caseAuditViews(events)})
}

func (s *Server) handleEntitiesSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/entities/"))
	if len(parts) != 2 || parts[1] != "activity" {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	entityHint, err := urlPathUnescape(parts[0])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid_path"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	events, err := s.audit.ListEntityActivityByRequester(ctx, user.ID, entityHint)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	activities, err := s.entityActivityViewsForActivityStream(ctx, user.ID, entityHint, events)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, EntityActivityResponse{Activities: activities})
}

func (s *Server) handleCaseDuplicateCandidates(w http.ResponseWriter, r *http.Request, user auth.User, caseID int64) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	candidates, err := s.cases.FindDuplicateCandidatesByOwner(ctx, user.ID, caseID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, CaseDuplicateCandidatesResponse{Candidates: duplicatePreviewViews(candidates)})
}

func (s *Server) handleCaseDuplicateMergePreview(w http.ResponseWriter, r *http.Request, user auth.User, sourceCaseID, duplicateCaseID int64) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	candidates, err := s.cases.FindDuplicateCandidatesByOwner(ctx, user.ID, sourceCaseID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	for _, candidate := range candidates {
		if candidate.CaseID == duplicateCaseID {
			response, err := s.caseDuplicateMergePreviewResponse(ctx, user.ID, sourceCaseID, candidate)
			if err != nil {
				writeDomainError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, response)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
}

func (s *Server) handleCaseNotes(w http.ResponseWriter, r *http.Request, user auth.User, caseID int64) {
	switch r.Method {
	case http.MethodGet:
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		notes, err := s.cases.ListNotesByOwner(ctx, user.ID, caseID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, CaseNotesResponse{Notes: caseNoteResponses(notes)})
	case http.MethodPost:
		var req CreateCaseNoteRequest
		if !decodeJSONRequest(w, r, &req) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		note, err := s.cases.CreateNote(ctx, casework.CreateNoteParams{
			OwnerUserID:  user.ID,
			CaseID:       caseID,
			AuthorUserID: user.ID,
			Visibility:   req.Visibility,
			Body:         req.Body,
		})
		if err != nil {
			writeDomainError(w, err)
			return
		}
		if err := s.recordAudit(ctx, auditrepo.CreateParams{
			ActorUserID:   user.ID,
			ObjectType:    "case_note",
			ObjectID:      note.ID,
			EventType:     "created",
			PublicMessage: "case note created",
			FieldChanges: []auditrepo.FieldChange{
				{Field: "case_note.body", NewValue: note.Body},
				{Field: "visibility", NewValue: note.Visibility},
			},
		}); err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, caseNoteResponse(note))
	default:
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
	}
}

func (s *Server) handleUpdateCaseStatus(w http.ResponseWriter, r *http.Request, user auth.User, caseID int64) {
	if r.Method != http.MethodPatch {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	var req UpdateCaseStatusRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	investigationCase, err := s.cases.UpdateStatus(ctx, casework.UpdateCaseStatusParams{
		OwnerUserID: user.ID,
		CaseID:      caseID,
		Status:      req.Status,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if err := s.recordAudit(ctx, auditrepo.CreateParams{
		ActorUserID:   user.ID,
		ObjectType:    "case",
		ObjectID:      investigationCase.ID,
		EventType:     "status_changed",
		PublicMessage: "case status changed",
		FieldChanges: []auditrepo.FieldChange{
			{Field: "status", NewValue: investigationCase.Status},
		},
	}); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, caseResponse(investigationCase))
}

func (s *Server) handleCreateCaseExport(w http.ResponseWriter, r *http.Request, user auth.User, caseID, disputeID int64) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	var req CreateExportRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	bundle, err := s.buildExportBundle(ctx, user.ID, caseID, disputeID, req)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		writeDomainError(w, exportrepo.ErrInvalidInput)
		return
	}
	record, err := s.exports.CreateExport(ctx, exportrepo.CreateExportParams{
		OwnerUserID: user.ID,
		RootCaseID:  caseID,
		DisputeID:   disputeID,
		Purpose:     req.Purpose,
		Status:      "GENERATED",
		BundleJSON:  string(bundleJSON),
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	for _, item := range bundle.Items {
		itemJSON, err := json.Marshal(item)
		if err != nil {
			writeDomainError(w, exportrepo.ErrInvalidInput)
			return
		}
		if _, err := s.exports.CreateExportItem(ctx, exportrepo.CreateExportItemParams{
			OwnerUserID: user.ID,
			ExportID:    record.ID,
			ItemType:    item.ItemType,
			ObjectType:  item.ObjectType,
			ObjectID:    item.ObjectID,
			Relation:    item.Relation,
			PayloadJSON: string(itemJSON),
		}); err != nil {
			writeDomainError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, exportResponse(record, bundle))
}

func (s *Server) handleExportsSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}
	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/exports/"))
	if len(parts) != 1 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	exportID, ok := parseID(w, parts[0])
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	record, err := s.exports.GetExportByOwner(ctx, user.ID, exportID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	bundle, err := decodeExportBundle(record.BundleJSON)
	if err != nil {
		writeDomainError(w, exportrepo.ErrInvalidInput)
		return
	}
	writeJSON(w, http.StatusOK, exportResponse(record, bundle))
}

func (s *Server) handleExportsRoot(w http.ResponseWriter, _ *http.Request, _ auth.User) {
	writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
}

func (s *Server) handleDisputesRoot(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.URL.Path != "/api/disputes" {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}
	var req CreateDisputeRequest
	if !decodeJSONRequest(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	dispute, err := s.exports.CreateDispute(ctx, exportrepo.CreateDisputeParams{
		OwnerUserID: user.ID,
		CaseID:      req.CaseID,
		Status:      req.Status,
		Reason:      req.Reason,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, disputeResponse(dispute))
}

func (s *Server) handleDisputesSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/disputes/"))
	if len(parts) != 2 || parts[1] != "export" {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	disputeID, ok := parseID(w, parts[0])
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	dispute, err := s.exports.GetDisputeByOwner(ctx, user.ID, disputeID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.handleCreateCaseExport(w, r.WithContext(ctx), user, dispute.CaseID, dispute.ID)
}

func (s *Server) handleGraphEntitiesSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}

	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/graph/entities/"))
	if len(parts) == 0 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}

	entityHint := parts[0]
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	allowed, err := s.graph.HasEntityAccess(ctx, user.ID, entityHint)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if !allowed {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}

	switch {
	case len(parts) == 1:
		s.handleGraphEntity(w, ctx, user, entityHint)
	case len(parts) == 2 && parts[1] == "related-cases":
		s.handleGraphRelatedCases(w, ctx, user, entityHint)
	case len(parts) == 2 && parts[1] == "edd-summaries":
		s.handleGraphEDDSummaries(w, ctx, user, entityHint)
	default:
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
	}
}

func (s *Server) handleGraphEntity(w http.ResponseWriter, ctx context.Context, user auth.User, entityHint string) {
	summary, err := s.graph.GetEntitySummary(ctx, user.ID, entityHint)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, graphEntityView(summary))
}

func (s *Server) handleGraphRelatedCases(w http.ResponseWriter, ctx context.Context, user auth.User, entityHint string) {
	cases, err := s.graph.ListRelatedCases(ctx, user.ID, entityHint)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, GraphRelatedCasesResponse{Cases: graphRelatedCaseViews(cases)})
}

func (s *Server) handleGraphEDDSummaries(w http.ResponseWriter, ctx context.Context, user auth.User, entityHint string) {
	summaries, err := s.graph.ListEDDSummaries(ctx, user.ID, entityHint)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	response, err := s.graphEDDSummariesResponseForEntityReview(ctx, user.ID, entityHint, summaries)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleNetworkRoomsRoot(w http.ResponseWriter, r *http.Request, user auth.User) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	rooms, err := s.networkRooms.ListRoomsForUser(ctx, user.ID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, NetworkRoomsResponse{Rooms: networkRoomSummaryViews(rooms)})
}

func (s *Server) handleNetworkRoomsSubtree(w http.ResponseWriter, r *http.Request, user auth.User) {
	parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/network/rooms/"))
	if len(parts) < 1 {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
		return
	}
	roomID, ok := parseID(w, parts[0])
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	switch {
	case len(parts) == 1:
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
			return
		}
		room, err := s.networkRooms.GetRoomForUser(ctx, user.ID, roomID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		participants, err := s.networkRooms.ListParticipants(ctx, roomID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, NetworkRoomDetailResponse{
			Room:         networkRoomSummaryView(room),
			Participants: networkRoomParticipantViews(participants),
		})
	case len(parts) == 2 && parts[1] == "join":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
			return
		}
		participant, err := s.networkRooms.JoinRoom(ctx, networkrepo.JoinRoomParams{RoomID: roomID, UserID: user.ID})
		if err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, networkRoomParticipantView(participant))
	case len(parts) == 2 && parts[1] == "dossier":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method_not_allowed"})
			return
		}
		room, err := s.networkRooms.GetRoomForUser(ctx, user.ID, roomID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		dossier, err := s.networkRoomDossierResponseForSharedRoom(ctx, user.ID, roomID, room)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, dossier)
	default:
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
	}
}

func decodeAuthRequest(w http.ResponseWriter, r *http.Request) (RegisterRequest, bool) {
	var req RegisterRequest
	if !decodeJSONRequest(w, r, &req) {
		return RegisterRequest{}, false
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid_request"})
		return RegisterRequest{}, false
	}
	return req, true
}

func decodeJSONRequest(w http.ResponseWriter, r *http.Request, dest any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONRequestBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid_json"})
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid_json"})
		return false
	}
	return true
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return parts[1], true
}

func authResultResponse(result auth.AuthResult) AuthResponse {
	return AuthResponse{
		User: userResponse(result.User),
		Session: SessionResponse{
			Token:     result.RawToken,
			ExpiresAt: result.ExpiresAt,
		},
	}
}

func userResponse(user auth.User) UserResponse {
	return UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Role:      user.Role,
		Status:    user.Status,
		CreatedAt: user.CreatedAt,
	}
}

func customerResponse(customer cust.Customer) CustomerResponse {
	return CustomerResponse{
		ID:                 customer.ID,
		DisplayName:        customer.DisplayName,
		CustomerType:       customer.CustomerType,
		Country:            customer.Country,
		RegistrationNumber: customer.RegistrationNumber,
		RiskLevel:          customer.RiskLevel,
		EntityHint:         customer.EntityHint,
		CreatedAt:          customer.CreatedAt,
		Status:             customer.Status,
	}
}

func accountResponse(account acct.Account) AccountResponse {
	return AccountResponse{
		ID:         account.ID,
		CustomerID: account.CustomerID,
		IBANLike:   account.IBANLike,
		Currency:   account.Currency,
		Status:     account.Status,
		CreatedAt:  account.CreatedAt,
	}
}

func accountResponses(accounts []acct.Account) []AccountResponse {
	responses := make([]AccountResponse, 0, len(accounts))
	for _, account := range accounts {
		responses = append(responses, accountResponse(account))
	}
	return responses
}

func transactionResponse(transaction txn.Transaction) TransactionResponse {
	return TransactionResponse{
		ID:                      transaction.ID,
		AccountID:               transaction.AccountID,
		CounterpartyName:        transaction.CounterpartyName,
		CounterpartyCountry:     transaction.CounterpartyCountry,
		CounterpartyFingerprint: transaction.CounterpartyFingerprint,
		Amount:                  transaction.Amount,
		Currency:                transaction.Currency,
		Direction:               transaction.Direction,
		Purpose:                 transaction.Purpose,
		TraceID:                 transaction.TraceID,
		CreatedAt:               transaction.CreatedAt,
		RiskScore:               transaction.RiskScore,
	}
}

func transactionResponses(transactions []txn.Transaction) []TransactionResponse {
	responses := make([]TransactionResponse, 0, len(transactions))
	for _, transaction := range transactions {
		responses = append(responses, transactionResponse(transaction))
	}
	return responses
}

func alertResponse(alert alertrepo.Alert) AlertResponse {
	var assigned *int64
	if alert.AssignedUserID.Valid {
		value := alert.AssignedUserID.Int64
		assigned = &value
	}
	return AlertResponse{
		ID:             alert.ID,
		TransactionID:  alert.TransactionID,
		CustomerID:     alert.CustomerID,
		RuleCode:       alert.RuleCode,
		RiskScore:      alert.RiskScore,
		Status:         alert.Status,
		AssignedUserID: assigned,
		TypologyHint:   alert.TypologyHint,
		CreatedAt:      alert.CreatedAt,
		UpdatedAt:      alert.UpdatedAt,
	}
}

func alertResponses(alerts []alertrepo.Alert) []AlertResponse {
	responses := make([]AlertResponse, 0, len(alerts))
	for _, alert := range alerts {
		responses = append(responses, alertResponse(alert))
	}
	return responses
}

func caseResponse(investigationCase casework.Case) CaseResponse {
	return CaseResponse{
		ID:            investigationCase.ID,
		CustomerID:    investigationCase.CustomerID,
		AlertID:       investigationCase.AlertID,
		Status:        investigationCase.Status,
		PublicSummary: investigationCase.PublicSummary,
		RiskScore:     investigationCase.RiskScore,
		TypologyHint:  investigationCase.TypologyHint,
		CreatedAt:     investigationCase.CreatedAt,
		UpdatedAt:     investigationCase.UpdatedAt,
	}
}

func caseNoteResponse(note casework.CaseNote) CaseNoteResponse {
	return CaseNoteResponse{
		ID:           note.ID,
		CaseID:       note.CaseID,
		AuthorUserID: note.AuthorUserID,
		Visibility:   note.Visibility,
		Body:         note.Body,
		CreatedAt:    note.CreatedAt,
		UpdatedAt:    note.UpdatedAt,
	}
}

func caseNoteResponses(notes []casework.CaseNote) []CaseNoteResponse {
	responses := make([]CaseNoteResponse, 0, len(notes))
	for _, note := range notes {
		responses = append(responses, caseNoteResponse(note))
	}
	return responses
}

func caseAuditViews(events []auditrepo.Event) []CaseAuditView {
	responses := make([]CaseAuditView, 0, len(events))
	for _, event := range events {
		responses = append(responses, caseAuditView(event))
	}
	return responses
}

func entityActivityViews(events []auditrepo.EntityActivityEvent) []EntityActivityView {
	responses := make([]EntityActivityView, 0, len(events))
	for _, event := range events {
		responses = append(responses, entityActivityView(event, caseAuditChangeResponses(event.DiffJSON), auditrepo.ActivityNarrative{}))
	}
	return responses
}

func (s *Server) entityActivityViewsWithDetail(ctx context.Context, events []auditrepo.EntityActivityEvent, audience auditrepo.ActivityAudience, detailForEvent func(auditrepo.EntityActivityEvent) auditrepo.ActivityDetailLevel) ([]EntityActivityView, error) {
	hydrator := auditrepo.NewActivityHydrator(activityReviewContextSource(s.audit))
	responses := make([]EntityActivityView, 0, len(events))
	for _, event := range events {
		detail := auditrepo.ActivityDetailRelated
		if detailForEvent != nil {
			if selected := detailForEvent(event); selected != "" {
				detail = selected
			}
		}
		narrative, err := hydrator.Hydrate(ctx, auditrepo.ActivityHydrationRequest{
			Event:       event,
			Audience:    audience,
			DetailLevel: detail,
		})
		if err != nil {
			return nil, err
		}
		responses = append(responses, entityActivityView(event, caseAuditChangeResponses(event.DiffJSON), narrative))
	}
	return responses, nil
}

func entityActivityView(event auditrepo.EntityActivityEvent, changes []CaseAuditChangeResponse, narrative auditrepo.ActivityNarrative) EntityActivityView {
	return EntityActivityView{
		CaseID:          event.CaseID,
		CustomerID:      event.CustomerID,
		EntityHint:      event.EntityHint,
		PublicSummary:   event.PublicSummary,
		ActivitySubject: string(narrative.Subject),
		ActivityLevel:   string(narrative.DetailLevel),
		ActivityText:    narrative.Narrative,
		ActivitySource:  string(narrative.Provenance),
		ObjectType:      event.ObjectType,
		ObjectID:        event.ObjectID,
		EventType:       event.EventType,
		PublicMessage:   event.PublicMessage,
		Changes:         changes,
		CreatedAt:       event.CreatedAt,
		VisibilityScope: event.VisibilityScope,
	}
}

func activityReviewContextSource(repository AuditRepository) auditrepo.ActivityReviewContextSource {
	source, ok := repository.(auditrepo.ActivityReviewContextSource)
	if !ok {
		return nil
	}
	return source
}

func caseAuditView(event auditrepo.Event) CaseAuditView {
	return CaseAuditView{
		ID:              event.ID,
		ObjectType:      event.ObjectType,
		ObjectID:        event.ObjectID,
		EventType:       event.EventType,
		PublicMessage:   event.PublicMessage,
		Changes:         caseAuditChangeResponses(event.DiffJSON),
		CreatedAt:       event.CreatedAt,
		VisibilityScope: event.VisibilityScope,
	}
}

func caseAuditChangeResponses(diffJSON string) []CaseAuditChangeResponse {
	var changes []auditrepo.RedactedFieldChange
	if err := json.Unmarshal([]byte(diffJSON), &changes); err != nil {
		return []CaseAuditChangeResponse{}
	}
	responses := make([]CaseAuditChangeResponse, 0, len(changes))
	for _, change := range changes {
		field := change.Field
		if change.Redacted && auditrepo.IsRestrictedField(field) {
			field = "restricted_field"
		}
		responses = append(responses, CaseAuditChangeResponse{
			Field:    field,
			Old:      change.Old,
			New:      change.New,
			Redacted: change.Redacted,
		})
	}
	return responses
}

func (s *Server) recordAudit(ctx context.Context, params auditrepo.CreateParams) error {
	if s.audit == nil {
		return nil
	}
	if params.VisibilityScope == "" {
		params.VisibilityScope = "owner"
	}
	_, err := s.audit.Create(ctx, params)
	return err
}

func duplicatePreviewViews(candidates []casework.DuplicateCandidate) []CaseDuplicatePreviewView {
	responses := make([]CaseDuplicatePreviewView, 0, len(candidates))
	for _, candidate := range candidates {
		responses = append(responses, duplicatePreviewView(candidate))
	}
	return responses
}

func duplicatePreviewView(candidate casework.DuplicateCandidate) CaseDuplicatePreviewView {
	return CaseDuplicatePreviewView{
		CaseID:           candidate.CaseID,
		PublicSummary:    candidate.PublicSummary,
		RiskTags:         duplicateRiskTags(candidate),
		OverlapScore:     duplicateOverlapScore(candidate),
		MatchExplanation: "shared_dedup_hint",
	}
}

func duplicateRiskTags(candidate casework.DuplicateCandidate) []string {
	tags := make([]string, 0, 3)
	if candidate.RiskLevel != "" {
		tags = append(tags, "risk_level:"+candidate.RiskLevel)
	}
	if candidate.TypologyHint != "" {
		tags = append(tags, "typology:"+candidate.TypologyHint)
	}
	if candidate.RiskScore >= 75 {
		tags = append(tags, "risk_score:high")
	}
	return tags
}

func duplicateOverlapScore(candidate casework.DuplicateCandidate) int {
	if candidate.DedupHint == "" {
		return 0
	}
	if candidate.RiskScore >= 75 {
		return 95
	}
	return 85
}

func graphEntityView(summary graphrepo.EntitySummary) GraphEntityView {
	return GraphEntityView{
		EntityHint:    summary.EntityHint,
		RelationType:  summary.RelationType,
		CustomerCount: summary.CustomerCount,
		CaseCount:     summary.CaseCount,
		HighestRisk:   summary.HighestRisk,
		RiskTags:      append([]string(nil), summary.PublicRiskTags...),
		UpdatedAt:     summary.UpdatedAt,
	}
}

func graphRelatedCaseViews(cases []graphrepo.RelatedCaseSummary) []GraphRelatedCaseView {
	responses := make([]GraphRelatedCaseView, 0, len(cases))
	for _, related := range cases {
		responses = append(responses, GraphRelatedCaseView{
			CaseID:        related.CaseID,
			CustomerID:    related.CustomerID,
			EntityHint:    related.EntityHint,
			DisplayName:   related.DisplayName,
			Country:       related.Country,
			Status:        related.Status,
			PublicSummary: related.PublicSummary,
			RiskScore:     related.RiskScore,
			TypologyHint:  related.TypologyHint,
			CreatedAt:     related.CreatedAt,
			UpdatedAt:     related.UpdatedAt,
		})
	}
	return responses
}

func eddGraphSummaryViews(summaries []graphrepo.EDDSummary) []EDDGraphSummaryView {
	responses := make([]EDDGraphSummaryView, 0, len(summaries))
	for _, summary := range summaries {
		responses = append(responses, EDDGraphSummaryView{
			CustomerID:   summary.CustomerID,
			EntityHint:   summary.EntityHint,
			ReviewStatus: summary.ReviewStatus,
			RiskTags:     eddGraphRiskTags(summary),
			CreatedAt:    summary.CreatedAt,
			UpdatedAt:    summary.UpdatedAt,
		})
	}
	return responses
}

func eddGraphRiskTags(summary graphrepo.EDDSummary) []string {
	if summary.RiskLevel == "" {
		return []string{}
	}
	return []string{"risk_level:" + summary.RiskLevel}
}

func eddOwnerView(record edd.EDDRecord) EDDOwnerView {
	return EDDOwnerView{
		ID:                  record.ID,
		CustomerID:          record.CustomerID,
		AnalystUserID:       record.AnalystUserID,
		SourceOfFunds:       record.SourceOfFunds,
		RiskRationale:       record.RiskRationale,
		ConfidentialComment: record.ConfidentialComment,
		ReviewStatus:        record.ReviewStatus,
		CreatedAt:           record.CreatedAt,
		UpdatedAt:           record.UpdatedAt,
	}
}

func (s *Server) buildExportBundle(ctx context.Context, ownerUserID, caseID, disputeID int64, req CreateExportRequest) (exportrepo.ExportBundle, error) {
	root, err := s.cases.GetByOwner(ctx, ownerUserID, caseID)
	if err != nil {
		return exportrepo.ExportBundle{}, err
	}
	snapshot := exportCaseSnapshot(root)
	if s.cases != nil {
		notes, err := s.cases.ListNotesByOwner(ctx, ownerUserID, caseID)
		if err != nil && !errors.Is(err, casework.ErrNoteNotFound) && !errors.Is(err, casework.ErrCaseNotFound) {
			return exportrepo.ExportBundle{}, err
		}
		for _, note := range notes {
			snapshot.Notes = append(snapshot.Notes, exportNoteSnapshot(note))
		}
		linked, err := s.cases.FindDuplicateCandidatesByOwner(ctx, ownerUserID, caseID)
		if err != nil {
			return exportrepo.ExportBundle{}, err
		}
		for _, candidate := range linked {
			linkedSnapshot := exportLinkedCaseSnapshot(candidate)
			if err := s.populateExportLinkedCaseData(ctx, ownerUserID, caseID, &linkedSnapshot); err != nil {
				return exportrepo.ExportBundle{}, err
			}
			snapshot.LinkedCases = append(snapshot.LinkedCases, linkedSnapshot)
		}
	}
	if s.edd != nil {
		record, err := s.edd.GetByOwnerCustomer(ctx, ownerUserID, root.CustomerID)
		if err == nil {
			snapshot.EDDRecords = append(snapshot.EDDRecords, exportEDDSnapshot(record, ""))
		} else if !errors.Is(err, edd.ErrEDDRecordNotFound) {
			return exportrepo.ExportBundle{}, err
		}
	}
	if s.audit != nil {
		events, err := s.audit.ListCaseTimelineByOwner(ctx, ownerUserID, caseID)
		if err != nil {
			return exportrepo.ExportBundle{}, err
		}
		for _, event := range events {
			snapshot.AuditEvents = append(snapshot.AuditEvents, exportAuditSnapshot(event))
		}
	}
	return exportrepo.BuildBundle(exportrepo.ExportContext{
		RequesterUserID: ownerUserID,
		RootCaseID:      caseID,
		DisputeID:       disputeID,
		Purpose:         req.Purpose,
		AllowedScopes:   exportAllowedScopes(req.AllowedScopes),
	}, snapshot, time.Now().UTC())
}

func exportAllowedScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"root_case", "linked_cases", "audit_summary", "edd_summary", "item_metadata"}
	}
	return scopes
}

func exportCaseSnapshot(c casework.Case) exportrepo.CaseSnapshot {
	return exportrepo.CaseSnapshot{
		CaseID:        c.ID,
		CustomerID:    c.CustomerID,
		OwnerUserID:   c.OwnerUserID,
		Status:        c.Status,
		PublicSummary: c.PublicSummary,
		RiskScore:     c.RiskScore,
		TypologyHint:  c.TypologyHint,
		CreatedAt:     c.CreatedAt,
		UpdatedAt:     c.UpdatedAt,
	}
}

func exportLinkedCaseSnapshot(candidate casework.DuplicateCandidate) exportrepo.CaseSnapshot {
	return exportrepo.CaseSnapshot{
		CaseID:        candidate.CaseID,
		CustomerID:    candidate.CustomerID,
		Status:        candidate.Status,
		PublicSummary: candidate.PublicSummary,
		RiskScore:     candidate.RiskScore,
		TypologyHint:  candidate.TypologyHint,
		CreatedAt:     candidate.CreatedAt,
		UpdatedAt:     candidate.UpdatedAt,
	}
}

func exportNoteSnapshot(note casework.CaseNote) exportrepo.CaseNoteSnapshot {
	return exportrepo.CaseNoteSnapshot{
		ID:         note.ID,
		Visibility: note.Visibility,
		Body:       note.Body,
		CreatedAt:  note.CreatedAt,
	}
}

func exportEDDSnapshot(record edd.EDDRecord, riskLevel string) exportrepo.EDDRecordSnapshot {
	return exportrepo.EDDRecordSnapshot{
		ID:                  record.ID,
		CustomerID:          record.CustomerID,
		ReviewStatus:        record.ReviewStatus,
		RiskLevel:           riskLevel,
		SourceOfFunds:       record.SourceOfFunds,
		RiskRationale:       record.RiskRationale,
		ConfidentialComment: record.ConfidentialComment,
		CreatedAt:           record.CreatedAt,
		UpdatedAt:           record.UpdatedAt,
	}
}

func exportAuditSnapshot(event auditrepo.Event) exportrepo.AuditEventSnapshot {
	return exportrepo.AuditEventSnapshot{
		ID:            event.ID,
		ObjectType:    event.ObjectType,
		ObjectID:      event.ObjectID,
		EventType:     event.EventType,
		PublicMessage: event.PublicMessage,
		DiffJSON:      event.DiffJSON,
		Changes:       exportAuditChanges(event.DiffJSON),
		CreatedAt:     event.CreatedAt,
	}
}

func exportAuditChanges(diffJSON string) []exportrepo.AuditChangeSnapshot {
	var changes []auditrepo.RedactedFieldChange
	if err := json.Unmarshal([]byte(diffJSON), &changes); err != nil {
		return nil
	}
	responses := make([]exportrepo.AuditChangeSnapshot, 0, len(changes))
	for _, change := range changes {
		responses = append(responses, exportrepo.AuditChangeSnapshot{
			Field:    change.Field,
			Old:      change.Old,
			New:      change.New,
			OldHash:  change.OldHash,
			NewHash:  change.NewHash,
			Redacted: change.Redacted,
		})
	}
	return responses
}

func exportResponse(record exportrepo.ExportRecord, bundle exportrepo.ExportBundle) ExportResponse {
	return ExportResponse{
		ID:              record.ID,
		RootCaseID:      record.RootCaseID,
		DisputeID:       record.DisputeID,
		Purpose:         record.Purpose,
		Status:          record.Status,
		RedactionPolicy: record.RedactionPolicy,
		Bundle:          exportBundleView(bundle),
		CreatedAt:       record.CreatedAt,
		UpdatedAt:       record.UpdatedAt,
		ExpiresAt:       record.ExpiresAt,
	}
}

func decodeExportBundle(bundleJSON string) (exportrepo.ExportBundle, error) {
	var bundle exportrepo.ExportBundle
	if err := json.Unmarshal([]byte(bundleJSON), &bundle); err != nil {
		return exportrepo.ExportBundle{}, err
	}
	return bundle, nil
}

func exportBundleView(bundle exportrepo.ExportBundle) ExportBundleView {
	return ExportBundleView{
		Purpose:         bundle.Purpose,
		RedactionPolicy: bundle.RedactionPolicy,
		GeneratedAt:     bundle.GeneratedAt,
		RootCase:        exportCaseShellView(bundle.RootCase),
		LinkedCases:     exportCaseShellViews(bundle.LinkedCases),
		LinkedEvidence:  cloneExportLinkedEvidenceMaps(bundle.LinkedEvidence),
		AuditSummaries:  exportAuditSummaryViews(bundle.AuditSummaries),
		EDDSummaries:    exportEDDSummaryViews(bundle.EDDSummaries),
		Items:           exportItemMetadataViews(bundle.Items),
	}
}

func exportCaseShellView(shell exportrepo.ExportCaseShell) ExportCaseShellView {
	return ExportCaseShellView{
		CaseID:        shell.CaseID,
		CustomerID:    shell.CustomerID,
		Status:        shell.Status,
		PublicSummary: shell.PublicSummary,
		RiskScore:     shell.RiskScore,
		TypologyHint:  shell.TypologyHint,
		CreatedAt:     shell.CreatedAt,
		UpdatedAt:     shell.UpdatedAt,
	}
}

func exportCaseShellViews(shells []exportrepo.ExportCaseShell) []ExportCaseShellView {
	views := make([]ExportCaseShellView, 0, len(shells))
	for _, shell := range shells {
		views = append(views, exportCaseShellView(shell))
	}
	return views
}

func cloneExportLinkedEvidenceMaps(items []map[string]any) []map[string]any {
	views := make([]map[string]any, 0, len(items))
	for _, item := range items {
		copied := make(map[string]any, len(item))
		for key, value := range item {
			copied[key] = value
		}
		views = append(views, copied)
	}
	return views
}

func exportAuditSummaryViews(summaries []exportrepo.ExportAuditSummary) []ExportAuditSummaryView {
	views := make([]ExportAuditSummaryView, 0, len(summaries))
	for _, summary := range summaries {
		views = append(views, ExportAuditSummaryView{
			EventID:       summary.EventID,
			ObjectType:    summary.ObjectType,
			ObjectID:      summary.ObjectID,
			EventType:     summary.EventType,
			PublicMessage: summary.PublicMessage,
			ChangedFields: append([]string(nil), summary.ChangedFields...),
			CreatedAt:     summary.CreatedAt,
		})
	}
	return views
}

func exportEDDSummaryViews(summaries []exportrepo.ExportEDDSummary) []ExportEDDSummaryView {
	views := make([]ExportEDDSummaryView, 0, len(summaries))
	for _, summary := range summaries {
		views = append(views, ExportEDDSummaryView{
			RecordID:     summary.RecordID,
			CustomerID:   summary.CustomerID,
			ReviewStatus: summary.ReviewStatus,
			RiskTags:     append([]string(nil), summary.RiskTags...),
			CreatedAt:    summary.CreatedAt,
			UpdatedAt:    summary.UpdatedAt,
		})
	}
	return views
}

func exportItemMetadataViews(items []exportrepo.ExportItemMetadata) []ExportItemMetadataView {
	views := make([]ExportItemMetadataView, 0, len(items))
	for _, item := range items {
		views = append(views, ExportItemMetadataView{
			ItemType:        item.ItemType,
			ObjectType:      item.ObjectType,
			ObjectID:        item.ObjectID,
			Relation:        item.Relation,
			RedactionPolicy: item.RedactionPolicy,
		})
	}
	return views
}

func disputeResponse(dispute exportrepo.Dispute) DisputeResponse {
	return DisputeResponse{
		ID:                dispute.ID,
		CaseID:            dispute.CaseID,
		Status:            dispute.Status,
		Reason:            dispute.Reason,
		ResolutionSummary: dispute.ResolutionSummary,
		CreatedAt:         dispute.CreatedAt,
		UpdatedAt:         dispute.UpdatedAt,
	}
}

func networkRoomSummaryViews(rooms []networkrepo.RoomSummary) []NetworkRoomSummaryView {
	views := make([]NetworkRoomSummaryView, 0, len(rooms))
	for _, room := range rooms {
		views = append(views, networkRoomSummaryView(room))
	}
	return views
}

func networkRoomSummaryView(room networkrepo.RoomSummary) NetworkRoomSummaryView {
	return NetworkRoomSummaryView{
		ID:               room.ID,
		RoomKey:          room.RoomKey,
		EntityHint:       room.EntityHint,
		TypologyHint:     room.TypologyHint,
		Status:           room.Status,
		PublicSummary:    room.PublicSummary,
		PublicRiskTags:   append([]string(nil), room.PublicRiskTags...),
		CaseCount:        room.CaseCount,
		ParticipantCount: room.ParticipantCount,
		CreatedAt:        room.CreatedAt,
		UpdatedAt:        room.UpdatedAt,
	}
}

func networkRoomParticipantViews(participants []networkrepo.Participant) []NetworkRoomParticipantView {
	views := make([]NetworkRoomParticipantView, 0, len(participants))
	for _, participant := range participants {
		views = append(views, networkRoomParticipantView(participant))
	}
	return views
}

func networkRoomParticipantView(participant networkrepo.Participant) NetworkRoomParticipantView {
	return NetworkRoomParticipantView{
		ID:              participant.ID,
		RoomID:          participant.RoomID,
		UserID:          participant.UserID,
		ParticipantRole: participant.ParticipantRole,
		JoinedAt:        participant.JoinedAt,
	}
}

func networkRoomDossierView(dossier networkrepo.SafeDossier) NetworkRoomDossierView {
	return NetworkRoomDossierView{
		Room:           networkRoomSummaryView(dossier.Room),
		Cases:          networkRoomCaseViews(dossier.Cases),
		ScopePolicy:    dossier.ScopePolicy,
		CoveragePolicy: dossier.CoveragePolicy,
	}
}

func networkRoomCaseViews(cases []networkrepo.CaseDossierSummary) []NetworkRoomCaseView {
	views := make([]NetworkRoomCaseView, 0, len(cases))
	for _, c := range cases {
		views = append(views, NetworkRoomCaseView{
			CaseID:                c.CaseID,
			CustomerID:            c.CustomerID,
			OwnedByRequester:      c.OwnedByRequester,
			Status:                c.Status,
			PublicSummary:         c.PublicSummary,
			RiskScore:             c.RiskScore,
			TypologyHint:          c.TypologyHint,
			PublicRiskTags:        append([]string(nil), c.PublicRiskTags...),
			ScopeCoverageComplete: c.ScopeCoverageComplete,
			CreatedAt:             c.CreatedAt,
			UpdatedAt:             c.UpdatedAt,
		})
	}
	return views
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid_request"})
	case errors.Is(err, auth.ErrDuplicateUsername):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "duplicate_username"})
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "invalid_credentials"})
	case errors.Is(err, auth.ErrUnauthenticated):
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "unauthenticated"})
	case errors.Is(err, auth.ErrDisabledUser):
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "user_disabled"})
	default:
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal_error"})
	}
}

func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, cust.ErrInvalidInput), errors.Is(err, acct.ErrInvalidInput), errors.Is(err, txn.ErrInvalidInput), errors.Is(err, alertrepo.ErrInvalidInput), errors.Is(err, casework.ErrInvalidInput), errors.Is(err, risk.ErrInvalidInput), errors.Is(err, edd.ErrInvalidInput), errors.Is(err, auditrepo.ErrInvalidInput), errors.Is(err, graphrepo.ErrInvalidInput), errors.Is(err, exportrepo.ErrInvalidInput), errors.Is(err, networkrepo.ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid_request"})
	case errors.Is(err, cust.ErrDuplicate):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "duplicate_customer_registration"})
	case errors.Is(err, acct.ErrDuplicate):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "duplicate_account_iban"})
	case errors.Is(err, txn.ErrDuplicate):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "duplicate_transaction_trace"})
	case errors.Is(err, alertrepo.ErrDuplicate):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "duplicate_alert"})
	case errors.Is(err, casework.ErrDuplicate):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "duplicate_case"})
	case errors.Is(err, edd.ErrDuplicate):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "duplicate_edd_record"})
	case errors.Is(err, exportrepo.ErrDuplicate):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "duplicate_export_object"})
	case errors.Is(err, networkrepo.ErrDuplicate):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "duplicate_network_room_object"})
	case errors.Is(err, alertrepo.ErrInvalidTransition), errors.Is(err, casework.ErrInvalidTransition):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "invalid_transition"})
	case errors.Is(err, cust.ErrCustomerNotFound), errors.Is(err, acct.ErrAccountNotFound), errors.Is(err, txn.ErrTransactionNotFound), errors.Is(err, alertrepo.ErrAlertNotFound), errors.Is(err, casework.ErrCaseNotFound), errors.Is(err, casework.ErrNoteNotFound), errors.Is(err, edd.ErrEDDRecordNotFound), errors.Is(err, auditrepo.ErrEventNotFound), errors.Is(err, graphrepo.ErrEntityNotFound), errors.Is(err, exportrepo.ErrExportNotFound), errors.Is(err, networkrepo.ErrRoomNotFound):
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not_found"})
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeJSON(w, http.StatusRequestTimeout, ErrorResponse{Error: "request_timeout"})
	default:
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal_error"})
	}
}

func parseID(w http.ResponseWriter, value string) (int64, bool) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid_path"})
		return 0, false
	}
	return id, true
}

func pathParts(path string) []string {
	if path == "" {
		return nil
	}
	parts := strings.Split(path, "/")
	clean := parts[:0]
	for _, part := range parts {
		if part != "" {
			clean = append(clean, part)
		}
	}
	return clean
}

func urlPathUnescape(value string) (string, error) {
	return url.PathUnescape(value)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		_, _ = fmt.Fprintln(w, `{"error":"internal_error"}`)
	}
}

```

### `internal/logging/doc.go (part 1, lines 1-2)`
```
// Package logging reserves the future process logging boundary.
package logging

```

### `internal/networkroom/dossier_context.go (part 1, lines 1-136)`
```
package networkroom

import (
	"sentinel-aml/internal/classification"
	"sort"
	"strings"
	"time"
)

type DossierContextBlock struct {
	BlockID        int64  `json:"block_id"`
	CaseID         int64  `json:"case_id"`
	CoveragePolicy string `json:"coverage_policy"`
	Content        string `json:"content"`
}

type DossierEvaluationBlock struct {
	BlockID        int64  `json:"block_id"`
	CustomerID     int64  `json:"customer_id"`
	CoveragePolicy string `json:"coverage_policy"`
	Content        string `json:"content"`
}

type ExtendedCaseDossierInput struct {
	CaseDossierInput
	ContextBlocks    []DossierContextBlock
	EvaluationBlocks []DossierEvaluationBlock
}

type ExtendedCaseDossierSummary struct {
	CaseID                int64                    `json:"case_id"`
	CustomerID            int64                    `json:"customer_id"`
	OwnedByRequester      bool                     `json:"owned_by_requester"`
	Status                string                   `json:"status"`
	PublicSummary         string                   `json:"public_summary"`
	RiskScore             int                      `json:"risk_score"`
	TypologyHint          string                   `json:"typology_hint"`
	PublicRiskTags        []string                 `json:"public_risk_tags"`
	ScopeCoverageComplete bool                     `json:"scope_coverage_complete"`
	ContextBlocks         []DossierContextBlock    `json:"context_blocks,omitempty"`
	EvaluationBlocks      []DossierEvaluationBlock `json:"evaluation_blocks,omitempty"`
	CreatedAt             time.Time                `json:"created_at"`
	UpdatedAt             time.Time                `json:"updated_at"`
}

type ExtendedDossier struct {
	Room           RoomSummary                  `json:"room"`
	Cases          []ExtendedCaseDossierSummary `json:"cases"`
	ScopePolicy    string                       `json:"scope_policy"`
	CoveragePolicy string                       `json:"coverage_policy"`
}

func BuildExtendedDossier(requesterUserID int64, room RoomSummary, cases []ExtendedCaseDossierInput) (ExtendedDossier, error) {
	if requesterUserID <= 0 || room.ID <= 0 || strings.TrimSpace(room.RoomKey) == "" {
		return ExtendedDossier{}, ErrInvalidInput
	}

	summaries := make([]ExtendedCaseDossierSummary, 0, len(cases))
	for _, c := range cases {
		if c.CaseID <= 0 || c.CustomerID <= 0 {
			return ExtendedDossier{}, ErrInvalidInput
		}
		summary := ExtendedCaseDossierSummary{
			CaseID:                c.CaseID,
			CustomerID:            c.CustomerID,
			OwnedByRequester:      c.OwnerUserID == requesterUserID,
			Status:                strings.TrimSpace(c.Status),
			PublicSummary:         strings.TrimSpace(c.PublicSummary),
			RiskScore:             c.RiskScore,
			TypologyHint:          strings.TrimSpace(c.TypologyHint),
			PublicRiskTags:        normalizeTags(c.PublicRiskTags),
			ScopeCoverageComplete: true,
			CreatedAt:             c.CreatedAt.UTC(),
			UpdatedAt:             c.UpdatedAt.UTC(),
		}
		if !summary.OwnedByRequester {
			summary.ContextBlocks = boundedContextBlocks(c.ContextBlocks)
			summary.EvaluationBlocks = boundedEvaluationBlocks(c.EvaluationBlocks)
			summary.ScopeCoverageComplete = len(summary.ContextBlocks) == 0 && len(summary.EvaluationBlocks) == 0
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].CaseID < summaries[j].CaseID })

	room.PublicRiskTags = normalizeTags(room.PublicRiskTags)
	room.CreatedAt = room.CreatedAt.UTC()
	room.UpdatedAt = room.UpdatedAt.UTC()
	return ExtendedDossier{
		Room:           room,
		Cases:          summaries,
		ScopePolicy:    classification.RoomScopeParticipantContext,
		CoveragePolicy: classification.RoomCoverageSharedCase,
	}, nil
}

func boundedContextBlocks(blocks []DossierContextBlock) []DossierContextBlock {
	bounded := make([]DossierContextBlock, 0, len(blocks))
	for _, block := range blocks {
		if block.BlockID <= 0 || block.CaseID <= 0 || strings.TrimSpace(block.Content) == "" {
			continue
		}
		bounded = append(bounded, DossierContextBlock{
			BlockID:        block.BlockID,
			CaseID:         block.CaseID,
			CoveragePolicy: normalizeArtifactCoverage(block.CoveragePolicy),
			Content:        strings.TrimSpace(block.Content),
		})
	}
	sort.Slice(bounded, func(i, j int) bool { return bounded[i].BlockID < bounded[j].BlockID })
	return bounded
}

func boundedEvaluationBlocks(blocks []DossierEvaluationBlock) []DossierEvaluationBlock {
	bounded := make([]DossierEvaluationBlock, 0, len(blocks))
	for _, block := range blocks {
		if block.BlockID <= 0 || block.CustomerID <= 0 || strings.TrimSpace(block.Content) == "" {
			continue
		}
		bounded = append(bounded, DossierEvaluationBlock{
			BlockID:        block.BlockID,
			CustomerID:     block.CustomerID,
			CoveragePolicy: normalizeArtifactCoverage(block.CoveragePolicy),
			Content:        strings.TrimSpace(block.Content),
		})
	}
	sort.Slice(bounded, func(i, j int) bool { return bounded[i].BlockID < bounded[j].BlockID })
	return bounded
}

func normalizeArtifactCoverage(value string) string {
	value = normalizeToken(value)
	if value == "" {
		return classification.RoomCoverageSummaryMaterial
	}
	return value
}

```

### `internal/networkroom/lifecycle.go (part 1, lines 1-224)`
```
package networkroom

import (
	"context"
	"errors"
	"fmt"
	"sentinel-aml/internal/classification"
	"time"
)

var errDirtyBatchBudgetExhausted = errors.New("network room dirty batch budget exhausted")

const dirtyBatchBudgetMargin = 500 * time.Millisecond

type LifecycleStats struct {
	GroupsProcessed       int
	CasesAttached         int
	ParticipantsJoined    int
	DuplicateCaseLinks    int
	DuplicateParticipants int
	ArtifactsMaterialized int
	DuplicateArtifacts    int
}

func (r *Repository) ProcessDirtyBatch(ctx context.Context, batchSize int, lockTTL time.Duration) (LifecycleStats, error) {
	if err := ctx.Err(); err != nil {
		return LifecycleStats{}, err
	}
	candidates, err := r.ClaimDirtyCandidates(ctx, batchSize, lockTTL)
	if err != nil {
		return LifecycleStats{}, err
	}

	var stats LifecycleStats
	var firstErr error
	for index, candidate := range candidates {
		if dirtyBatchBudgetLow(ctx) {
			requeueDirtyCandidates(ctx, r, candidates[index:])
			return stats, nil
		}
		requeue, err := r.processDirtyCandidate(ctx, candidate, &stats)
		if err != nil {
			if errors.Is(err, errDirtyBatchBudgetExhausted) {
				if markErr := r.MarkDirtyCandidatePending(ctx, candidate.ID); markErr != nil && firstErr == nil {
					firstErr = markErr
				}
				return stats, firstErr
			}
			if markErr := r.MarkDirtyCandidateFailed(ctx, candidate.ID, err); markErr != nil && firstErr == nil {
				firstErr = markErr
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if requeue {
			if err := r.MarkDirtyCandidatePending(ctx, candidate.ID); err != nil && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := r.MarkDirtyCandidateDone(ctx, candidate.ID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return stats, firstErr
}

func (r *Repository) processDirtyCandidate(ctx context.Context, candidate DirtyCandidate, stats *LifecycleStats) (bool, error) {
	summary, err := r.GetCandidateClusterSummary(ctx, candidate.EntityHintNorm, candidate.TypologyHintNorm)
	if err != nil {
		return false, err
	}
	if summary.TotalCases < 2 {
		return false, nil
	}
	room, err := r.CreateOrFindRoom(ctx, CreateOrFindRoomParams{
		ActorUserID:   summary.ActorUserID,
		EntityHint:    candidate.EntityHintNorm,
		TypologyHint:  candidate.TypologyHintNorm,
		PublicSummary: fmt.Sprintf("Related activity for %s / %s", candidate.EntityHintNorm, candidate.TypologyHintNorm),
		PublicRiskTags: []string{
			"shared_entity",
			"typology:" + candidate.TypologyHintNorm,
		},
	})
	if err != nil {
		return false, err
	}
	cases, err := r.ListUnattachedCasesForCandidate(ctx, room.ID, candidate.EntityHintNorm, candidate.TypologyHintNorm, r.caseLimitPerCandidate)
	if err != nil {
		return false, err
	}
	if len(cases) == 0 {
		return false, nil
	}
	for _, item := range cases {
		if dirtyBatchBudgetLow(ctx) {
			return true, errDirtyBatchBudgetExhausted
		}
		caseAttached := false
		_, err := r.AttachCase(ctx, AttachCaseParams{
			ActorUserID:  item.OwnerUserID,
			RoomID:       room.ID,
			CaseID:       item.CaseID,
			RelationType: "typology_match",
		})
		if err == nil {
			stats.CasesAttached++
			caseAttached = true
		} else if errors.Is(err, ErrDuplicate) {
			stats.DuplicateCaseLinks++
		} else {
			return false, err
		}

		_, err = r.JoinRoom(ctx, JoinRoomParams{
			RoomID:          room.ID,
			UserID:          item.OwnerUserID,
			ParticipantRole: "analyst",
		})
		if err == nil {
			stats.ParticipantsJoined++
		} else if errors.Is(err, ErrDuplicate) {
			stats.DuplicateParticipants++
		} else {
			return false, err
		}

		if caseAttached {
			created, duplicates, err := r.materializeCandidateArtifactsWithLimit(ctx, room.ID, item.CaseID, r.artifactLimitPerCase)
			if err != nil {
				return false, err
			}
			stats.ArtifactsMaterialized += created
			stats.DuplicateArtifacts += duplicates
		}
	}
	stats.GroupsProcessed++
	remaining, err := r.CountUnattachedCasesForCandidate(ctx, room.ID, candidate.EntityHintNorm, candidate.TypologyHintNorm)
	if err != nil {
		return false, err
	}
	return remaining > 0, nil
}

func requeueDirtyCandidates(ctx context.Context, r *Repository, candidates []DirtyCandidate) {
	for _, candidate := range candidates {
		_ = r.MarkDirtyCandidatePending(ctx, candidate.ID)
	}
}

func effectiveLimit(configured int, fallback int) int {
	if configured > 0 {
		return configured
	}
	return fallback
}

func dirtyBatchBudgetLow(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return false
	}
	return time.Until(deadline) <= dirtyBatchBudgetMargin
}

func (r *Repository) materializeCandidateArtifacts(ctx context.Context, roomID, caseID int64) (int, int, error) {
	return r.materializeCandidateArtifactsWithLimit(ctx, roomID, caseID, r.artifactLimitPerCase)
}

func (r *Repository) materializeCandidateArtifactsWithLimit(ctx context.Context, roomID, caseID int64, limit int) (int, int, error) {
	if roomID <= 0 || caseID <= 0 {
		return 0, 0, ErrInvalidInput
	}
	if limit <= 0 {
		limit = DefaultArtifactLimitPerCase
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT ca.id, ca.customer_id, 'room_context', 'collaboration_context', $2, cn.body
FROM cases ca
JOIN case_notes cn ON cn.case_id = ca.id
WHERE ca.id = $1
  AND cn.visibility = 'private'
  AND btrim(cn.body) <> ''
UNION ALL
SELECT ca.id, ca.customer_id, 'assessment_summary', 'evaluation_summary', $2, er.confidential_comment
FROM cases ca
JOIN edd_records er ON er.customer_id = ca.customer_id
WHERE ca.id = $1
  AND btrim(er.confidential_comment) <> ''
ORDER BY 1, 3, 4
LIMIT $3`,
		caseID,
		classification.RoomCoverageSourceMaterial,
		limit,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("list network room source material: %w", err)
	}
	defer rows.Close()

	var created int
	var duplicates int
	for rows.Next() {
		var params MaterializeArtifactParams
		params.RoomID = roomID
		if err := rows.Scan(&params.CaseID, &params.CustomerID, &params.ArtifactKind, &params.SourceClass, &params.CoveragePolicy, &params.Content); err != nil {
			return created, duplicates, fmt.Errorf("scan network room source material: %w", err)
		}
		if _, err := r.MaterializeArtifact(ctx, params); err == nil {
			created++
		} else if errors.Is(err, ErrDuplicate) {
			duplicates++
		} else {
			return created, duplicates, err
		}
	}
	if err := rows.Err(); err != nil {
		return created, duplicates, fmt.Errorf("iterate network room source material: %w", err)
	}
	return created, duplicates, nil
}

```

### `internal/networkroom/repository.go (part 1, lines 1-1009)`
```
package networkroom

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sentinel-aml/internal/classification"
	"sort"
	"strings"
	"time"
)

var (
	ErrRoomNotFound = errors.New("network room not found")
	ErrDuplicate    = errors.New("duplicate network room object")
	ErrInvalidInput = errors.New("invalid network room input")
)

var allowedRoomStatuses = map[string]struct{}{
	"OPEN":       {},
	"MONITORING": {},
	"CLOSED":     {},
}

var allowedRelations = map[string]struct{}{
	"root_case":      {},
	"related_case":   {},
	"typology_match": {},
	"entity_match":   {},
}

var allowedParticipantRoles = map[string]struct{}{
	"analyst":  {},
	"observer": {},
}

type rowScanner interface {
	Scan(dest ...any) error
}

type rowsScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) rowScanner
	QueryContext(ctx context.Context, query string, args ...any) (rowsScanner, error)
}

type Repository struct {
	db                    queryer
	caseLimitPerCandidate int
	artifactLimitPerCase  int
}

const (
	DefaultDirtyBatchSize           = 100
	DefaultDirtyLockTTL             = 30 * time.Second
	DefaultCaseLimitPerCandidate    = 500
	DefaultArtifactLimitPerCase     = 20
	DefaultDirtyCandidateReason     = "case_changed"
	maxDirtyCandidateErrorBytes     = 512
	defaultDirtyCandidateQueryLimit = 1
)

type Room struct {
	ID              int64
	RoomKey         string
	EntityHint      string
	TypologyHint    string
	Status          string
	PublicSummary   string
	PublicRiskTags  []string
	CreatedByUserID int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type RoomCase struct {
	ID            int64
	RoomID        int64
	CaseID        int64
	RelationType  string
	AddedByUserID int64
	CreatedAt     time.Time
}

type Participant struct {
	ID              int64
	RoomID          int64
	UserID          int64
	ParticipantRole string
	JoinedAt        time.Time
}

type RoomSummary struct {
	ID               int64     `json:"id"`
	RoomKey          string    `json:"room_key"`
	EntityHint       string    `json:"entity_hint"`
	TypologyHint     string    `json:"typology_hint"`
	Status           string    `json:"status"`
	PublicSummary    string    `json:"public_summary"`
	PublicRiskTags   []string  `json:"public_risk_tags"`
	CaseCount        int       `json:"case_count"`
	ParticipantCount int       `json:"participant_count"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type CaseDossierInput struct {
	CaseID           int64
	CustomerID       int64
	OwnerUserID      int64
	Status           string
	PublicSummary    string
	RiskScore        int
	TypologyHint     string
	PublicRiskTags   []string
	SensitiveSamples []string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type CollaborationArtifact struct {
	ID             int64
	RoomID         int64
	CaseID         int64
	CustomerID     int64
	ArtifactKind   string
	SourceClass    string
	CoveragePolicy string
	Content        string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type DirtyCandidate struct {
	ID               int64
	EntityHintNorm   string
	TypologyHintNorm string
	Reason           string
	Status           string
	Attempts         int
	LockedUntil      sql.NullTime
	LastError        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type CandidateCase struct {
	CaseID      int64
	OwnerUserID int64
}

type CandidateClusterSummary struct {
	ActorUserID int64
	TotalCases  int
}

type CaseDossierSummary struct {
	CaseID                int64     `json:"case_id"`
	CustomerID            int64     `json:"customer_id"`
	OwnedByRequester      bool      `json:"owned_by_requester"`
	Status                string    `json:"status"`
	PublicSummary         string    `json:"public_summary"`
	RiskScore             int       `json:"risk_score"`
	TypologyHint          string    `json:"typology_hint"`
	PublicRiskTags        []string  `json:"public_risk_tags"`
	ScopeCoverageComplete bool      `json:"scope_coverage_complete"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type SafeDossier struct {
	Room           RoomSummary          `json:"room"`
	Cases          []CaseDossierSummary `json:"cases"`
	ScopePolicy    string               `json:"scope_policy"`
	CoveragePolicy string               `json:"coverage_policy"`
}

type CreateOrFindRoomParams struct {
	ActorUserID    int64
	EntityHint     string
	TypologyHint   string
	PublicSummary  string
	PublicRiskTags []string
}

type AttachCaseParams struct {
	ActorUserID  int64
	RoomID       int64
	CaseID       int64
	RelationType string
}

type JoinRoomParams struct {
	RoomID          int64
	UserID          int64
	ParticipantRole string
}

type MaterializeArtifactParams struct {
	RoomID         int64
	CaseID         int64
	CustomerID     int64
	ArtifactKind   string
	SourceClass    string
	CoveragePolicy string
	Content        string
}

func NewRepository(db *sql.DB) *Repository {
	return newRepository(sqlDBAdapter{db: db})
}

func newRepository(db queryer) *Repository {
	return &Repository{
		db:                    db,
		caseLimitPerCandidate: DefaultCaseLimitPerCandidate,
		artifactLimitPerCase:  DefaultArtifactLimitPerCase,
	}
}

func (r *Repository) SetLifecycleLimits(caseLimitPerCandidate, artifactLimitPerCase int) {
	if caseLimitPerCandidate > 0 {
		r.caseLimitPerCandidate = caseLimitPerCandidate
	}
	if artifactLimitPerCase > 0 {
		r.artifactLimitPerCase = artifactLimitPerCase
	}
}

type sqlDBAdapter struct {
	db *sql.DB
}

func (a sqlDBAdapter) QueryRowContext(ctx context.Context, query string, args ...any) rowScanner {
	return a.db.QueryRowContext(ctx, query, args...)
}

func (a sqlDBAdapter) QueryContext(ctx context.Context, query string, args ...any) (rowsScanner, error) {
	return a.db.QueryContext(ctx, query, args...)
}

func (r *Repository) CreateOrFindRoom(ctx context.Context, params CreateOrFindRoomParams) (Room, error) {
	if err := ctx.Err(); err != nil {
		return Room{}, err
	}
	params = normalizeCreateOrFindRoomParams(params)
	if err := validateCreateOrFindRoomParams(params); err != nil {
		return Room{}, err
	}
	roomKey := deterministicRoomKey(params.EntityHint, params.TypologyHint)
	riskTags := strings.Join(normalizeTags(params.PublicRiskTags), ",")

	var room Room
	var tags string
	err := r.db.QueryRowContext(ctx, `
INSERT INTO network_rooms (room_key, entity_hint, typology_hint, public_summary, public_risk_tags, created_by_user_id)
VALUES ($1, $2, $3, $4, CASE WHEN btrim($5) = '' THEN '{}'::text[] ELSE string_to_array($5, ',') END, $6)
ON CONFLICT (room_key) DO UPDATE
SET updated_at = network_rooms.updated_at
RETURNING id, room_key, entity_hint, typology_hint, status, public_summary, array_to_string(public_risk_tags, ','), created_by_user_id, created_at, updated_at`,
		roomKey,
		params.EntityHint,
		params.TypologyHint,
		params.PublicSummary,
		riskTags,
		params.ActorUserID,
	).Scan(&room.ID, &room.RoomKey, &room.EntityHint, &room.TypologyHint, &room.Status, &room.PublicSummary, &tags, &room.CreatedByUserID, &room.CreatedAt, &room.UpdatedAt)
	if err != nil {
		return Room{}, fmt.Errorf("create or find network room: %w", err)
	}
	room.PublicRiskTags = splitTags(tags)
	return room, nil
}

func (r *Repository) AttachCase(ctx context.Context, params AttachCaseParams) (RoomCase, error) {
	if err := ctx.Err(); err != nil {
		return RoomCase{}, err
	}
	params = normalizeAttachCaseParams(params)
	if err := validateAttachCaseParams(params); err != nil {
		return RoomCase{}, err
	}

	var link RoomCase
	err := r.db.QueryRowContext(ctx, `
INSERT INTO network_room_cases (room_id, case_id, relation_type, added_by_user_id)
SELECT nr.id, c.id, $4, $1
FROM network_rooms nr
JOIN cases c ON c.id = $3
WHERE nr.id = $2
RETURNING id, room_id, case_id, relation_type, added_by_user_id, created_at`,
		params.ActorUserID,
		params.RoomID,
		params.CaseID,
		params.RelationType,
	).Scan(&link.ID, &link.RoomID, &link.CaseID, &link.RelationType, &link.AddedByUserID, &link.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RoomCase{}, ErrRoomNotFound
	}
	if isUniqueViolation(err) {
		return RoomCase{}, ErrDuplicate
	}
	if err != nil {
		return RoomCase{}, fmt.Errorf("attach network room case: %w", err)
	}
	return link, nil
}

func (r *Repository) JoinRoom(ctx context.Context, params JoinRoomParams) (Participant, error) {
	if err := ctx.Err(); err != nil {
		return Participant{}, err
	}
	params = normalizeJoinRoomParams(params)
	if err := validateJoinRoomParams(params); err != nil {
		return Participant{}, err
	}

	var participant Participant
	err := r.db.QueryRowContext(ctx, `
INSERT INTO network_room_participants (room_id, user_id, participant_role)
SELECT nr.id, u.id, $3
FROM network_rooms nr
JOIN users u ON u.id = $2
WHERE nr.id = $1
  AND EXISTS (
      SELECT 1
      FROM network_room_cases nrc
      JOIN cases ca ON ca.id = nrc.case_id
      WHERE nrc.room_id = nr.id
        AND ca.owner_user_id = u.id
  )
RETURNING id, room_id, user_id, participant_role, joined_at`,
		params.RoomID,
		params.UserID,
		params.ParticipantRole,
	).Scan(&participant.ID, &participant.RoomID, &participant.UserID, &participant.ParticipantRole, &participant.JoinedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Participant{}, ErrRoomNotFound
	}
	if isUniqueViolation(err) {
		return Participant{}, ErrDuplicate
	}
	if err != nil {
		return Participant{}, fmt.Errorf("join network room: %w", err)
	}
	return participant, nil
}

func (r *Repository) MaterializeArtifact(ctx context.Context, params MaterializeArtifactParams) (CollaborationArtifact, error) {
	if err := ctx.Err(); err != nil {
		return CollaborationArtifact{}, err
	}
	params = normalizeMaterializeArtifactParams(params)
	if err := validateMaterializeArtifactParams(params); err != nil {
		return CollaborationArtifact{}, err
	}

	var artifact CollaborationArtifact
	err := r.db.QueryRowContext(ctx, `
INSERT INTO network_room_artifacts (room_id, case_id, customer_id, artifact_kind, source_class, coverage_policy, content)
SELECT nr.id, ca.id, ca.customer_id, $4, $5, $6, $7
FROM network_rooms nr
JOIN network_room_cases nrc ON nrc.room_id = nr.id AND nrc.case_id = $2
JOIN cases ca ON ca.id = nrc.case_id AND ca.customer_id = $3
WHERE nr.id = $1
ON CONFLICT (room_id, case_id, artifact_kind, source_class) DO UPDATE
SET customer_id = EXCLUDED.customer_id,
    coverage_policy = EXCLUDED.coverage_policy,
    content = EXCLUDED.content,
    updated_at = now()
RETURNING id, room_id, case_id, customer_id, artifact_kind, source_class, coverage_policy, content, created_at, updated_at`,
		params.RoomID,
		params.CaseID,
		params.CustomerID,
		params.ArtifactKind,
		params.SourceClass,
		params.CoveragePolicy,
		params.Content,
	).Scan(&artifact.ID, &artifact.RoomID, &artifact.CaseID, &artifact.CustomerID, &artifact.ArtifactKind, &artifact.SourceClass, &artifact.CoveragePolicy, &artifact.Content, &artifact.CreatedAt, &artifact.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CollaborationArtifact{}, ErrRoomNotFound
	}
	if err != nil {
		return CollaborationArtifact{}, fmt.Errorf("materialize network room artifact: %w", err)
	}
	return artifact, nil
}

func (r *Repository) EnqueueCaseCandidate(ctx context.Context, caseID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return ErrInvalidInput
	}

	var id int64
	err := r.db.QueryRowContext(ctx, `
WITH candidate AS (
    SELECT replace(lower(btrim(cust.entity_hint)), ' ', '_') AS entity_hint_norm,
           replace(lower(btrim(ca.typology_hint)), ' ', '_') AS typology_hint_norm
    FROM cases ca
    JOIN customers cust ON cust.id = ca.customer_id
    WHERE ca.id::text = $1
      AND btrim(cust.entity_hint) <> ''
      AND btrim(ca.typology_hint) <> ''
),
upserted AS (
    INSERT INTO network_room_dirty_candidates (entity_hint_norm, typology_hint_norm, reason, status, locked_until, last_error)
    SELECT entity_hint_norm, typology_hint_norm, $2, 'pending', NULL, ''
    FROM candidate
    ON CONFLICT (entity_hint_norm, typology_hint_norm) DO UPDATE
    SET reason = EXCLUDED.reason,
        status = 'pending',
        locked_until = NULL,
        last_error = '',
        updated_at = now()
    RETURNING id
)
SELECT coalesce((SELECT id FROM upserted LIMIT 1), 0)`,
		caseID,
		DefaultDirtyCandidateReason,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("enqueue network room dirty candidate: %w", err)
	}
	return nil
}

func (r *Repository) ClaimDirtyCandidates(ctx context.Context, limit int, lockFor time.Duration) ([]DirtyCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = DefaultDirtyBatchSize
	}
	if lockFor <= 0 {
		lockFor = DefaultDirtyLockTTL
	}

	rows, err := r.db.QueryContext(ctx, `
WITH due AS (
    SELECT id
    FROM network_room_dirty_candidates
    WHERE status = 'pending'
       OR (status = 'processing' AND locked_until <= now())
    ORDER BY updated_at, id
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE network_room_dirty_candidates dirty
SET status = 'processing',
    attempts = dirty.attempts + 1,
    locked_until = now() + ($2::double precision * interval '1 second'),
    updated_at = now()
FROM due
WHERE dirty.id = due.id
RETURNING dirty.id, dirty.entity_hint_norm, dirty.typology_hint_norm, dirty.reason, dirty.status,
          dirty.attempts, dirty.locked_until, dirty.last_error, dirty.created_at, dirty.updated_at`,
		limit,
		lockFor.Seconds(),
	)
	if err != nil {
		return nil, fmt.Errorf("claim network room dirty candidates: %w", err)
	}
	defer rows.Close()

	var candidates []DirtyCandidate
	for rows.Next() {
		var candidate DirtyCandidate
		if err := rows.Scan(
			&candidate.ID,
			&candidate.EntityHintNorm,
			&candidate.TypologyHintNorm,
			&candidate.Reason,
			&candidate.Status,
			&candidate.Attempts,
			&candidate.LockedUntil,
			&candidate.LastError,
			&candidate.CreatedAt,
			&candidate.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan network room dirty candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network room dirty candidates: %w", err)
	}
	return candidates, nil
}

func (r *Repository) MarkDirtyCandidateDone(ctx context.Context, id int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if id <= 0 {
		return ErrInvalidInput
	}
	var updatedID int64
	err := r.db.QueryRowContext(ctx, `
UPDATE network_room_dirty_candidates
SET status = 'done',
    locked_until = NULL,
    last_error = '',
    updated_at = now()
WHERE id = $1
RETURNING id`,
		id,
	).Scan(&updatedID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidInput
	}
	if err != nil {
		return fmt.Errorf("mark network room dirty candidate done: %w", err)
	}
	return nil
}

func (r *Repository) MarkDirtyCandidateFailed(ctx context.Context, id int64, cause error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if id <= 0 {
		return ErrInvalidInput
	}
	message := "network room candidate processing failed"
	if cause != nil {
		message = strings.TrimSpace(cause.Error())
	}
	if len(message) > maxDirtyCandidateErrorBytes {
		message = message[:maxDirtyCandidateErrorBytes]
	}
	var updatedID int64
	err := r.db.QueryRowContext(ctx, `
UPDATE network_room_dirty_candidates
SET status = 'pending',
    locked_until = NULL,
    last_error = $2,
    updated_at = now()
WHERE id = $1
RETURNING id`,
		id,
		message,
	).Scan(&updatedID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidInput
	}
	if err != nil {
		return fmt.Errorf("mark network room dirty candidate failed: %w", err)
	}
	return nil
}

func (r *Repository) MarkDirtyCandidatePending(ctx context.Context, id int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if id <= 0 {
		return ErrInvalidInput
	}
	var updatedID int64
	err := r.db.QueryRowContext(ctx, `
UPDATE network_room_dirty_candidates
SET status = 'pending',
    locked_until = NULL,
    updated_at = now()
WHERE id = $1
RETURNING id`,
		id,
	).Scan(&updatedID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidInput
	}
	if err != nil {
		return fmt.Errorf("mark network room dirty candidate pending: %w", err)
	}
	return nil
}

func (r *Repository) GetCandidateClusterSummary(ctx context.Context, entityHint, typologyHint string) (CandidateClusterSummary, error) {
	if err := ctx.Err(); err != nil {
		return CandidateClusterSummary{}, err
	}
	entityHint = normalizeToken(entityHint)
	typologyHint = normalizeToken(typologyHint)
	if entityHint == "" || typologyHint == "" {
		return CandidateClusterSummary{}, ErrInvalidInput
	}

	var summary CandidateClusterSummary
	err := r.db.QueryRowContext(ctx, `
SELECT coalesce(min(ca.owner_user_id), 0), count(*)::int
FROM cases ca
JOIN customers cust ON cust.id = ca.customer_id
WHERE replace(lower(btrim(cust.entity_hint)), ' ', '_') = $1
  AND replace(lower(btrim(ca.typology_hint)), ' ', '_') = $2`,
		entityHint,
		typologyHint,
	).Scan(&summary.ActorUserID, &summary.TotalCases)
	if err != nil {
		return CandidateClusterSummary{}, fmt.Errorf("get network room candidate summary: %w", err)
	}
	return summary, nil
}

func (r *Repository) ListUnattachedCasesForCandidate(ctx context.Context, roomID int64, entityHint, typologyHint string, limit int) ([]CandidateCase, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entityHint = normalizeToken(entityHint)
	typologyHint = normalizeToken(typologyHint)
	if roomID <= 0 || entityHint == "" || typologyHint == "" {
		return nil, ErrInvalidInput
	}
	if limit <= 0 {
		limit = r.caseLimitPerCandidate
	}
	if limit <= 0 {
		limit = DefaultCaseLimitPerCandidate
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT ca.id, ca.owner_user_id
FROM cases ca
JOIN customers cust ON cust.id = ca.customer_id
WHERE replace(lower(btrim(cust.entity_hint)), ' ', '_') = $1
  AND replace(lower(btrim(ca.typology_hint)), ' ', '_') = $2
  AND NOT EXISTS (
      SELECT 1
      FROM network_room_cases nrc
      WHERE nrc.room_id = $3
        AND nrc.case_id = ca.id
  )
ORDER BY ca.id
LIMIT $4`,
		entityHint,
		typologyHint,
		roomID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list unattached network room cases: %w", err)
	}
	defer rows.Close()

	var cases []CandidateCase
	for rows.Next() {
		var item CandidateCase
		if err := rows.Scan(&item.CaseID, &item.OwnerUserID); err != nil {
			return nil, fmt.Errorf("scan unattached network room case: %w", err)
		}
		cases = append(cases, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unattached network room cases: %w", err)
	}
	return cases, nil
}

func (r *Repository) CountUnattachedCasesForCandidate(ctx context.Context, roomID int64, entityHint, typologyHint string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	entityHint = normalizeToken(entityHint)
	typologyHint = normalizeToken(typologyHint)
	if roomID <= 0 || entityHint == "" || typologyHint == "" {
		return 0, ErrInvalidInput
	}

	var count int
	err := r.db.QueryRowContext(ctx, `
SELECT count(*)::int
FROM cases ca
JOIN customers cust ON cust.id = ca.customer_id
WHERE replace(lower(btrim(cust.entity_hint)), ' ', '_') = $1
  AND replace(lower(btrim(ca.typology_hint)), ' ', '_') = $2
  AND NOT EXISTS (
      SELECT 1
      FROM network_room_cases nrc
      WHERE nrc.room_id = $3
        AND nrc.case_id = ca.id
  )`,
		entityHint,
		typologyHint,
		roomID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count unattached network room cases: %w", err)
	}
	return count, nil
}

func (r *Repository) ListParticipants(ctx context.Context, roomID int64) ([]Participant, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if roomID <= 0 {
		return nil, ErrInvalidInput
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT id, room_id, user_id, participant_role, joined_at
FROM network_room_participants
WHERE room_id = $1
ORDER BY joined_at, id`,
		roomID,
	)
	if err != nil {
		return nil, fmt.Errorf("list network room participants: %w", err)
	}
	defer rows.Close()

	var participants []Participant
	for rows.Next() {
		var participant Participant
		if err := rows.Scan(&participant.ID, &participant.RoomID, &participant.UserID, &participant.ParticipantRole, &participant.JoinedAt); err != nil {
			return nil, fmt.Errorf("scan network room participant: %w", err)
		}
		participants = append(participants, participant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network room participants: %w", err)
	}
	return participants, nil
}

func (r *Repository) GetRoomForUser(ctx context.Context, userID, roomID int64) (RoomSummary, error) {
	if err := ctx.Err(); err != nil {
		return RoomSummary{}, err
	}
	if userID <= 0 || roomID <= 0 {
		return RoomSummary{}, ErrInvalidInput
	}

	var summary RoomSummary
	var tags string
	err := r.db.QueryRowContext(ctx, `
SELECT nr.id, nr.room_key, nr.entity_hint, nr.typology_hint, nr.status, nr.public_summary,
       array_to_string(nr.public_risk_tags, ',') AS public_risk_tags,
       count(DISTINCT nrc.case_id)::int AS case_count,
       count(DISTINCT nrp.user_id)::int AS participant_count,
       nr.created_at, nr.updated_at
FROM network_rooms nr
JOIN network_room_participants owned ON owned.room_id = nr.id AND owned.user_id = $1
LEFT JOIN network_room_cases nrc ON nrc.room_id = nr.id
LEFT JOIN network_room_participants nrp ON nrp.room_id = nr.id
WHERE nr.id = $2
GROUP BY nr.id`,
		userID,
		roomID,
	).Scan(&summary.ID, &summary.RoomKey, &summary.EntityHint, &summary.TypologyHint, &summary.Status, &summary.PublicSummary, &tags, &summary.CaseCount, &summary.ParticipantCount, &summary.CreatedAt, &summary.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RoomSummary{}, ErrRoomNotFound
	}
	if err != nil {
		return RoomSummary{}, fmt.Errorf("get network room for user: %w", err)
	}
	summary.PublicRiskTags = splitTags(tags)
	return summary, nil
}

func (r *Repository) ListDossierCases(ctx context.Context, userID, roomID int64) ([]CaseDossierInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if userID <= 0 || roomID <= 0 {
		return nil, ErrInvalidInput
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT ca.id, ca.customer_id, ca.owner_user_id, ca.status, ca.public_summary, ca.risk_score, ca.typology_hint,
       coalesce(nullif(ca.typology_hint, ''), 'case') AS public_risk_tags,
       ca.created_at, ca.updated_at
FROM network_room_cases nrc
JOIN network_room_participants owned ON owned.room_id = nrc.room_id AND owned.user_id = $1
JOIN cases ca ON ca.id = nrc.case_id
WHERE nrc.room_id = $2
ORDER BY ca.id`,
		userID,
		roomID,
	)
	if err != nil {
		return nil, fmt.Errorf("list network room dossier cases: %w", err)
	}
	defer rows.Close()

	var cases []CaseDossierInput
	for rows.Next() {
		var c CaseDossierInput
		var tags string
		if err := rows.Scan(&c.CaseID, &c.CustomerID, &c.OwnerUserID, &c.Status, &c.PublicSummary, &c.RiskScore, &c.TypologyHint, &tags, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan network room dossier case: %w", err)
		}
		c.PublicRiskTags = splitTags(tags)
		cases = append(cases, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network room dossier cases: %w", err)
	}
	return cases, nil
}

func (r *Repository) ListRoomsForUser(ctx context.Context, userID int64) ([]RoomSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if userID <= 0 {
		return nil, ErrInvalidInput
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT nr.id, nr.room_key, nr.entity_hint, nr.typology_hint, nr.status, nr.public_summary,
       array_to_string(nr.public_risk_tags, ',') AS public_risk_tags,
       count(DISTINCT nrc.case_id)::int AS case_count,
       count(DISTINCT nrp.user_id)::int AS participant_count,
       nr.created_at, nr.updated_at
FROM network_rooms nr
JOIN network_room_participants owned ON owned.room_id = nr.id AND owned.user_id = $1
LEFT JOIN network_room_cases nrc ON nrc.room_id = nr.id
LEFT JOIN network_room_participants nrp ON nrp.room_id = nr.id
GROUP BY nr.id
ORDER BY nr.updated_at DESC, nr.id`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list network rooms: %w", err)
	}
	defer rows.Close()

	var rooms []RoomSummary
	for rows.Next() {
		var summary RoomSummary
		var tags string
		if err := rows.Scan(&summary.ID, &summary.RoomKey, &summary.EntityHint, &summary.TypologyHint, &summary.Status, &summary.PublicSummary, &tags, &summary.CaseCount, &summary.ParticipantCount, &summary.CreatedAt, &summary.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan network room summary: %w", err)
		}
		summary.PublicRiskTags = splitTags(tags)
		rooms = append(rooms, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network rooms: %w", err)
	}
	return rooms, nil
}

func BuildSafeDossier(requesterUserID int64, room RoomSummary, cases []CaseDossierInput) (SafeDossier, error) {
	if requesterUserID <= 0 || room.ID <= 0 || strings.TrimSpace(room.RoomKey) == "" {
		return SafeDossier{}, ErrInvalidInput
	}

	summaries := make([]CaseDossierSummary, 0, len(cases))
	for _, c := range cases {
		if c.CaseID <= 0 || c.CustomerID <= 0 {
			return SafeDossier{}, ErrInvalidInput
		}
		summaries = append(summaries, CaseDossierSummary{
			CaseID:                c.CaseID,
			CustomerID:            c.CustomerID,
			OwnedByRequester:      c.OwnerUserID == requesterUserID,
			Status:                strings.TrimSpace(c.Status),
			PublicSummary:         strings.TrimSpace(c.PublicSummary),
			RiskScore:             c.RiskScore,
			TypologyHint:          strings.TrimSpace(c.TypologyHint),
			PublicRiskTags:        normalizeTags(c.PublicRiskTags),
			ScopeCoverageComplete: true,
			CreatedAt:             c.CreatedAt.UTC(),
			UpdatedAt:             c.UpdatedAt.UTC(),
		})
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].CaseID < summaries[j].CaseID })

	room.PublicRiskTags = normalizeTags(room.PublicRiskTags)
	room.CreatedAt = room.CreatedAt.UTC()
	room.UpdatedAt = room.UpdatedAt.UTC()
	return SafeDossier{
		Room:           room,
		Cases:          summaries,
		ScopePolicy:    classification.RoomScopeCaseReference,
		CoveragePolicy: classification.RoomCoverageSummary,
	}, nil
}

func deterministicRoomKey(entityHint, typologyHint string) string {
	if typologyHint == "" {
		typologyHint = "general"
	}
	return normalizeToken(entityHint) + ":" + normalizeToken(typologyHint)
}

func normalizeCreateOrFindRoomParams(params CreateOrFindRoomParams) CreateOrFindRoomParams {
	params.EntityHint = normalizeToken(params.EntityHint)
	params.TypologyHint = normalizeToken(params.TypologyHint)
	params.PublicSummary = strings.TrimSpace(params.PublicSummary)
	params.PublicRiskTags = normalizeTags(params.PublicRiskTags)
	return params
}

func validateCreateOrFindRoomParams(params CreateOrFindRoomParams) error {
	if params.ActorUserID <= 0 || params.EntityHint == "" {
		return ErrInvalidInput
	}
	for _, tag := range params.PublicRiskTags {
		if tag == "" {
			return ErrInvalidInput
		}
	}
	return nil
}

func normalizeAttachCaseParams(params AttachCaseParams) AttachCaseParams {
	params.RelationType = normalizeToken(params.RelationType)
	if params.RelationType == "" {
		params.RelationType = "related_case"
	}
	return params
}

func validateAttachCaseParams(params AttachCaseParams) error {
	if params.ActorUserID <= 0 || params.RoomID <= 0 || params.CaseID <= 0 {
		return ErrInvalidInput
	}
	if _, ok := allowedRelations[params.RelationType]; !ok {
		return ErrInvalidInput
	}
	return nil
}

func normalizeJoinRoomParams(params JoinRoomParams) JoinRoomParams {
	params.ParticipantRole = normalizeToken(params.ParticipantRole)
	if params.ParticipantRole == "" {
		params.ParticipantRole = "analyst"
	}
	return params
}

func normalizeMaterializeArtifactParams(params MaterializeArtifactParams) MaterializeArtifactParams {
	params.ArtifactKind = normalizeToken(params.ArtifactKind)
	params.SourceClass = normalizeToken(params.SourceClass)
	params.CoveragePolicy = normalizeToken(params.CoveragePolicy)
	params.Content = strings.TrimSpace(params.Content)
	return params
}

func validateMaterializeArtifactParams(params MaterializeArtifactParams) error {
	if params.RoomID <= 0 || params.CaseID <= 0 || params.CustomerID <= 0 || params.Content == "" || params.SourceClass == "" {
		return ErrInvalidInput
	}
	if params.ArtifactKind != "room_context" && params.ArtifactKind != "assessment_summary" {
		return ErrInvalidInput
	}
	if params.CoveragePolicy != classification.RoomCoverageSummaryMaterial && params.CoveragePolicy != classification.RoomCoverageSourceMaterial {
		return ErrInvalidInput
	}
	return nil
}

func validateJoinRoomParams(params JoinRoomParams) error {
	if params.RoomID <= 0 || params.UserID <= 0 {
		return ErrInvalidInput
	}
	if _, ok := allowedParticipantRoles[params.ParticipantRole]; !ok {
		return ErrInvalidInput
	}
	return nil
}

func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	normalized := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = normalizeToken(tag)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		normalized = append(normalized, tag)
	}
	sort.Strings(normalized)
	return normalized
}

func splitTags(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	return normalizeTags(strings.Split(value, ","))
}

func normalizeToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique")
}

```

### `internal/networkroom/repository_context.go (part 1, lines 1-68)`
```
package networkroom

import (
	"context"
	"fmt"
)

func (r *Repository) ListExtendedDossierCases(ctx context.Context, userID, roomID int64) ([]ExtendedCaseDossierInput, error) {
	cases, err := r.ListDossierCases(ctx, userID, roomID)
	if err != nil {
		return nil, err
	}

	detailCases := make([]ExtendedCaseDossierInput, 0, len(cases))
	byCaseID := make(map[int64]*ExtendedCaseDossierInput, len(cases))
	for _, c := range cases {
		item := ExtendedCaseDossierInput{CaseDossierInput: c}
		detailCases = append(detailCases, item)
		byCaseID[c.CaseID] = &detailCases[len(detailCases)-1]
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT nra.case_id, nra.id, nra.customer_id, nra.artifact_kind, nra.coverage_policy, nra.content
FROM network_room_artifacts nra
JOIN network_room_participants owned ON owned.room_id = nra.room_id AND owned.user_id = $1
WHERE nra.room_id = $2
  AND btrim(nra.content) <> ''
ORDER BY nra.case_id, nra.artifact_kind, nra.id`,
		userID,
		roomID,
	)
	if err != nil {
		return nil, fmt.Errorf("list network room artifacts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var caseID int64
		var artifactID, customerID int64
		var artifactKind, coveragePolicy, content string
		if err := rows.Scan(&caseID, &artifactID, &customerID, &artifactKind, &coveragePolicy, &content); err != nil {
			return nil, fmt.Errorf("scan network room artifact: %w", err)
		}
		if item, ok := byCaseID[caseID]; ok {
			switch artifactKind {
			case "room_context":
				item.ContextBlocks = append(item.ContextBlocks, DossierContextBlock{
					BlockID:        artifactID,
					CaseID:         caseID,
					CoveragePolicy: coveragePolicy,
					Content:        content,
				})
			case "assessment_summary":
				item.EvaluationBlocks = append(item.EvaluationBlocks, DossierEvaluationBlock{
					BlockID:        artifactID,
					CustomerID:     customerID,
					CoveragePolicy: coveragePolicy,
					Content:        content,
				})
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network room artifacts: %w", err)
	}

	return detailCases, nil
}

```

Reply only with this exact line in plain text: RECEIVED-0a7821dfbe8b