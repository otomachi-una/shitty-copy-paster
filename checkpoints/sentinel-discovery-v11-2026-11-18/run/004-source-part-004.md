Review turn ae5816a43943
SOURCE PART 4/4. This is source material from the file map already provided. Inspect each file or fragment now and add it to your working map. Note API/command entry points, cross-file calls, sensitive sources, output sinks, and the checks between them. Track split files across parts without drawing conclusions from an incomplete fragment. Keep this part for the final review.

### `internal/projection/contracts.go (part 1, lines 1-327)`
```
package projection

import (
	"sentinel-aml/internal/classification"
	"sort"
	"time"
)

// Contract records the JSON allowlist for one projection surface.
type Contract struct {
	Name              string
	View              any
	AllowedJSONFields []string
	OwnerOnly         bool
}

type OwnerCustomerView struct {
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

type OwnerAccountView struct {
	ID         int64     `json:"id"`
	CustomerID int64     `json:"customer_id"`
	IBANLike   string    `json:"iban_like"`
	Currency   string    `json:"currency"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

type OwnerTransactionView struct {
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

type OwnerAlertView struct {
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

type OwnerCaseView struct {
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

type OwnerCaseNoteView struct {
	ID           int64     `json:"id"`
	CaseID       int64     `json:"case_id"`
	AuthorUserID int64     `json:"author_user_id"`
	Visibility   string    `json:"visibility"`
	Body         string    `json:"body"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type OwnerEDDView struct {
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

type OwnerCaseAuditChangeView struct {
	Field    string `json:"field"`
	Old      string `json:"old,omitempty"`
	New      string `json:"new,omitempty"`
	Redacted bool   `json:"redacted"`
}

type OwnerCaseAuditView struct {
	ID              int64                      `json:"id"`
	ObjectType      string                     `json:"object_type"`
	ObjectID        int64                      `json:"object_id"`
	EventType       string                     `json:"event_type"`
	PublicMessage   string                     `json:"public_message"`
	Changes         []OwnerCaseAuditChangeView `json:"changes"`
	CreatedAt       time.Time                  `json:"created_at"`
	VisibilityScope string                     `json:"visibility_scope"`
}

type CaseDuplicatePreviewView struct {
	CaseID           int64    `json:"case_id"`
	PublicSummary    string   `json:"public_summary"`
	RiskTags         []string `json:"risk_tags"`
	OverlapScore     int      `json:"overlap_score"`
	MatchExplanation string   `json:"match_explanation"`
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

type EDDGraphSummaryView struct {
	CustomerID   int64     `json:"customer_id"`
	EntityHint   string    `json:"entity_hint"`
	ReviewStatus string    `json:"review_status"`
	RiskTags     []string  `json:"risk_tags"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ExportBundleView struct {
	Purpose         string                   `json:"purpose"`
	RedactionPolicy string                   `json:"redaction_policy"`
	GeneratedAt     time.Time                `json:"generated_at"`
	RootCase        ExportCaseShellView      `json:"root_case"`
	LinkedCases     []ExportCaseShellView    `json:"linked_cases"`
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

type NetworkRoomDossierView struct {
	Room           NetworkRoomSummaryView `json:"room"`
	Cases          []NetworkRoomCaseView  `json:"cases"`
	ScopePolicy    string                 `json:"scope_policy"`
	CoveragePolicy string                 `json:"coverage_policy"`
}

type FuturePublicCaseShell struct {
	ID            int64     `json:"id"`
	CustomerID    int64     `json:"customer_id"`
	Status        string    `json:"status"`
	PublicSummary string    `json:"public_summary"`
	RiskScore     int       `json:"risk_score"`
	TypologyHint  string    `json:"typology_hint"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type FutureDuplicatePreview struct {
	CandidateCustomerID int64  `json:"candidate_customer_id"`
	MatchCustomerID     int64  `json:"match_customer_id"`
	DisplayName         string `json:"display_name"`
	Country             string `json:"country"`
	RiskLevel           string `json:"risk_level"`
	MatchReason         string `json:"match_reason"`
	ConfidenceBucket    string `json:"confidence_bucket"`
}

type FutureAuditSummary struct {
	ID         int64     `json:"id"`
	EventType  string    `json:"event_type"`
	ObjectType string    `json:"object_type"`
	ObjectID   int64     `json:"object_id"`
	CreatedAt  time.Time `json:"created_at"`
}

type FutureExportSummary struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func CatalogProjectionFields() []string {
	profiles := classification.ProjectionProfiles()
	fields := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		fields = append(fields, profile.Name)
	}
	sort.Strings(fields)
	return fields
}

func CurrentOwnerContracts() []Contract {
	return []Contract{
		{Name: "owner_customer", View: OwnerCustomerView{}, AllowedJSONFields: []string{"id", "display_name", "customer_type", "country", "registration_number", "risk_level", "entity_hint", "created_at", "status"}, OwnerOnly: true},
		{Name: "owner_account", View: OwnerAccountView{}, AllowedJSONFields: []string{"id", "customer_id", "iban_like", "currency", "status", "created_at"}, OwnerOnly: true},
		{Name: "owner_transaction", View: OwnerTransactionView{}, AllowedJSONFields: []string{"id", "account_id", "counterparty_name", "counterparty_country", "counterparty_fingerprint", "amount", "currency", "direction", "purpose", "trace_id", "created_at", "risk_score"}, OwnerOnly: true},
		{Name: "owner_alert", View: OwnerAlertView{}, AllowedJSONFields: []string{"id", "transaction_id", "customer_id", "rule_code", "risk_score", "status", "assigned_user_id", "typology_hint", "created_at", "updated_at"}, OwnerOnly: true},
		{Name: "owner_case", View: OwnerCaseView{}, AllowedJSONFields: []string{"id", "customer_id", "alert_id", "status", "public_summary", "risk_score", "typology_hint", "created_at", "updated_at"}, OwnerOnly: true},
		{Name: "owner_case_note", View: OwnerCaseNoteView{}, AllowedJSONFields: []string{"id", "case_id", "author_user_id", "visibility", "body", "created_at", "updated_at"}, OwnerOnly: true},
		{Name: "owner_edd", View: OwnerEDDView{}, AllowedJSONFields: []string{"id", "customer_id", "analyst_user_id", "source_of_funds", "risk_rationale", "confidential_comment", "review_status", "created_at", "updated_at"}, OwnerOnly: true},
		{Name: "owner_case_audit", View: OwnerCaseAuditView{}, AllowedJSONFields: []string{"id", "object_type", "object_id", "event_type", "public_message", "changes", "created_at", "visibility_scope"}, OwnerOnly: true},
	}
}

func CurrentSideViewContracts() []Contract {
	return []Contract{
		{Name: "case_duplicate_preview", View: CaseDuplicatePreviewView{}, AllowedJSONFields: []string{"case_id", "public_summary", "risk_tags", "overlap_score", "match_explanation"}},
		{Name: "graph_entity", View: GraphEntityView{}, AllowedJSONFields: []string{"entity_hint", "relation_type", "customer_count", "case_count", "highest_risk", "risk_tags", "updated_at"}},
		{Name: "graph_related_case", View: GraphRelatedCaseView{}, AllowedJSONFields: []string{"case_id", "customer_id", "entity_hint", "display_name", "country", "status", "public_summary", "risk_score", "typology_hint", "created_at", "updated_at"}},
		{Name: "edd_graph_summary", View: EDDGraphSummaryView{}, AllowedJSONFields: []string{"customer_id", "entity_hint", "review_status", "risk_tags", "created_at", "updated_at"}},
		{Name: "export_bundle", View: ExportBundleView{}, AllowedJSONFields: []string{"purpose", "redaction_policy", "generated_at", "root_case", "linked_cases", "audit_summaries", "edd_summaries", "items"}},
		{Name: "export_case_shell", View: ExportCaseShellView{}, AllowedJSONFields: []string{"case_id", "customer_id", "status", "public_summary", "risk_score", "typology_hint", "created_at", "updated_at"}},
		{Name: "export_audit_summary", View: ExportAuditSummaryView{}, AllowedJSONFields: []string{"event_id", "object_type", "object_id", "event_type", "public_message", "changed_fields", "created_at"}},
		{Name: "export_edd_summary", View: ExportEDDSummaryView{}, AllowedJSONFields: []string{"record_id", "customer_id", "review_status", "risk_tags", "created_at", "updated_at"}},
		{Name: "export_item_metadata", View: ExportItemMetadataView{}, AllowedJSONFields: []string{"item_type", "object_type", "object_id", "relation", "redaction_policy"}},
		{Name: "network_room_summary", View: NetworkRoomSummaryView{}, AllowedJSONFields: []string{"id", "room_key", "entity_hint", "typology_hint", "status", "public_summary", "public_risk_tags", "case_count", "participant_count", "created_at", "updated_at"}},
		{Name: "network_room_case", View: NetworkRoomCaseView{}, AllowedJSONFields: []string{"case_id", "customer_id", "owned_by_requester", "status", "public_summary", "risk_score", "typology_hint", "public_risk_tags", "scope_coverage_complete", "created_at", "updated_at"}},
		{Name: "network_room_dossier", View: NetworkRoomDossierView{}, AllowedJSONFields: []string{"room", "cases", "scope_policy", "coverage_policy"}},
	}
}

func FutureSafeContracts() []Contract {
	return []Contract{
		{Name: "future_public_case_shell", View: FuturePublicCaseShell{}, AllowedJSONFields: []string{"id", "customer_id", "status", "public_summary", "risk_score", "typology_hint", "created_at", "updated_at"}},
		{Name: "future_duplicate_preview", View: FutureDuplicatePreview{}, AllowedJSONFields: []string{"candidate_customer_id", "match_customer_id", "display_name", "country", "risk_level", "match_reason", "confidence_bucket"}},
		{Name: "future_audit_summary", View: FutureAuditSummary{}, AllowedJSONFields: []string{"id", "event_type", "object_type", "object_id", "created_at"}},
		{Name: "future_export_summary", View: FutureExportSummary{}, AllowedJSONFields: []string{"id", "kind", "status", "created_at", "expires_at"}},
	}
}

```

### `internal/risk/scoring.go (part 1, lines 1-231)`
```
package risk

import (
	"context"
	"errors"
	"strconv"
	"strings"

	alertrepo "sentinel-aml/internal/alert"
	txn "sentinel-aml/internal/transaction"
)

const (
	RuleDeterministicThreshold = "DETERMINISTIC_RISK_THRESHOLD"
	SuspiciousThreshold        = 70
)

var ErrInvalidInput = errors.New("invalid risk input")

type TransactionRepository interface {
	GetByOwner(context.Context, int64, int64) (txn.Transaction, error)
	UpdateRiskScoreByOwner(context.Context, txn.RiskScoreParams) (txn.Transaction, error)
}

type AlertRepository interface {
	Create(context.Context, alertrepo.CreateParams) (alertrepo.Alert, error)
}

type Service struct {
	transactions TransactionRepository
	alerts       AlertRepository
}

type Input struct {
	Amount                  string
	Country                 string
	CounterpartyFingerprint string
	TypologyHint            string
}

type Decision struct {
	Transaction  txn.Transaction
	Alert        alertrepo.Alert
	RiskScore    int
	AmountBucket string
	TypologyHint string
	RuleCode     string
	Suspicious   bool
	AlertCreated bool
}

func NewService(transactions TransactionRepository, alerts AlertRepository) *Service {
	return &Service{transactions: transactions, alerts: alerts}
}

func (s *Service) ScoreTransaction(ctx context.Context, ownerUserID, transactionID int64) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if s == nil || s.transactions == nil || s.alerts == nil || ownerUserID <= 0 || transactionID <= 0 {
		return Decision{}, ErrInvalidInput
	}

	transaction, err := s.transactions.GetByOwner(ctx, ownerUserID, transactionID)
	if err != nil {
		return Decision{}, err
	}
	decision, err := Score(Input{
		Amount:                  transaction.Amount,
		Country:                 transaction.CounterpartyCountry,
		CounterpartyFingerprint: transaction.CounterpartyFingerprint,
	})
	if err != nil {
		return Decision{}, err
	}

	updatedTransaction, err := s.transactions.UpdateRiskScoreByOwner(ctx, txn.RiskScoreParams{
		OwnerUserID:   ownerUserID,
		TransactionID: transaction.ID,
		RiskScore:     decision.RiskScore,
	})
	if err != nil {
		return Decision{}, err
	}
	decision.Transaction = updatedTransaction

	if !decision.Suspicious {
		return decision, nil
	}
	alert, err := s.alerts.Create(ctx, alertrepo.CreateParams{
		OwnerUserID:   ownerUserID,
		TransactionID: transaction.ID,
		RuleCode:      decision.RuleCode,
		RiskScore:     decision.RiskScore,
		TypologyHint:  decision.TypologyHint,
	})
	if errors.Is(err, alertrepo.ErrDuplicate) {
		return decision, nil
	}
	if err != nil {
		return Decision{}, err
	}
	decision.Alert = alert
	decision.AlertCreated = true
	return decision, nil
}

func Score(input Input) (Decision, error) {
	if err := txn.ValidateAmount(input.Amount); err != nil {
		return Decision{}, ErrInvalidInput
	}
	bucket, amountWeight, err := amountBucket(input.Amount)
	if err != nil {
		return Decision{}, err
	}

	country := strings.ToUpper(strings.TrimSpace(input.Country))
	fingerprint := strings.ToLower(strings.TrimSpace(input.CounterpartyFingerprint))
	typology := strings.TrimSpace(input.TypologyHint)
	if typology == "" {
		typology = deriveTypology(bucket, country, fingerprint)
	}

	score := amountWeight + countryWeight(country) + fingerprintWeight(fingerprint) + typologyWeight(typology)
	if score > 100 {
		score = 100
	}

	decision := Decision{
		RiskScore:    score,
		AmountBucket: bucket,
		TypologyHint: typology,
		Suspicious:   score >= SuspiciousThreshold,
	}
	if decision.Suspicious {
		decision.RuleCode = RuleDeterministicThreshold
	}
	return decision, nil
}

func amountBucket(amount string) (string, int, error) {
	cents, err := amountCents(amount)
	if err != nil {
		return "", 0, err
	}
	switch {
	case cents < 100000:
		return "small", 5, nil
	case cents < 1000000:
		return "medium", 20, nil
	case cents < 5000000:
		return "large", 45, nil
	default:
		return "very_large", 65, nil
	}
}

func amountCents(amount string) (int64, error) {
	amount = strings.TrimSpace(amount)
	parts := strings.Split(amount, ".")
	whole := parts[0]
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	for len(fraction) < 2 {
		fraction += "0"
	}
	cents, err := strconv.ParseInt(whole+fraction, 10, 64)
	if err != nil {
		return 0, ErrInvalidInput
	}
	return cents, nil
}

func deriveTypology(bucket, country, fingerprint string) string {
	if countryWeight(country) > 0 {
		return "high-risk-country"
	}
	if fingerprintKeywordWeight(fingerprint) > 0 {
		return "counterparty-watchlist"
	}
	if bucket == "large" || bucket == "very_large" {
		return "large-value-transfer"
	}
	return "standard-transaction"
}

func countryWeight(country string) int {
	switch country {
	case "IR", "KP", "SY":
		return 20
	default:
		return 0
	}
}

func fingerprintWeight(fingerprint string) int {
	if weight := fingerprintKeywordWeight(fingerprint); weight > 0 {
		return weight
	}
	var sum int
	for _, r := range fingerprint {
		sum += int(r)
	}
	return (sum % 3) * 5
}

func fingerprintKeywordWeight(fingerprint string) int {
	for _, marker := range []string{"sanction", "watchlist", "shell", "mule"} {
		if strings.Contains(fingerprint, marker) {
			return 20
		}
	}
	return 0
}

func typologyWeight(typology string) int {
	switch typology {
	case "high-risk-country":
		return 10
	case "counterparty-watchlist":
		return 20
	case "large-value-transfer":
		return 15
	case "standard-transaction":
		return 0
	default:
		return 5
	}
}

```

### `internal/transaction/repository.go (part 1, lines 1-371)`
```
package transaction

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrTransactionNotFound = errors.New("transaction not found")
	ErrDuplicate           = errors.New("duplicate transaction trace id")
	ErrInvalidInput        = errors.New("invalid transaction input")
)

var allowedDirections = map[string]struct{}{
	"inbound":  {},
	"outbound": {},
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
	db queryer
}

type Transaction struct {
	ID                      int64
	AccountID               int64
	CounterpartyName        string
	CounterpartyCountry     string
	CounterpartyFingerprint string
	Amount                  string
	Currency                string
	Direction               string
	Purpose                 string
	TraceID                 string
	CreatedAt               time.Time
	RiskScore               int
}

type CreateParams struct {
	OwnerUserID             int64
	AccountID               int64
	CounterpartyName        string
	CounterpartyCountry     string
	CounterpartyFingerprint string
	Amount                  string
	Currency                string
	Direction               string
	Purpose                 string
	TraceID                 string
}

type RiskScoreParams struct {
	OwnerUserID   int64
	TransactionID int64
	RiskScore     int
}

func NewRepository(db *sql.DB) *Repository {
	return newRepository(sqlDBAdapter{db: db})
}

func newRepository(db queryer) *Repository {
	return &Repository{db: db}
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

func (r *Repository) Create(ctx context.Context, params CreateParams) (Transaction, error) {
	if err := ctx.Err(); err != nil {
		return Transaction{}, err
	}
	if err := validateCreateParams(params); err != nil {
		return Transaction{}, err
	}
	params = normalizeCreateParams(params)

	var transaction Transaction
	err := r.db.QueryRowContext(ctx, `
INSERT INTO transactions (account_id, counterparty_name, counterparty_country, counterparty_fingerprint, amount, currency, direction, purpose, trace_id)
SELECT a.id, $3, $4, $5, $6, $7, $8, $9, $10
FROM accounts a
JOIN customers c ON c.id = a.customer_id
WHERE c.owner_user_id = $1 AND a.id = $2
RETURNING id, account_id, counterparty_name, counterparty_country, counterparty_fingerprint, amount::text, currency, direction, purpose, trace_id, created_at, risk_score`,
		params.OwnerUserID,
		params.AccountID,
		params.CounterpartyName,
		params.CounterpartyCountry,
		params.CounterpartyFingerprint,
		params.Amount,
		params.Currency,
		params.Direction,
		params.Purpose,
		params.TraceID,
	).Scan(&transaction.ID, &transaction.AccountID, &transaction.CounterpartyName, &transaction.CounterpartyCountry, &transaction.CounterpartyFingerprint, &transaction.Amount, &transaction.Currency, &transaction.Direction, &transaction.Purpose, &transaction.TraceID, &transaction.CreatedAt, &transaction.RiskScore)
	if errors.Is(err, sql.ErrNoRows) {
		return Transaction{}, ErrTransactionNotFound
	}
	if isUniqueViolation(err) {
		return Transaction{}, ErrDuplicate
	}
	if err != nil {
		return Transaction{}, fmt.Errorf("create transaction: %w", err)
	}
	return transaction, nil
}

func (r *Repository) GetByOwner(ctx context.Context, ownerUserID, transactionID int64) (Transaction, error) {
	if err := ctx.Err(); err != nil {
		return Transaction{}, err
	}
	if ownerUserID <= 0 || transactionID <= 0 {
		return Transaction{}, ErrInvalidInput
	}

	var transaction Transaction
	err := r.db.QueryRowContext(ctx, `
SELECT t.id, t.account_id, t.counterparty_name, t.counterparty_country, t.counterparty_fingerprint, t.amount::text, t.currency, t.direction, t.purpose, t.trace_id, t.created_at, t.risk_score
FROM transactions t
JOIN accounts a ON a.id = t.account_id
JOIN customers c ON c.id = a.customer_id
WHERE c.owner_user_id = $1 AND t.id = $2`,
		ownerUserID,
		transactionID,
	).Scan(&transaction.ID, &transaction.AccountID, &transaction.CounterpartyName, &transaction.CounterpartyCountry, &transaction.CounterpartyFingerprint, &transaction.Amount, &transaction.Currency, &transaction.Direction, &transaction.Purpose, &transaction.TraceID, &transaction.CreatedAt, &transaction.RiskScore)
	if errors.Is(err, sql.ErrNoRows) {
		return Transaction{}, ErrTransactionNotFound
	}
	if err != nil {
		return Transaction{}, fmt.Errorf("get transaction by owner: %w", err)
	}
	return transaction, nil
}

func (r *Repository) UpdateRiskScoreByOwner(ctx context.Context, params RiskScoreParams) (Transaction, error) {
	if err := ctx.Err(); err != nil {
		return Transaction{}, err
	}
	if params.OwnerUserID <= 0 || params.TransactionID <= 0 || params.RiskScore < 0 || params.RiskScore > 100 {
		return Transaction{}, ErrInvalidInput
	}

	var transaction Transaction
	err := r.db.QueryRowContext(ctx, `
UPDATE transactions t
SET risk_score = $3
FROM accounts a
JOIN customers c ON c.id = a.customer_id
WHERE t.account_id = a.id AND c.owner_user_id = $1 AND t.id = $2
RETURNING t.id, t.account_id, t.counterparty_name, t.counterparty_country, t.counterparty_fingerprint, t.amount::text, t.currency, t.direction, t.purpose, t.trace_id, t.created_at, t.risk_score`,
		params.OwnerUserID,
		params.TransactionID,
		params.RiskScore,
	).Scan(&transaction.ID, &transaction.AccountID, &transaction.CounterpartyName, &transaction.CounterpartyCountry, &transaction.CounterpartyFingerprint, &transaction.Amount, &transaction.Currency, &transaction.Direction, &transaction.Purpose, &transaction.TraceID, &transaction.CreatedAt, &transaction.RiskScore)
	if errors.Is(err, sql.ErrNoRows) {
		return Transaction{}, ErrTransactionNotFound
	}
	if err != nil {
		return Transaction{}, fmt.Errorf("update transaction risk score by owner: %w", err)
	}
	return transaction, nil
}

func (r *Repository) ListByOwner(ctx context.Context, ownerUserID int64) ([]Transaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ownerUserID <= 0 {
		return nil, ErrInvalidInput
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT t.id, t.account_id, t.counterparty_name, t.counterparty_country, t.counterparty_fingerprint, t.amount::text, t.currency, t.direction, t.purpose, t.trace_id, t.created_at, t.risk_score
FROM transactions t
JOIN accounts a ON a.id = t.account_id
JOIN customers c ON c.id = a.customer_id
WHERE c.owner_user_id = $1
ORDER BY t.id`,
		ownerUserID,
	)
	if err != nil {
		return nil, fmt.Errorf("list transactions by owner: %w", err)
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var transaction Transaction
		if err := rows.Scan(&transaction.ID, &transaction.AccountID, &transaction.CounterpartyName, &transaction.CounterpartyCountry, &transaction.CounterpartyFingerprint, &transaction.Amount, &transaction.Currency, &transaction.Direction, &transaction.Purpose, &transaction.TraceID, &transaction.CreatedAt, &transaction.RiskScore); err != nil {
			return nil, fmt.Errorf("scan transaction: %w", err)
		}
		transactions = append(transactions, transaction)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate transactions: %w", err)
	}
	return transactions, nil
}

func (r *Repository) ListByCustomerOwner(ctx context.Context, ownerUserID, customerID int64) ([]Transaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ownerUserID <= 0 || customerID <= 0 {
		return nil, ErrInvalidInput
	}

	var ownedCustomerID int64
	if err := r.db.QueryRowContext(ctx, `
SELECT id
FROM customers
WHERE owner_user_id = $1 AND id = $2`,
		ownerUserID,
		customerID,
	).Scan(&ownedCustomerID); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTransactionNotFound
	} else if err != nil {
		return nil, fmt.Errorf("verify customer owner for transactions: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT t.id, t.account_id, t.counterparty_name, t.counterparty_country, t.counterparty_fingerprint, t.amount::text, t.currency, t.direction, t.purpose, t.trace_id, t.created_at, t.risk_score
FROM transactions t
JOIN accounts a ON a.id = t.account_id
JOIN customers c ON c.id = a.customer_id
WHERE c.owner_user_id = $1 AND c.id = $2
ORDER BY t.id`,
		ownerUserID,
		customerID,
	)
	if err != nil {
		return nil, fmt.Errorf("list transactions by customer owner: %w", err)
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var transaction Transaction
		if err := rows.Scan(&transaction.ID, &transaction.AccountID, &transaction.CounterpartyName, &transaction.CounterpartyCountry, &transaction.CounterpartyFingerprint, &transaction.Amount, &transaction.Currency, &transaction.Direction, &transaction.Purpose, &transaction.TraceID, &transaction.CreatedAt, &transaction.RiskScore); err != nil {
			return nil, fmt.Errorf("scan transaction: %w", err)
		}
		transactions = append(transactions, transaction)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate transactions: %w", err)
	}
	return transactions, nil
}

func validateCreateParams(params CreateParams) error {
	if params.OwnerUserID <= 0 || params.AccountID <= 0 {
		return ErrInvalidInput
	}
	if strings.TrimSpace(params.CounterpartyName) == "" ||
		strings.TrimSpace(params.CounterpartyCountry) == "" ||
		strings.TrimSpace(params.CounterpartyFingerprint) == "" ||
		!validCurrency(params.Currency) ||
		strings.TrimSpace(params.Purpose) == "" ||
		strings.TrimSpace(params.TraceID) == "" {
		return ErrInvalidInput
	}
	if err := ValidateAmount(params.Amount); err != nil {
		return err
	}
	if _, ok := allowedDirections[params.Direction]; !ok {
		return ErrInvalidInput
	}
	return nil
}

func ValidateAmount(amount string) error {
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return ErrInvalidInput
	}

	parts := strings.Split(amount, ".")
	if len(parts) > 2 || parts[0] == "" {
		return ErrInvalidInput
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
		if len(fraction) == 0 || len(fraction) > 2 {
			return ErrInvalidInput
		}
	}
	if !allDigits(parts[0]) || (fraction != "" && !allDigits(fraction)) {
		return ErrInvalidInput
	}
	if len(strings.TrimLeft(parts[0], "0")) > 16 {
		return ErrInvalidInput
	}
	if strings.Trim(parts[0]+fraction, "0") == "" {
		return ErrInvalidInput
	}
	return nil
}

func normalizeCreateParams(params CreateParams) CreateParams {
	params.CounterpartyName = strings.TrimSpace(params.CounterpartyName)
	params.CounterpartyCountry = strings.TrimSpace(params.CounterpartyCountry)
	params.CounterpartyFingerprint = strings.TrimSpace(params.CounterpartyFingerprint)
	params.Amount = strings.TrimSpace(params.Amount)
	params.Currency = strings.TrimSpace(params.Currency)
	params.Purpose = strings.TrimSpace(params.Purpose)
	params.TraceID = strings.TrimSpace(params.TraceID)
	return params
}

func validCurrency(currency string) bool {
	if len(currency) != 3 {
		return false
	}
	for _, r := range currency {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type sqlStateError interface {
	SQLState() string
}

func isUniqueViolation(err error) bool {
	var stateErr sqlStateError
	if errors.As(err, &stateErr) && stateErr.SQLState() == "23505" {
		return true
	}
	return strings.Contains(strings.ToLower(fmt.Sprint(err)), "duplicate key")
}

```

### `migrations/000001_create_users_sessions.sql (part 1, lines 1-25)`
```
CREATE TABLE users (
    id bigserial PRIMARY KEY,
    username text NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_username_unique UNIQUE (username),
    CONSTRAINT users_role_check CHECK (role IN ('analyst', 'senior_analyst', 'supervisor', 'auditor', 'system_worker')),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE sessions (
    id bigserial PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT sessions_token_hash_unique UNIQUE (token_hash),
    CONSTRAINT sessions_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_active_token_hash_idx ON sessions(token_hash) WHERE revoked_at IS NULL;

```

### `migrations/000002_create_customers_accounts_transactions.sql (part 1, lines 1-61)`
```
CREATE TABLE customers (
    id bigserial PRIMARY KEY,
    owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name text NOT NULL,
    customer_type text NOT NULL,
    country text NOT NULL,
    registration_number text NOT NULL,
    risk_level text NOT NULL DEFAULT 'medium',
    entity_hint text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL DEFAULT 'active',
    UNIQUE (owner_user_id, registration_number),
    CHECK (customer_type IN ('individual', 'organization')),
    CHECK (risk_level IN ('low', 'medium', 'high')),
    CHECK (status IN ('active', 'inactive'))
);

CREATE INDEX customers_owner_user_id_idx ON customers(owner_user_id);
CREATE INDEX customers_owner_status_idx ON customers(owner_user_id, status);
CREATE INDEX customers_risk_level_idx ON customers(risk_level);

CREATE TABLE accounts (
    id bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    iban_like text NOT NULL,
    currency text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_id, iban_like),
    CHECK (currency ~ '^[A-Z]{3}$'),
    CHECK (status IN ('active', 'closed'))
);

CREATE INDEX accounts_customer_id_idx ON accounts(customer_id);
CREATE INDEX accounts_status_idx ON accounts(status);

CREATE TABLE transactions (
    id bigserial PRIMARY KEY,
    account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    counterparty_name text NOT NULL,
    counterparty_country text NOT NULL,
    counterparty_fingerprint text NOT NULL,
    amount numeric(18,2) NOT NULL,
    currency text NOT NULL,
    direction text NOT NULL,
    purpose text NOT NULL,
    trace_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    risk_score integer NOT NULL DEFAULT 0,
    UNIQUE (account_id, trace_id),
    CHECK (amount > 0),
    CHECK (currency ~ '^[A-Z]{3}$'),
    CHECK (direction IN ('inbound', 'outbound')),
    CHECK (risk_score >= 0 AND risk_score <= 100)
);

CREATE INDEX transactions_account_id_idx ON transactions(account_id);
CREATE INDEX transactions_trace_id_idx ON transactions(trace_id);
CREATE INDEX transactions_counterparty_fingerprint_idx ON transactions(counterparty_fingerprint);
CREATE INDEX transactions_created_at_idx ON transactions(created_at);
CREATE INDEX transactions_risk_score_idx ON transactions(risk_score);

```

### `migrations/000003_create_alerts_cases_notes.sql (part 1, lines 1-60)`
```
CREATE TABLE alerts (
    id bigserial PRIMARY KEY,
    transaction_id bigint NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    rule_code text NOT NULL,
    risk_score integer NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'NEW',
    assigned_user_id bigint REFERENCES users(id) ON DELETE SET NULL,
    typology_hint text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (transaction_id, rule_code),
    CHECK (risk_score >= 0 AND risk_score <= 100),
    CHECK (status IN ('NEW', 'TRIAGED', 'CASE_OPENED', 'ESCALATED', 'CLOSED'))
);

CREATE INDEX alerts_transaction_id_idx ON alerts(transaction_id);
CREATE INDEX alerts_customer_id_idx ON alerts(customer_id);
CREATE INDEX alerts_customer_status_idx ON alerts(customer_id, status);
CREATE INDEX alerts_assigned_user_id_idx ON alerts(assigned_user_id);
CREATE INDEX alerts_status_idx ON alerts(status);
CREATE INDEX alerts_updated_at_idx ON alerts(updated_at);

CREATE TABLE cases (
    id bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    alert_id bigint NOT NULL REFERENCES alerts(id) ON DELETE RESTRICT,
    owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'OPEN',
    public_summary text NOT NULL DEFAULT '',
    risk_score integer NOT NULL DEFAULT 0,
    typology_hint text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (alert_id),
    CHECK (risk_score >= 0 AND risk_score <= 100),
    CHECK (status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED', 'REPORTED', 'CLOSED'))
);

CREATE INDEX cases_customer_id_idx ON cases(customer_id);
CREATE INDEX cases_alert_id_idx ON cases(alert_id);
CREATE INDEX cases_owner_user_id_idx ON cases(owner_user_id);
CREATE INDEX cases_owner_status_idx ON cases(owner_user_id, status);
CREATE INDEX cases_updated_at_idx ON cases(updated_at);

CREATE TABLE case_notes (
    id bigserial PRIMARY KEY,
    case_id bigint NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    visibility text NOT NULL DEFAULT 'private',
    body text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (visibility IN ('private', 'internal'))
);

CREATE INDEX case_notes_case_id_idx ON case_notes(case_id);
CREATE INDEX case_notes_author_user_id_idx ON case_notes(author_user_id);
CREATE INDEX case_notes_visibility_idx ON case_notes(visibility);
CREATE INDEX case_notes_updated_at_idx ON case_notes(updated_at);

```

### `migrations/000004_create_edd_records.sql (part 1, lines 1-18)`
```
CREATE TABLE edd_records (
    id bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
    analyst_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    source_of_funds text NOT NULL,
    risk_rationale text NOT NULL,
    confidential_comment text NOT NULL,
    review_status text NOT NULL DEFAULT 'DRAFT',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_id),
    CHECK (review_status IN ('DRAFT', 'IN_REVIEW', 'APPROVED', 'REJECTED'))
);

CREATE INDEX edd_records_customer_id_idx ON edd_records(customer_id);
CREATE INDEX edd_records_analyst_user_id_idx ON edd_records(analyst_user_id);
CREATE INDEX edd_records_review_status_idx ON edd_records(review_status);
CREATE INDEX edd_records_updated_at_idx ON edd_records(updated_at);

```

### `migrations/000005_add_case_dedup_hint.sql (part 1, lines 1-9)`
```
ALTER TABLE cases
    ADD COLUMN dedup_hint text NOT NULL DEFAULT '';

ALTER TABLE cases
    ADD CONSTRAINT cases_dedup_hint_not_blank_when_set
    CHECK (dedup_hint = '' OR btrim(dedup_hint) <> '');

CREATE INDEX cases_dedup_hint_idx ON cases(dedup_hint) WHERE dedup_hint <> '';
CREATE INDEX cases_owner_dedup_hint_idx ON cases(owner_user_id, dedup_hint) WHERE dedup_hint <> '';

```

### `migrations/000006_create_audit_events.sql (part 1, lines 1-22)`
```
CREATE TABLE audit_events (
    id bigserial PRIMARY KEY,
    actor_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    object_type text NOT NULL,
    object_id bigint NOT NULL,
    event_type text NOT NULL,
    public_message text NOT NULL DEFAULT '',
    diff_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    visibility_scope text NOT NULL DEFAULT 'owner',
    CHECK (object_id > 0),
    CHECK (object_type IN ('customer', 'account', 'transaction', 'alert', 'case', 'case_note', 'edd_record')),
    CHECK (event_type IN ('created', 'updated', 'status_changed', 'claimed', 'triaged', 'reviewed')),
    CHECK (visibility_scope IN ('owner', 'internal', 'system')),
    CHECK (jsonb_typeof(diff_json) = 'array')
);

CREATE INDEX audit_events_actor_user_id_idx ON audit_events(actor_user_id);
CREATE INDEX audit_events_object_idx ON audit_events(object_type, object_id);
CREATE INDEX audit_events_event_type_idx ON audit_events(event_type);
CREATE INDEX audit_events_visibility_created_idx ON audit_events(visibility_scope, created_at);
CREATE INDEX audit_events_created_at_idx ON audit_events(created_at);

```

### `migrations/000007_create_entity_graph.sql (part 1, lines 1-33)`
```
CREATE TABLE entity_graph_nodes (
    id bigserial PRIMARY KEY,
    entity_hint text NOT NULL,
    node_type text NOT NULL,
    display_label text NOT NULL DEFAULT '',
    public_risk_tags text[] NOT NULL DEFAULT '{}'::text[],
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (entity_hint, node_type),
    CHECK (btrim(entity_hint) <> ''),
    CHECK (node_type IN ('customer_entity', 'counterparty', 'case_cluster', 'edd_status'))
);

CREATE TABLE entity_graph_edges (
    id bigserial PRIMARY KEY,
    source_node_id bigint NOT NULL REFERENCES entity_graph_nodes(id) ON DELETE CASCADE,
    target_node_id bigint NOT NULL REFERENCES entity_graph_nodes(id) ON DELETE CASCADE,
    relation_type text NOT NULL,
    strength integer NOT NULL DEFAULT 0,
    public_summary text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_node_id, target_node_id, relation_type),
    CHECK (source_node_id <> target_node_id),
    CHECK (relation_type IN ('shared_entity_hint', 'shared_counterparty', 'same_case_cluster', 'edd_status_overlap')),
    CHECK (strength >= 0 AND strength <= 100)
);

CREATE INDEX entity_graph_nodes_entity_hint_idx ON entity_graph_nodes(entity_hint);
CREATE INDEX entity_graph_nodes_node_type_idx ON entity_graph_nodes(node_type);
CREATE INDEX entity_graph_edges_source_node_id_idx ON entity_graph_edges(source_node_id);
CREATE INDEX entity_graph_edges_target_node_id_idx ON entity_graph_edges(target_node_id);
CREATE INDEX entity_graph_edges_relation_type_idx ON entity_graph_edges(relation_type);

```

### `migrations/000008_create_exports_disputes.sql (part 1, lines 1-63)`
```
CREATE TABLE disputes (
    id bigserial PRIMARY KEY,
    owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    case_id bigint NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'OPEN',
    reason text NOT NULL,
    resolution_summary text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_user_id, case_id, status),
    CHECK (btrim(reason) <> ''),
    CHECK (status IN ('OPEN', 'UNDER_REVIEW', 'RESOLVED', 'REJECTED'))
);

CREATE INDEX disputes_owner_status_idx ON disputes(owner_user_id, status);
CREATE INDEX disputes_case_id_idx ON disputes(case_id);
CREATE INDEX disputes_created_at_idx ON disputes(created_at);

CREATE TABLE exports (
    id bigserial PRIMARY KEY,
    owner_user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    root_case_id bigint NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    dispute_id bigint REFERENCES disputes(id) ON DELETE SET NULL,
    purpose text NOT NULL,
    status text NOT NULL DEFAULT 'PENDING',
    bundle_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    redaction_policy text NOT NULL DEFAULT 'public_redacted',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
    CHECK (btrim(purpose) <> ''),
    CHECK (status IN ('PENDING', 'GENERATED', 'FAILED', 'EXPIRED')),
    CHECK (redaction_policy IN ('public_redacted')),
    CHECK (jsonb_typeof(bundle_json) = 'object')
);

CREATE INDEX exports_owner_status_idx ON exports(owner_user_id, status);
CREATE INDEX exports_root_case_id_idx ON exports(root_case_id);
CREATE INDEX exports_dispute_id_idx ON exports(dispute_id);
CREATE INDEX exports_expires_at_idx ON exports(expires_at);

CREATE TABLE export_items (
    id bigserial PRIMARY KEY,
    export_id bigint NOT NULL REFERENCES exports(id) ON DELETE CASCADE,
    item_type text NOT NULL,
    object_type text NOT NULL,
    object_id bigint NOT NULL,
    relation text NOT NULL,
    redaction_policy text NOT NULL DEFAULT 'public_redacted',
    payload_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (export_id, item_type, object_type, object_id, relation),
    CHECK (object_id > 0),
    CHECK (item_type IN ('root_case', 'linked_case', 'audit_summary', 'edd_summary', 'metadata')),
    CHECK (object_type IN ('case', 'audit_event', 'edd_record', 'export')),
    CHECK (relation IN ('root', 'linked', 'audit', 'edd', 'metadata')),
    CHECK (redaction_policy IN ('public_redacted')),
    CHECK (jsonb_typeof(payload_json) = 'object')
);

CREATE INDEX export_items_export_id_idx ON export_items(export_id);
CREATE INDEX export_items_object_idx ON export_items(object_type, object_id);
CREATE INDEX export_items_item_type_idx ON export_items(item_type);

```

### `migrations/000009_create_network_rooms.sql (part 1, lines 1-49)`
```
CREATE TABLE network_rooms (
    id bigserial PRIMARY KEY,
    room_key text NOT NULL,
    entity_hint text NOT NULL,
    typology_hint text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'OPEN',
    public_summary text NOT NULL DEFAULT '',
    public_risk_tags text[] NOT NULL DEFAULT '{}'::text[],
    created_by_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (room_key),
    CHECK (btrim(room_key) <> ''),
    CHECK (btrim(entity_hint) <> ''),
    CHECK (status IN ('OPEN', 'MONITORING', 'CLOSED'))
);

CREATE INDEX network_rooms_entity_hint_idx ON network_rooms(entity_hint);
CREATE INDEX network_rooms_typology_hint_idx ON network_rooms(typology_hint) WHERE typology_hint <> '';
CREATE INDEX network_rooms_status_idx ON network_rooms(status);
CREATE INDEX network_rooms_created_by_user_id_idx ON network_rooms(created_by_user_id);

CREATE TABLE network_room_cases (
    id bigserial PRIMARY KEY,
    room_id bigint NOT NULL REFERENCES network_rooms(id) ON DELETE CASCADE,
    case_id bigint NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    relation_type text NOT NULL DEFAULT 'related_case',
    added_by_user_id bigint NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (room_id, case_id),
    CHECK (relation_type IN ('root_case', 'related_case', 'typology_match', 'entity_match'))
);

CREATE INDEX network_room_cases_room_id_idx ON network_room_cases(room_id);
CREATE INDEX network_room_cases_case_id_idx ON network_room_cases(case_id);
CREATE INDEX network_room_cases_relation_type_idx ON network_room_cases(relation_type);

CREATE TABLE network_room_participants (
    id bigserial PRIMARY KEY,
    room_id bigint NOT NULL REFERENCES network_rooms(id) ON DELETE CASCADE,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    participant_role text NOT NULL DEFAULT 'analyst',
    joined_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (room_id, user_id),
    CHECK (participant_role IN ('analyst', 'observer'))
);

CREATE INDEX network_room_participants_room_id_idx ON network_room_participants(room_id);
CREATE INDEX network_room_participants_user_id_idx ON network_room_participants(user_id);

```

### `migrations/000010_create_network_room_artifacts.sql (part 1, lines 1-20)`
```
CREATE TABLE network_room_artifacts (
    id bigserial PRIMARY KEY,
    room_id bigint NOT NULL REFERENCES network_rooms(id) ON DELETE CASCADE,
    case_id bigint NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    artifact_kind text NOT NULL,
    source_class text NOT NULL,
    coverage_policy text NOT NULL,
    content text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (room_id, case_id, artifact_kind, source_class),
    CHECK (artifact_kind IN ('room_context', 'assessment_summary')),
    CHECK (coverage_policy IN ('room_summary', 'source_scope')),
    CHECK (btrim(source_class) <> '')
);

CREATE INDEX network_room_artifacts_room_id_idx ON network_room_artifacts(room_id);
CREATE INDEX network_room_artifacts_case_id_idx ON network_room_artifacts(case_id);
CREATE INDEX network_room_artifacts_coverage_idx ON network_room_artifacts(coverage_policy);

```

### `migrations/000011_network_room_dirty_candidates.sql (part 1, lines 1-44)`
```
CREATE TABLE network_room_dirty_candidates (
    id bigserial PRIMARY KEY,
    entity_hint_norm text NOT NULL,
    typology_hint_norm text NOT NULL,
    reason text NOT NULL DEFAULT 'case_changed',
    status text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (entity_hint_norm, typology_hint_norm),
    CHECK (btrim(entity_hint_norm) <> ''),
    CHECK (btrim(typology_hint_norm) <> ''),
    CHECK (status IN ('pending', 'processing', 'done'))
);

CREATE INDEX IF NOT EXISTS network_room_dirty_candidates_pending_idx
ON network_room_dirty_candidates (updated_at, id)
WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS network_room_dirty_candidates_expired_processing_idx
ON network_room_dirty_candidates (locked_until, id)
WHERE status = 'processing';

CREATE INDEX IF NOT EXISTS customers_entity_hint_norm_idx
ON customers ((replace(lower(btrim(entity_hint)), ' ', '_')))
WHERE btrim(entity_hint) <> '';

CREATE INDEX IF NOT EXISTS cases_typology_hint_norm_idx
ON cases ((replace(lower(btrim(typology_hint)), ' ', '_')))
WHERE btrim(typology_hint) <> '';

CREATE INDEX IF NOT EXISTS cases_customer_typology_idx
ON cases(customer_id, typology_hint);

CREATE INDEX IF NOT EXISTS network_room_cases_room_idx
ON network_room_cases(room_id);

CREATE INDEX IF NOT EXISTS network_room_cases_case_idx
ON network_room_cases(case_id);

CREATE INDEX IF NOT EXISTS audit_events_object_created_idx
ON audit_events(object_type, object_id, created_at);

```

Reply only with this exact line in plain text: RECEIVED-d5138f9d23e7