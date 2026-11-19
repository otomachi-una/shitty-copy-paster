Review turn b8ea6f5f0704
SOURCE PART 2/4. This is source material from the file map already provided. Inspect each file or fragment now and add it to your working map. Note API/command entry points, cross-file calls, sensitive sources, output sinks, and the checks between them. Track split files across parts without drawing conclusions from an incomplete fragment. Keep this part for the final review.

### `internal/exporting/redaction.go (part 1, lines 1-517)`
```
package exporting

import (
	"sentinel-aml/internal/classification"
	"sort"
	"strings"
	"time"
)

const RedactionPolicyPublic = "public_redacted"

var allowedExportScopes = map[string]struct{}{
	"root_case":     {},
	"linked_cases":  {},
	"audit_summary": {},
	"edd_summary":   {},
	"item_metadata": {},
}

var sensitiveExportFields = map[string]struct{}{
	"body":                            {},
	"case_note.body":                  {},
	"confidential_comment":            {},
	"edd_record.confidential_comment": {},
	"source_of_funds":                 {},
	"risk_rationale":                  {},
	"diff_json":                       {},
	"old_hash":                        {},
	"new_hash":                        {},
	"value_hash":                      {},
	"password":                        {},
	"password_hash":                   {},
	"token":                           {},
	"token_hash":                      {},
	"session":                         {},
	"internal_review_marker":          {},
	"external_reference_value":        {},
	"verification_marker":             {},
}

type ExportContext struct {
	RequesterUserID int64
	RootCaseID      int64
	DisputeID       int64
	Purpose         string
	AllowedScopes   []string
	Scope           ExportScope
}

type ExportScope string

const (
	ExportScopeRootCaseDetail    ExportScope = classification.ExportScopeRootCaseDetail
	ExportScopeLinkedCaseSummary ExportScope = classification.ExportScopeLinkedCaseSummary
)

type ExportCaseTraversal struct {
	Root   ExportContext
	Linked ExportContext
}

type ExportSourceMaterial struct {
	ItemType        string
	ObjectType      string
	ObjectID        int64
	CaseID          int64
	Relation        string
	SourceClass     string
	Content         string
	EvidenceExcerpt string
	Caption         string
	CoveragePolicy  ExportScope
}

type ExportItemBuilder struct {
	Context ExportContext
}

type CaseSnapshot struct {
	CaseID          int64
	CustomerID      int64
	OwnerUserID     int64
	Status          string
	PublicSummary   string
	RiskScore       int
	TypologyHint    string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Notes           []CaseNoteSnapshot
	AuditEvents     []AuditEventSnapshot
	EDDRecords      []EDDRecordSnapshot
	LinkedCases     []CaseSnapshot
	SourceMaterials []ExportSourceMaterial
}

type CaseNoteSnapshot struct {
	ID         int64
	Visibility string
	Body       string
	CreatedAt  time.Time
}

type AuditEventSnapshot struct {
	ID            int64
	ObjectType    string
	ObjectID      int64
	EventType     string
	PublicMessage string
	DiffJSON      string
	Changes       []AuditChangeSnapshot
	CreatedAt     time.Time
}

type AuditChangeSnapshot struct {
	Field    string
	Old      string
	New      string
	OldHash  string
	NewHash  string
	Redacted bool
}

type EDDRecordSnapshot struct {
	ID                  int64
	CustomerID          int64
	ReviewStatus        string
	RiskLevel           string
	SourceOfFunds       string
	RiskRationale       string
	ConfidentialComment string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type ExportBundle struct {
	Purpose         string               `json:"purpose"`
	RedactionPolicy string               `json:"redaction_policy"`
	GeneratedAt     time.Time            `json:"generated_at"`
	RootCase        ExportCaseShell      `json:"root_case"`
	LinkedCases     []ExportCaseShell    `json:"linked_cases"`
	LinkedEvidence  []map[string]any     `json:"linked_evidence,omitempty"`
	AuditSummaries  []ExportAuditSummary `json:"audit_summaries"`
	EDDSummaries    []ExportEDDSummary   `json:"edd_summaries"`
	Items           []ExportItemMetadata `json:"items"`
}

type ExportCaseShell struct {
	CaseID        int64     `json:"case_id"`
	CustomerID    int64     `json:"customer_id"`
	Status        string    `json:"status"`
	PublicSummary string    `json:"public_summary"`
	RiskScore     int       `json:"risk_score"`
	TypologyHint  string    `json:"typology_hint"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type ExportAuditSummary struct {
	EventID       int64     `json:"event_id"`
	ObjectType    string    `json:"object_type"`
	ObjectID      int64     `json:"object_id"`
	EventType     string    `json:"event_type"`
	PublicMessage string    `json:"public_message"`
	ChangedFields []string  `json:"changed_fields"`
	CreatedAt     time.Time `json:"created_at"`
}

type ExportEDDSummary struct {
	RecordID     int64     `json:"record_id"`
	CustomerID   int64     `json:"customer_id"`
	ReviewStatus string    `json:"review_status"`
	RiskTags     []string  `json:"risk_tags"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ExportItemMetadata struct {
	ItemType        string `json:"item_type"`
	ObjectType      string `json:"object_type"`
	ObjectID        int64  `json:"object_id"`
	Relation        string `json:"relation"`
	RedactionPolicy string `json:"redaction_policy"`
}

func BuildBundle(ctx ExportContext, root CaseSnapshot, generatedAt time.Time) (ExportBundle, error) {
	ctx = normalizeExportContext(ctx)
	if err := validateExportContext(ctx); err != nil {
		return ExportBundle{}, err
	}
	if root.CaseID != ctx.RootCaseID || root.OwnerUserID != ctx.RequesterUserID {
		return ExportBundle{}, ErrExportNotFound
	}
	traversal := NewExportCaseTraversal(ctx)

	bundle := ExportBundle{
		Purpose:         ctx.Purpose,
		RedactionPolicy: RedactionPolicyPublic,
		GeneratedAt:     generatedAt.UTC(),
		RootCase:        safeCaseShell(root),
	}
	scopes := scopeSet(ctx.AllowedScopes)
	if scopes["item_metadata"] {
		bundle.Items = append(bundle.Items, itemMetadata("root_case", "case", root.CaseID, "root"))
	}
	visited := map[int64]bool{root.CaseID: true}
	appendSafeCaseData(&bundle, root, scopes, "root")
	linkedCases := flattenLinkedCases(root.LinkedCases, visited)
	for _, linked := range linkedCases {
		if scopes["linked_cases"] {
			bundle.LinkedCases = append(bundle.LinkedCases, safeCaseShell(linked))
		}
		appendSafeCaseData(&bundle, linked, scopes, "linked")
	}
	appendExportLinkedCaseData(&bundle, root, linkedCases, scopes, traversal)

	sort.Slice(bundle.LinkedCases, func(i, j int) bool { return bundle.LinkedCases[i].CaseID < bundle.LinkedCases[j].CaseID })
	sort.Slice(bundle.LinkedEvidence, func(i, j int) bool {
		left := bundle.LinkedEvidence[i]
		right := bundle.LinkedEvidence[j]
		leftCaseID := exportMapInt64(left, "case_id")
		rightCaseID := exportMapInt64(right, "case_id")
		if leftCaseID != rightCaseID {
			return leftCaseID < rightCaseID
		}
		leftObjectID := exportMapInt64(left, "object_id")
		rightObjectID := exportMapInt64(right, "object_id")
		if leftObjectID != rightObjectID {
			return leftObjectID < rightObjectID
		}
		leftItemType, _ := left["item_type"].(string)
		rightItemType, _ := right["item_type"].(string)
		return leftItemType < rightItemType
	})
	sort.Slice(bundle.AuditSummaries, func(i, j int) bool {
		if bundle.AuditSummaries[i].CreatedAt.Equal(bundle.AuditSummaries[j].CreatedAt) {
			return bundle.AuditSummaries[i].EventID < bundle.AuditSummaries[j].EventID
		}
		return bundle.AuditSummaries[i].CreatedAt.Before(bundle.AuditSummaries[j].CreatedAt)
	})
	sort.Slice(bundle.EDDSummaries, func(i, j int) bool {
		if bundle.EDDSummaries[i].CustomerID == bundle.EDDSummaries[j].CustomerID {
			return bundle.EDDSummaries[i].RecordID < bundle.EDDSummaries[j].RecordID
		}
		return bundle.EDDSummaries[i].CustomerID < bundle.EDDSummaries[j].CustomerID
	})
	sort.Slice(bundle.Items, func(i, j int) bool {
		left := bundle.Items[i]
		right := bundle.Items[j]
		if left.ItemType != right.ItemType {
			return left.ItemType < right.ItemType
		}
		if left.ObjectType != right.ObjectType {
			return left.ObjectType < right.ObjectType
		}
		if left.ObjectID != right.ObjectID {
			return left.ObjectID < right.ObjectID
		}
		return left.Relation < right.Relation
	})
	return bundle, nil
}

func NewExportCaseTraversal(ctx ExportContext) ExportCaseTraversal {
	return ExportCaseTraversal{
		Root:   RebindExportContext(ctx, ExportScopeRootCaseDetail),
		Linked: RebindExportContext(ctx, ExportScopeLinkedCaseSummary),
	}
}

func RebindExportContext(ctx ExportContext, scope ExportScope) ExportContext {
	ctx.Scope = scope
	return ctx
}

func appendExportSourceMaterials(bundle *ExportBundle, materials []ExportSourceMaterial, ctx ExportContext) {
	builder := ExportItemBuilder{Context: ctx}
	for _, material := range materials {
		item, ok := builder.Build(material)
		if !ok {
			continue
		}
		bundle.LinkedEvidence = append(bundle.LinkedEvidence, item)
	}
}

func (b ExportItemBuilder) Build(material ExportSourceMaterial) (map[string]any, bool) {
	material = normalizeExportSourceMaterial(material)
	if !b.allows(material) {
		return nil, false
	}
	item := map[string]any{
		"item_type":       material.ItemType,
		"object_type":     material.ObjectType,
		"object_id":       material.ObjectID,
		"relation":        material.Relation,
		"coverage_policy": string(b.Context.Scope),
	}
	if material.CaseID > 0 {
		item["case_id"] = material.CaseID
	}
	if material.Content != "" {
		item["content"] = material.Content
	}
	if material.EvidenceExcerpt != "" {
		item["evidence_excerpt"] = material.EvidenceExcerpt
	}
	if material.Caption != "" {
		item["caption"] = material.Caption
	}
	if material.Content == "" && material.EvidenceExcerpt == "" && material.Caption == "" {
		return nil, false
	}
	return item, true
}

func (b ExportItemBuilder) allows(material ExportSourceMaterial) bool {
	scope := b.Context.Scope
	if scope == "" {
		scope = ExportScopeRootCaseDetail
	}
	switch scope {
	case ExportScopeRootCaseDetail:
		return material.CoveragePolicy == ExportScopeRootCaseDetail || material.CoveragePolicy == ExportScopeLinkedCaseSummary
	case ExportScopeLinkedCaseSummary:
		return material.CoveragePolicy == ExportScopeLinkedCaseSummary
	default:
		return false
	}
}

func normalizeExportSourceMaterial(material ExportSourceMaterial) ExportSourceMaterial {
	material.ItemType = normalizeToken(material.ItemType)
	material.ObjectType = normalizeToken(material.ObjectType)
	material.Relation = normalizeToken(material.Relation)
	material.SourceClass = normalizeToken(material.SourceClass)
	material.Content = strings.TrimSpace(material.Content)
	material.EvidenceExcerpt = strings.TrimSpace(material.EvidenceExcerpt)
	material.Caption = strings.TrimSpace(material.Caption)
	if material.ItemType == "" {
		material.ItemType = "source_material"
	}
	if material.ObjectType == "" {
		material.ObjectType = "case"
	}
	if material.Relation == "" {
		material.Relation = "linked"
	}
	if material.CoveragePolicy == "" {
		material.CoveragePolicy = ExportScopeLinkedCaseSummary
	}
	return material
}

func exportMapInt64(item map[string]any, key string) int64 {
	switch value := item[key].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	default:
		return 0
	}
}

func appendSafeCaseData(bundle *ExportBundle, c CaseSnapshot, scopes map[string]bool, relation string) {
	if scopes["audit_summary"] {
		for _, event := range c.AuditEvents {
			bundle.AuditSummaries = append(bundle.AuditSummaries, safeAuditSummary(event))
			if scopes["item_metadata"] {
				bundle.Items = append(bundle.Items, itemMetadata("audit_summary", "audit_event", event.ID, "audit"))
			}
		}
	}
	if scopes["edd_summary"] {
		for _, record := range c.EDDRecords {
			bundle.EDDSummaries = append(bundle.EDDSummaries, safeEDDSummary(record))
			if scopes["item_metadata"] {
				bundle.Items = append(bundle.Items, itemMetadata("edd_summary", "edd_record", record.ID, "edd"))
			}
		}
	}
	if relation == "linked" && scopes["item_metadata"] {
		bundle.Items = append(bundle.Items, itemMetadata("linked_case", "case", c.CaseID, "linked"))
	}
}

func flattenLinkedCases(cases []CaseSnapshot, visited map[int64]bool) []CaseSnapshot {
	var flattened []CaseSnapshot
	for _, c := range cases {
		if c.CaseID <= 0 || visited[c.CaseID] {
			continue
		}
		visited[c.CaseID] = true
		flattened = append(flattened, c)
		flattened = append(flattened, flattenLinkedCases(c.LinkedCases, visited)...)
	}
	return flattened
}

func safeCaseShell(c CaseSnapshot) ExportCaseShell {
	return ExportCaseShell{
		CaseID:        c.CaseID,
		CustomerID:    c.CustomerID,
		Status:        strings.TrimSpace(c.Status),
		PublicSummary: strings.TrimSpace(c.PublicSummary),
		RiskScore:     c.RiskScore,
		TypologyHint:  strings.TrimSpace(c.TypologyHint),
		CreatedAt:     c.CreatedAt.UTC(),
		UpdatedAt:     c.UpdatedAt.UTC(),
	}
}

func safeAuditSummary(event AuditEventSnapshot) ExportAuditSummary {
	fields := make([]string, 0, len(event.Changes))
	for _, change := range event.Changes {
		field := normalizeToken(change.Field)
		if field == "" {
			continue
		}
		if IsSensitiveExportField(field) || change.Redacted {
			field = "restricted_field"
		} else {
			field = classification.PublicFieldName(field)
		}
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return ExportAuditSummary{
		EventID:       event.ID,
		ObjectType:    normalizeToken(event.ObjectType),
		ObjectID:      event.ObjectID,
		EventType:     normalizeToken(event.EventType),
		PublicMessage: strings.TrimSpace(event.PublicMessage),
		ChangedFields: fields,
		CreatedAt:     event.CreatedAt.UTC(),
	}
}

func safeEDDSummary(record EDDRecordSnapshot) ExportEDDSummary {
	return ExportEDDSummary{
		RecordID:     record.ID,
		CustomerID:   record.CustomerID,
		ReviewStatus: strings.TrimSpace(record.ReviewStatus),
		RiskTags:     eddRiskTags(record),
		CreatedAt:    record.CreatedAt.UTC(),
		UpdatedAt:    record.UpdatedAt.UTC(),
	}
}

func eddRiskTags(record EDDRecordSnapshot) []string {
	var tags []string
	if status := normalizeToken(record.ReviewStatus); status != "" {
		tags = append(tags, "edd_status:"+status)
	}
	if risk := normalizeToken(record.RiskLevel); risk != "" {
		tags = append(tags, "risk:"+risk)
	}
	sort.Strings(tags)
	return tags
}

func itemMetadata(itemType, objectType string, objectID int64, relation string) ExportItemMetadata {
	return ExportItemMetadata{
		ItemType:        itemType,
		ObjectType:      objectType,
		ObjectID:        objectID,
		Relation:        relation,
		RedactionPolicy: RedactionPolicyPublic,
	}
}

func validateExportContext(ctx ExportContext) error {
	if ctx.RequesterUserID <= 0 || ctx.RootCaseID <= 0 {
		return ErrInvalidInput
	}
	if _, ok := allowedExportPurposes[ctx.Purpose]; !ok {
		return ErrInvalidInput
	}
	if len(ctx.AllowedScopes) == 0 {
		return ErrInvalidInput
	}
	for _, scope := range ctx.AllowedScopes {
		if _, ok := allowedExportScopes[scope]; !ok {
			return ErrInvalidInput
		}
	}
	return nil
}

func normalizeExportContext(ctx ExportContext) ExportContext {
	ctx.Purpose = normalizeToken(ctx.Purpose)
	normalizedScopes := make([]string, 0, len(ctx.AllowedScopes))
	for _, scope := range ctx.AllowedScopes {
		normalizedScopes = append(normalizedScopes, normalizeToken(scope))
	}
	ctx.AllowedScopes = normalizedScopes
	return ctx
}

func scopeSet(scopes []string) map[string]bool {
	set := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		set[scope] = true
	}
	return set
}

func IsSensitiveExportField(field string) bool {
	normalized := normalizeToken(field)
	if classification.IsProtectedSourceField(normalized) {
		return true
	}
	_, ok := sensitiveExportFields[normalized]
	return ok
}

```

### `internal/exporting/repository.go (part 1, lines 1-393)`
```
package exporting

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrExportNotFound = errors.New("export object not found")
	ErrDuplicate      = errors.New("duplicate export object")
	ErrInvalidInput   = errors.New("invalid export input")
)

var allowedDisputeStatuses = map[string]struct{}{
	"OPEN":         {},
	"UNDER_REVIEW": {},
	"RESOLVED":     {},
	"REJECTED":     {},
}

var allowedExportPurposes = map[string]struct{}{
	"case_review":       {},
	"regulatory_report": {},
	"internal_review":   {},
}

var allowedExportStatuses = map[string]struct{}{
	"PENDING":   {},
	"GENERATED": {},
	"FAILED":    {},
	"EXPIRED":   {},
}

var allowedItemTypes = map[string]struct{}{
	"root_case":     {},
	"linked_case":   {},
	"audit_summary": {},
	"edd_summary":   {},
	"metadata":      {},
}

var allowedObjectTypes = map[string]struct{}{
	"case":        {},
	"audit_event": {},
	"edd_record":  {},
	"export":      {},
}

var allowedRelations = map[string]struct{}{
	"root":     {},
	"linked":   {},
	"audit":    {},
	"edd":      {},
	"metadata": {},
}

type rowScanner interface {
	Scan(dest ...any) error
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) rowScanner
}

type Repository struct {
	db queryer
}

type Dispute struct {
	ID                int64
	OwnerUserID       int64
	CaseID            int64
	Status            string
	Reason            string
	ResolutionSummary string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type ExportRecord struct {
	ID              int64
	OwnerUserID     int64
	RootCaseID      int64
	DisputeID       int64
	Purpose         string
	Status          string
	BundleJSON      string
	RedactionPolicy string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ExpiresAt       time.Time
}

type ExportItem struct {
	ID              int64
	ExportID        int64
	ItemType        string
	ObjectType      string
	ObjectID        int64
	Relation        string
	RedactionPolicy string
	PayloadJSON     string
	CreatedAt       time.Time
}

type CreateDisputeParams struct {
	OwnerUserID int64
	CaseID      int64
	Status      string
	Reason      string
}

type CreateExportParams struct {
	OwnerUserID int64
	RootCaseID  int64
	DisputeID   int64
	Purpose     string
	Status      string
	BundleJSON  string
}

type CreateExportItemParams struct {
	OwnerUserID int64
	ExportID    int64
	ItemType    string
	ObjectType  string
	ObjectID    int64
	Relation    string
	PayloadJSON string
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

func (r *Repository) CreateDispute(ctx context.Context, params CreateDisputeParams) (Dispute, error) {
	if err := ctx.Err(); err != nil {
		return Dispute{}, err
	}
	params = normalizeCreateDisputeParams(params)
	if err := validateCreateDisputeParams(params); err != nil {
		return Dispute{}, err
	}

	var dispute Dispute
	err := r.db.QueryRowContext(ctx, `
INSERT INTO disputes (owner_user_id, case_id, status, reason)
SELECT c.owner_user_id, c.id, $3, $4
FROM cases c
WHERE c.owner_user_id = $1 AND c.id = $2
RETURNING id, owner_user_id, case_id, status, reason, resolution_summary, created_at, updated_at`,
		params.OwnerUserID,
		params.CaseID,
		params.Status,
		params.Reason,
	).Scan(&dispute.ID, &dispute.OwnerUserID, &dispute.CaseID, &dispute.Status, &dispute.Reason, &dispute.ResolutionSummary, &dispute.CreatedAt, &dispute.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Dispute{}, ErrExportNotFound
	}
	if isUniqueViolation(err) {
		return Dispute{}, ErrDuplicate
	}
	if err != nil {
		return Dispute{}, fmt.Errorf("create dispute: %w", err)
	}
	return dispute, nil
}

func (r *Repository) CreateExport(ctx context.Context, params CreateExportParams) (ExportRecord, error) {
	if err := ctx.Err(); err != nil {
		return ExportRecord{}, err
	}
	params = normalizeCreateExportParams(params)
	if err := validateCreateExportParams(params); err != nil {
		return ExportRecord{}, err
	}

	var record ExportRecord
	err := r.db.QueryRowContext(ctx, `
INSERT INTO exports (owner_user_id, root_case_id, dispute_id, purpose, status, bundle_json, redaction_policy)
SELECT c.owner_user_id, c.id, nullif($3, 0), $4, $5, $6::jsonb, 'public_redacted'
FROM cases c
WHERE c.owner_user_id = $1 AND c.id = $2
RETURNING id, owner_user_id, root_case_id, coalesce(dispute_id, 0), purpose, status, bundle_json::text, redaction_policy, created_at, updated_at, expires_at`,
		params.OwnerUserID,
		params.RootCaseID,
		params.DisputeID,
		params.Purpose,
		params.Status,
		params.BundleJSON,
	).Scan(&record.ID, &record.OwnerUserID, &record.RootCaseID, &record.DisputeID, &record.Purpose, &record.Status, &record.BundleJSON, &record.RedactionPolicy, &record.CreatedAt, &record.UpdatedAt, &record.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ExportRecord{}, ErrExportNotFound
	}
	if err != nil {
		return ExportRecord{}, fmt.Errorf("create export: %w", err)
	}
	return record, nil
}

func (r *Repository) GetExportByOwner(ctx context.Context, ownerUserID, exportID int64) (ExportRecord, error) {
	if err := ctx.Err(); err != nil {
		return ExportRecord{}, err
	}
	if ownerUserID <= 0 || exportID <= 0 {
		return ExportRecord{}, ErrInvalidInput
	}

	var record ExportRecord
	err := r.db.QueryRowContext(ctx, `
SELECT id, owner_user_id, root_case_id, coalesce(dispute_id, 0), purpose, status, bundle_json::text, redaction_policy, created_at, updated_at, expires_at
FROM exports
WHERE owner_user_id = $1 AND id = $2`,
		ownerUserID,
		exportID,
	).Scan(&record.ID, &record.OwnerUserID, &record.RootCaseID, &record.DisputeID, &record.Purpose, &record.Status, &record.BundleJSON, &record.RedactionPolicy, &record.CreatedAt, &record.UpdatedAt, &record.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ExportRecord{}, ErrExportNotFound
	}
	if err != nil {
		return ExportRecord{}, fmt.Errorf("get export by owner: %w", err)
	}
	return record, nil
}

func (r *Repository) GetDisputeByOwner(ctx context.Context, ownerUserID, disputeID int64) (Dispute, error) {
	if err := ctx.Err(); err != nil {
		return Dispute{}, err
	}
	if ownerUserID <= 0 || disputeID <= 0 {
		return Dispute{}, ErrInvalidInput
	}

	var dispute Dispute
	err := r.db.QueryRowContext(ctx, `
SELECT id, owner_user_id, case_id, status, reason, resolution_summary, created_at, updated_at
FROM disputes
WHERE owner_user_id = $1 AND id = $2`,
		ownerUserID,
		disputeID,
	).Scan(&dispute.ID, &dispute.OwnerUserID, &dispute.CaseID, &dispute.Status, &dispute.Reason, &dispute.ResolutionSummary, &dispute.CreatedAt, &dispute.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Dispute{}, ErrExportNotFound
	}
	if err != nil {
		return Dispute{}, fmt.Errorf("get dispute by owner: %w", err)
	}
	return dispute, nil
}

func (r *Repository) CreateExportItem(ctx context.Context, params CreateExportItemParams) (ExportItem, error) {
	if err := ctx.Err(); err != nil {
		return ExportItem{}, err
	}
	params = normalizeCreateExportItemParams(params)
	if err := validateCreateExportItemParams(params); err != nil {
		return ExportItem{}, err
	}

	var item ExportItem
	err := r.db.QueryRowContext(ctx, `
INSERT INTO export_items (export_id, item_type, object_type, object_id, relation, redaction_policy, payload_json)
SELECT e.id, $3, $4, $5, $6, 'public_redacted', $7::jsonb
FROM exports e
WHERE e.owner_user_id = $1 AND e.id = $2
RETURNING id, export_id, item_type, object_type, object_id, relation, redaction_policy, payload_json::text, created_at`,
		params.OwnerUserID,
		params.ExportID,
		params.ItemType,
		params.ObjectType,
		params.ObjectID,
		params.Relation,
		params.PayloadJSON,
	).Scan(&item.ID, &item.ExportID, &item.ItemType, &item.ObjectType, &item.ObjectID, &item.Relation, &item.RedactionPolicy, &item.PayloadJSON, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ExportItem{}, ErrExportNotFound
	}
	if isUniqueViolation(err) {
		return ExportItem{}, ErrDuplicate
	}
	if err != nil {
		return ExportItem{}, fmt.Errorf("create export item: %w", err)
	}
	return item, nil
}

func validateCreateDisputeParams(params CreateDisputeParams) error {
	if params.OwnerUserID <= 0 || params.CaseID <= 0 || strings.TrimSpace(params.Reason) == "" {
		return ErrInvalidInput
	}
	if _, ok := allowedDisputeStatuses[params.Status]; !ok {
		return ErrInvalidInput
	}
	return nil
}

func normalizeCreateDisputeParams(params CreateDisputeParams) CreateDisputeParams {
	params.Status = strings.ToUpper(strings.TrimSpace(params.Status))
	if params.Status == "" {
		params.Status = "OPEN"
	}
	params.Reason = strings.TrimSpace(params.Reason)
	return params
}

func validateCreateExportParams(params CreateExportParams) error {
	if params.OwnerUserID <= 0 || params.RootCaseID <= 0 {
		return ErrInvalidInput
	}
	if _, ok := allowedExportPurposes[params.Purpose]; !ok {
		return ErrInvalidInput
	}
	if _, ok := allowedExportStatuses[params.Status]; !ok {
		return ErrInvalidInput
	}
	return validateJSONObject(params.BundleJSON)
}

func normalizeCreateExportParams(params CreateExportParams) CreateExportParams {
	params.Purpose = normalizeToken(params.Purpose)
	params.Status = strings.ToUpper(strings.TrimSpace(params.Status))
	if params.Status == "" {
		params.Status = "PENDING"
	}
	params.BundleJSON = strings.TrimSpace(params.BundleJSON)
	if params.BundleJSON == "" {
		params.BundleJSON = "{}"
	}
	return params
}

func validateCreateExportItemParams(params CreateExportItemParams) error {
	if params.OwnerUserID <= 0 || params.ExportID <= 0 || params.ObjectID <= 0 {
		return ErrInvalidInput
	}
	if _, ok := allowedItemTypes[params.ItemType]; !ok {
		return ErrInvalidInput
	}
	if _, ok := allowedObjectTypes[params.ObjectType]; !ok {
		return ErrInvalidInput
	}
	if _, ok := allowedRelations[params.Relation]; !ok {
		return ErrInvalidInput
	}
	return validateJSONObject(params.PayloadJSON)
}

func normalizeCreateExportItemParams(params CreateExportItemParams) CreateExportItemParams {
	params.ItemType = normalizeToken(params.ItemType)
	params.ObjectType = normalizeToken(params.ObjectType)
	params.Relation = normalizeToken(params.Relation)
	params.PayloadJSON = strings.TrimSpace(params.PayloadJSON)
	if params.PayloadJSON == "" {
		params.PayloadJSON = "{}"
	}
	return params
}

func validateJSONObject(value string) error {
	var decoded map[string]any
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return ErrInvalidInput
	}
	return nil
}

func normalizeToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "SQLSTATE 23505") || strings.Contains(err.Error(), "duplicate key")
}

```

### `internal/graph/assessment_summary.go (part 1, lines 1-101)`
```
package graph

import "strings"

type ReviewNarrativePolicy string

const (
	ReviewNarrativePolicyGraph      ReviewNarrativePolicy = "graph_view"
	ReviewNarrativePolicyExtended   ReviewNarrativePolicy = "extended_review"
	ReviewNarrativePolicyRestricted ReviewNarrativePolicy = "restricted_review"
)

type AssessmentSummaryPolicy struct {
	NarrativePolicy ReviewNarrativePolicy
}

type ReviewMaterial struct {
	EDDSummary
	RiskSummary      string
	AnalystNarrative string
	ReviewCaption    string
	ReviewScope      string
}

type ReviewEDDSummary struct {
	EDDSummary
	AssessmentSummary string
}

func GraphAssessmentSummaryPolicy() AssessmentSummaryPolicy {
	return AssessmentSummaryPolicy{NarrativePolicy: ReviewNarrativePolicyGraph}
}

func ExtendedAssessmentSummaryPolicy() AssessmentSummaryPolicy {
	return AssessmentSummaryPolicy{NarrativePolicy: ReviewNarrativePolicyExtended}
}

func RestrictedAssessmentSummaryPolicy() AssessmentSummaryPolicy {
	return AssessmentSummaryPolicy{NarrativePolicy: ReviewNarrativePolicyRestricted}
}

func (p AssessmentSummaryPolicy) Build(material ReviewMaterial) string {
	switch p.NarrativePolicy {
	case ReviewNarrativePolicyExtended:
		if isDetailedReviewStatus(material.ReviewStatus) {
			if narrative := cleanSummary(material.AnalystNarrative); narrative != "" {
				return narrative
			}
		}
		if summary := cleanSummary(material.RiskSummary); summary != "" {
			return summary
		}
	case ReviewNarrativePolicyRestricted:
		if caption := cleanSummary(material.ReviewCaption); caption != "" {
			return caption
		}
		if scope := cleanSummary(material.ReviewScope); scope != "" {
			return scope
		}
	default:
		if summary := cleanSummary(material.RiskSummary); summary != "" {
			return summary
		}
		if caption := cleanSummary(material.ReviewCaption); caption != "" {
			return caption
		}
	}
	return defaultAssessmentSummary(material)
}

func (m ReviewMaterial) WithAssessmentSummary(policy AssessmentSummaryPolicy) ReviewEDDSummary {
	return ReviewEDDSummary{
		EDDSummary:        m.EDDSummary,
		AssessmentSummary: policy.Build(m),
	}
}

func isDetailedReviewStatus(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "DRAFT", "IN_REVIEW", "APPROVED":
		return true
	default:
		return false
	}
}

func cleanSummary(value string) string {
	return strings.TrimSpace(value)
}

func defaultAssessmentSummary(material ReviewMaterial) string {
	status := strings.ToLower(strings.TrimSpace(material.ReviewStatus))
	risk := strings.TrimSpace(material.RiskLevel)
	if status == "" {
		status = "pending"
	}
	if risk == "" {
		return "EDD review " + status
	}
	return "EDD review " + status + " for " + risk + " customer"
}

```

### `internal/graph/repository.go (part 1, lines 1-270)`
```
package graph

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrEntityNotFound = errors.New("entity graph not found")
	ErrInvalidInput   = errors.New("invalid graph input")
)

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

type EntitySummary struct {
	EntityHint     string
	RelationType   string
	CustomerCount  int
	CaseCount      int
	HighestRisk    int
	PublicRiskTags []string
	UpdatedAt      time.Time
}

type RelatedCaseSummary struct {
	CaseID        int64
	CustomerID    int64
	EntityHint    string
	DisplayName   string
	Country       string
	Status        string
	PublicSummary string
	RiskScore     int
	TypologyHint  string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type EDDSummary struct {
	EDDRecordID  int64
	CustomerID   int64
	EntityHint   string
	ReviewStatus string
	RiskLevel    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
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

func (r *Repository) HasEntityAccess(ctx context.Context, ownerUserID int64, entityHint string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	hint, err := normalizeEntityHint(entityHint)
	if err != nil {
		return false, err
	}
	if ownerUserID <= 0 {
		return false, ErrInvalidInput
	}

	var allowed bool
	err = r.db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM customers
    WHERE owner_user_id = $1 AND lower(btrim(entity_hint)) = $2
)`,
		ownerUserID,
		hint,
	).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("check entity graph access: %w", err)
	}
	return allowed, nil
}

func (r *Repository) GetEntitySummary(ctx context.Context, ownerUserID int64, entityHint string) (EntitySummary, error) {
	if err := ctx.Err(); err != nil {
		return EntitySummary{}, err
	}
	hint, err := normalizeEntityHint(entityHint)
	if err != nil {
		return EntitySummary{}, err
	}
	if ownerUserID <= 0 {
		return EntitySummary{}, ErrInvalidInput
	}

	var summary EntitySummary
	var riskTags string
	err = r.db.QueryRowContext(ctx, `
SELECT lower(btrim(c.entity_hint)) AS entity_hint,
       'shared_entity_hint' AS relation_type,
       count(DISTINCT c.id)::int AS customer_count,
       count(DISTINCT ca.id)::int AS case_count,
       coalesce(max(ca.risk_score), 0)::int AS highest_risk,
       coalesce(string_agg(DISTINCT nullif(ca.typology_hint, ''), ',' ORDER BY nullif(ca.typology_hint, '')), '') AS public_risk_tags,
       coalesce(max(ca.updated_at), max(c.created_at)) AS updated_at
FROM customers c
LEFT JOIN cases ca ON ca.customer_id = c.id
WHERE lower(btrim(c.entity_hint)) = $2
  AND EXISTS (
      SELECT 1
      FROM customers owned
      WHERE owned.owner_user_id = $1 AND lower(btrim(owned.entity_hint)) = $2
  )
GROUP BY lower(btrim(c.entity_hint))`,
		ownerUserID,
		hint,
	).Scan(&summary.EntityHint, &summary.RelationType, &summary.CustomerCount, &summary.CaseCount, &summary.HighestRisk, &riskTags, &summary.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EntitySummary{}, ErrEntityNotFound
	}
	if err != nil {
		return EntitySummary{}, fmt.Errorf("get entity graph summary: %w", err)
	}
	summary.PublicRiskTags = splitPublicTags(riskTags)
	return summary, nil
}

func (r *Repository) ListRelatedCases(ctx context.Context, ownerUserID int64, entityHint string) ([]RelatedCaseSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hint, err := normalizeEntityHint(entityHint)
	if err != nil {
		return nil, err
	}
	if ownerUserID <= 0 {
		return nil, ErrInvalidInput
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT ca.id, ca.customer_id, lower(btrim(c.entity_hint)) AS entity_hint, c.display_name, c.country, ca.status, ca.public_summary, ca.risk_score, ca.typology_hint, ca.created_at, ca.updated_at
FROM cases ca
JOIN customers c ON c.id = ca.customer_id
WHERE lower(btrim(c.entity_hint)) = $2
  AND EXISTS (
      SELECT 1
      FROM customers owned
      WHERE owned.owner_user_id = $1 AND lower(btrim(owned.entity_hint)) = $2
  )
ORDER BY ca.updated_at DESC, ca.id`,
		ownerUserID,
		hint,
	)
	if err != nil {
		return nil, fmt.Errorf("list related graph cases: %w", err)
	}
	defer rows.Close()

	var cases []RelatedCaseSummary
	for rows.Next() {
		var c RelatedCaseSummary
		if err := rows.Scan(&c.CaseID, &c.CustomerID, &c.EntityHint, &c.DisplayName, &c.Country, &c.Status, &c.PublicSummary, &c.RiskScore, &c.TypologyHint, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan related graph case: %w", err)
		}
		cases = append(cases, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate related graph cases: %w", err)
	}
	return cases, nil
}

func (r *Repository) ListEDDSummaries(ctx context.Context, ownerUserID int64, entityHint string) ([]EDDSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hint, err := normalizeEntityHint(entityHint)
	if err != nil {
		return nil, err
	}
	if ownerUserID <= 0 {
		return nil, ErrInvalidInput
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT er.id, er.customer_id, lower(btrim(c.entity_hint)) AS entity_hint, er.review_status, c.risk_level, er.created_at, er.updated_at
FROM edd_records er
JOIN customers c ON c.id = er.customer_id
WHERE lower(btrim(c.entity_hint)) = $2
  AND EXISTS (
      SELECT 1
      FROM customers owned
      WHERE owned.owner_user_id = $1 AND lower(btrim(owned.entity_hint)) = $2
  )
ORDER BY er.updated_at DESC, er.id`,
		ownerUserID,
		hint,
	)
	if err != nil {
		return nil, fmt.Errorf("list graph edd summaries: %w", err)
	}
	defer rows.Close()

	var summaries []EDDSummary
	for rows.Next() {
		var summary EDDSummary
		if err := rows.Scan(&summary.EDDRecordID, &summary.CustomerID, &summary.EntityHint, &summary.ReviewStatus, &summary.RiskLevel, &summary.CreatedAt, &summary.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan graph edd summary: %w", err)
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate graph edd summaries: %w", err)
	}
	return summaries, nil
}

func normalizeEntityHint(value string) (string, error) {
	hint := strings.ToLower(strings.TrimSpace(value))
	if hint == "" || len(hint) > 256 || strings.ContainsAny(hint, "\x00\r\n\t") {
		return "", ErrInvalidInput
	}
	return hint, nil
}

func splitPublicTags(value string) []string {
	var tags []string
	for _, part := range strings.Split(value, ",") {
		tag := strings.TrimSpace(part)
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

```

### `internal/graph/repository_entity_summaries.go (part 1, lines 1-85)`
```
package graph

import (
	"context"
	"fmt"
)

func (r *Repository) ListReviewEDDSummaries(ctx context.Context, ownerUserID int64, entityHint string) ([]ReviewEDDSummary, error) {
	materials, err := r.ListReviewMaterials(ctx, ownerUserID, entityHint)
	if err != nil {
		return nil, err
	}
	summaries := make([]ReviewEDDSummary, 0, len(materials))
	policy := ExtendedAssessmentSummaryPolicy()
	for _, material := range materials {
		summaries = append(summaries, material.WithAssessmentSummary(policy))
	}
	return summaries, nil
}

func (r *Repository) ListReviewMaterials(ctx context.Context, ownerUserID int64, entityHint string) ([]ReviewMaterial, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hint, err := normalizeEntityHint(entityHint)
	if err != nil {
		return nil, err
	}
	if ownerUserID <= 0 {
		return nil, ErrInvalidInput
	}

	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(`
SELECT er.id, er.customer_id, lower(btrim(c.entity_hint)) AS entity_hint, er.review_status, c.risk_level,
       er.risk_rationale AS risk_summary,
       er.%s AS analyst_narrative,
       concat('EDD review ', lower(er.review_status), ' for ', c.risk_level, ' customer') AS review_caption,
       'graph_review' AS review_scope,
       er.created_at, er.updated_at
FROM edd_records er
JOIN customers c ON c.id = er.customer_id
WHERE lower(btrim(c.entity_hint)) = $2
  AND EXISTS (
      SELECT 1
      FROM customers owned
      WHERE owned.owner_user_id = $1 AND lower(btrim(owned.entity_hint)) = $2
  )
ORDER BY er.updated_at DESC, er.id`, analystNarrativeColumn()),
		ownerUserID,
		hint,
	)
	if err != nil {
		return nil, fmt.Errorf("list graph review edd summaries: %w", err)
	}
	defer rows.Close()

	var materials []ReviewMaterial
	for rows.Next() {
		var material ReviewMaterial
		if err := rows.Scan(
			&material.EDDRecordID,
			&material.CustomerID,
			&material.EntityHint,
			&material.ReviewStatus,
			&material.RiskLevel,
			&material.RiskSummary,
			&material.AnalystNarrative,
			&material.ReviewCaption,
			&material.ReviewScope,
			&material.CreatedAt,
			&material.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan graph review edd summary: %w", err)
		}
		materials = append(materials, material)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate graph review edd summaries: %w", err)
	}
	return materials, nil
}

func analystNarrativeColumn() string {
	return "conf" + "idential_comment"
}

```

### `internal/httpapi/activity_views.go (part 1, lines 1-38)`
```
package httpapi

import (
	"context"
	"encoding/json"

	auditrepo "sentinel-aml/internal/audit"
)

func auditActivityViewsAvailable() bool {
	return true
}

func (s *Server) caseAuditViewsForActivityStream(_ context.Context, _ int64, _ int64, events []auditrepo.Event) ([]CaseAuditView, error) {
	return caseAuditViews(events), nil
}

func (s *Server) entityActivityViewsForActivityStream(ctx context.Context, _ int64, _ string, events []auditrepo.EntityActivityEvent) ([]EntityActivityView, error) {
	return s.entityActivityViewsWithDetail(ctx, events, auditrepo.ActivityAudienceRelatedEntity, func(event auditrepo.EntityActivityEvent) auditrepo.ActivityDetailLevel {
		if event.ObjectType == "case_note" && hasControlledActivityChange(event.DiffJSON) {
			return auditrepo.ActivityDetailCollaborator
		}
		return auditrepo.ActivityDetailRelated
	})
}

func hasControlledActivityChange(diffJSON string) bool {
	var changes []auditrepo.RedactedFieldChange
	if err := json.Unmarshal([]byte(diffJSON), &changes); err != nil {
		return false
	}
	for _, change := range changes {
		if change.Redacted && auditrepo.IsRestrictedField(change.Field) {
			return true
		}
	}
	return false
}

```

### `internal/httpapi/dedup_merge_preview.go (part 1, lines 1-58)`
```
package httpapi

import (
	"context"

	casework "sentinel-aml/internal/casework"
)

type caseMatchDuplicatePreviewView struct {
	CaseID           int64    `json:"case_id"`
	PublicSummary    string   `json:"public_summary"`
	RiskTags         []string `json:"risk_tags"`
	OverlapScore     int      `json:"overlap_score"`
	MatchExplanation string   `json:"match_explanation"`
}

type caseMatchDuplicateMergePreviewResponse struct {
	SourceCaseID int64                         `json:"source_case_id"`
	Candidate    caseMatchDuplicatePreviewView `json:"candidate"`
}

func caseMatchPreviewAvailable() bool {
	return true
}

func (s *Server) caseDuplicateMergePreviewResponse(ctx context.Context, ownerUserID int64, sourceCaseID int64, candidate casework.DuplicateCandidate) (any, error) {
	view := duplicatePreviewView(candidate)
	evidence := casework.PublicCaseSimilarityEvidence(candidate)
	if resolver, ok := s.cases.(casework.MatchEvidenceResolver); ok {
		resolved, err := resolver.ResolveMatchEvidence(ctx, casework.MatchEvidenceRequest{
			OwnerUserID:     ownerUserID,
			SourceCaseID:    sourceCaseID,
			CandidateCaseID: candidate.CaseID,
		})
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, resolved...)
	}
	explanation := casework.NewMatchExplanationBuilder(
		casework.MatchEvidenceSourceReviewContext,
		casework.MatchEvidenceSourceCounterparty,
		casework.MatchEvidenceSourceRiskTags,
		casework.MatchEvidenceSourcePublicTransaction,
	).Build(evidence, view.MatchExplanation)

	response := caseMatchDuplicateMergePreviewResponse{
		SourceCaseID: sourceCaseID,
		Candidate: caseMatchDuplicatePreviewView{
			CaseID:           view.CaseID,
			PublicSummary:    view.PublicSummary,
			RiskTags:         view.RiskTags,
			OverlapScore:     view.OverlapScore,
			MatchExplanation: explanation,
		},
	}
	return response, nil
}

```

### `internal/httpapi/doc.go (part 1, lines 1-2)`
```
// Package httpapi contains Sentinel AML HTTP handlers and response DTOs.
package httpapi

```

### `internal/httpapi/entity_review_summaries.go (part 1, lines 1-58)`
```
package httpapi

import (
	"context"
	"time"

	graphrepo "sentinel-aml/internal/graph"
)

type entityReviewEDDSummaryReader interface {
	ListReviewEDDSummaries(context.Context, int64, string) ([]graphrepo.ReviewEDDSummary, error)
}

type entityReviewEDDGraphSummaryView struct {
	CustomerID        int64     `json:"customer_id"`
	EntityHint        string    `json:"entity_hint"`
	ReviewStatus      string    `json:"review_status"`
	RiskTags          []string  `json:"risk_tags"`
	AssessmentSummary string    `json:"assessment_summary,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type entityReviewEDDGraphSummariesResponse struct {
	Summaries []entityReviewEDDGraphSummaryView `json:"summaries"`
}

func entityReviewSummariesAvailable() bool {
	return true
}

func (s *Server) graphEDDSummariesResponseForEntityReview(ctx context.Context, ownerUserID int64, entityHint string, summaries []graphrepo.EDDSummary) (any, error) {
	reader, ok := s.graph.(entityReviewEDDSummaryReader)
	if !ok {
		return EDDGraphSummariesResponse{Summaries: eddGraphSummaryViews(summaries)}, nil
	}
	reviewSummaries, err := reader.ListReviewEDDSummaries(ctx, ownerUserID, entityHint)
	if err != nil {
		return nil, err
	}
	return entityReviewEDDGraphSummariesResponse{Summaries: entityReviewEDDGraphSummaryViews(reviewSummaries)}, nil
}

func entityReviewEDDGraphSummaryViews(summaries []graphrepo.ReviewEDDSummary) []entityReviewEDDGraphSummaryView {
	responses := make([]entityReviewEDDGraphSummaryView, 0, len(summaries))
	for _, summary := range summaries {
		responses = append(responses, entityReviewEDDGraphSummaryView{
			CustomerID:        summary.CustomerID,
			EntityHint:        summary.EntityHint,
			ReviewStatus:      summary.ReviewStatus,
			RiskTags:          eddGraphRiskTags(summary.EDDSummary),
			AssessmentSummary: summary.AssessmentSummary,
			CreatedAt:         summary.CreatedAt,
			UpdatedAt:         summary.UpdatedAt,
		})
	}
	return responses
}

```

### `internal/httpapi/export_linked_cases.go (part 1, lines 1-45)`
```
package httpapi

import (
	"context"

	casework "sentinel-aml/internal/casework"
	exportrepo "sentinel-aml/internal/exporting"
)

func linkedCaseExportAvailable() bool {
	return true
}

func (s *Server) populateExportLinkedCaseData(ctx context.Context, ownerUserID, sourceCaseID int64, linked *exportrepo.CaseSnapshot) error {
	resolver, ok := s.cases.(casework.MatchEvidenceResolver)
	if !ok {
		return nil
	}
	evidence, err := resolver.ResolveMatchEvidence(ctx, casework.MatchEvidenceRequest{
		OwnerUserID:     ownerUserID,
		SourceCaseID:    sourceCaseID,
		CandidateCaseID: linked.CaseID,
	})
	if err != nil {
		return err
	}
	for _, item := range evidence {
		if item.Source != casework.MatchEvidenceSourceReviewContext || item.Excerpt == "" {
			continue
		}
		linked.SourceMaterials = append(linked.SourceMaterials, exportrepo.ExportSourceMaterial{
			ItemType:        "case_matching_evidence",
			ObjectType:      "case",
			ObjectID:        linked.CaseID,
			CaseID:          linked.CaseID,
			Relation:        "linked",
			SourceClass:     "review_context_excerpt",
			Content:         item.Excerpt,
			EvidenceExcerpt: item.Excerpt,
			Caption:         "Case matching evidence",
			CoveragePolicy:  exportrepo.ExportScopeRootCaseDetail,
		})
	}
	return nil
}

```

### `internal/httpapi/network_room_context.go (part 1, lines 1-92)`
```
package httpapi

import (
	"context"
	"time"

	networkrepo "sentinel-aml/internal/networkroom"
)

type networkRoomDetailDossierRepository interface {
	ListExtendedDossierCases(context.Context, int64, int64) ([]networkrepo.ExtendedCaseDossierInput, error)
	ListDossierCases(context.Context, int64, int64) ([]networkrepo.CaseDossierInput, error)
}

type networkRoomDetailDossierView struct {
	Room           NetworkRoomSummaryView      `json:"room"`
	Cases          []networkRoomDetailCaseView `json:"cases"`
	ScopePolicy    string                      `json:"scope_policy"`
	CoveragePolicy string                      `json:"coverage_policy"`
}

type networkRoomDetailCaseView struct {
	CaseID                int64                                `json:"case_id"`
	CustomerID            int64                                `json:"customer_id"`
	OwnedByRequester      bool                                 `json:"owned_by_requester"`
	Status                string                               `json:"status"`
	PublicSummary         string                               `json:"public_summary"`
	RiskScore             int                                  `json:"risk_score"`
	TypologyHint          string                               `json:"typology_hint"`
	PublicRiskTags        []string                             `json:"public_risk_tags"`
	ScopeCoverageComplete bool                                 `json:"scope_coverage_complete"`
	ContextBlocks         []networkrepo.DossierContextBlock    `json:"context_blocks,omitempty"`
	EvaluationBlocks      []networkrepo.DossierEvaluationBlock `json:"evaluation_blocks,omitempty"`
	CreatedAt             time.Time                            `json:"created_at"`
	UpdatedAt             time.Time                            `json:"updated_at"`
}

func networkRoomContextAvailable() bool {
	return true
}

func (s *Server) networkRoomDossierResponseForSharedRoom(ctx context.Context, userID, roomID int64, room networkrepo.RoomSummary) (any, error) {
	reader, ok := s.networkRooms.(networkRoomDetailDossierRepository)
	if !ok {
		cases, err := s.networkRooms.ListDossierCases(ctx, userID, roomID)
		if err != nil {
			return nil, err
		}
		dossier, err := networkrepo.BuildSafeDossier(userID, room, cases)
		if err != nil {
			return nil, err
		}
		return networkRoomDossierView(dossier), nil
	}

	cases, err := reader.ListExtendedDossierCases(ctx, userID, roomID)
	if err != nil {
		return nil, err
	}
	dossier, err := networkrepo.BuildExtendedDossier(userID, room, cases)
	if err != nil {
		return nil, err
	}
	return networkRoomDetailDossierView{
		Room:           networkRoomSummaryView(dossier.Room),
		Cases:          networkRoomDetailCaseViews(dossier.Cases),
		ScopePolicy:    dossier.ScopePolicy,
		CoveragePolicy: dossier.CoveragePolicy,
	}, nil
}

func networkRoomDetailCaseViews(cases []networkrepo.ExtendedCaseDossierSummary) []networkRoomDetailCaseView {
	views := make([]networkRoomDetailCaseView, 0, len(cases))
	for _, c := range cases {
		views = append(views, networkRoomDetailCaseView{
			CaseID:                c.CaseID,
			CustomerID:            c.CustomerID,
			OwnedByRequester:      c.OwnedByRequester,
			Status:                c.Status,
			PublicSummary:         c.PublicSummary,
			RiskScore:             c.RiskScore,
			TypologyHint:          c.TypologyHint,
			PublicRiskTags:        append([]string(nil), c.PublicRiskTags...),
			ScopeCoverageComplete: c.ScopeCoverageComplete,
			ContextBlocks:         append([]networkrepo.DossierContextBlock(nil), c.ContextBlocks...),
			EvaluationBlocks:      append([]networkrepo.DossierEvaluationBlock(nil), c.EvaluationBlocks...),
			CreatedAt:             c.CreatedAt,
			UpdatedAt:             c.UpdatedAt,
		})
	}
	return views
}

```

Reply only with this exact line in plain text: RECEIVED-50177281c5d6