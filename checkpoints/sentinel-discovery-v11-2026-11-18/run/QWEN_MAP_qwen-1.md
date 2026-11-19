(A) Entry Point Inventory
Entry Point
	
Handler / Chain
	
Auth / Object Gate
	
Call Chain & Implementations
	
Output / Sink


POST /api/auth/register
	
handleRegister
	
None (Public)
	
auth.Register -> store.CreateUser -> store.CreateSession
	
AuthResponse (RawToken, User)


POST /api/auth/login
	
handleLogin
	
None (Public)
	
auth.Login -> store.FindUserByUsername -> CheckPassword -> store.CreateSession
	
AuthResponse (RawToken, User)


GET /api/auth/me
	
requireAuth -> handleMe
	
Bearer Token (CurrentUser)
	
authz.PrincipalFromContext
	
MeResponse (User)


POST /api/customers
	
requireAuth -> handleCustomersRoot
	
Principal UserID
	
customers.Create (OwnerUserID)
	
CustomerResponse


GET /api/customers/{id}
	
requireAuth -> handleCustomersSubtree -> handleGetCustomer
	
Principal UserID
	
customers.GetByOwner (OwnerUserID, ID)
	
CustomerResponse


GET /api/customers/{id}/accounts
	
requireAuth -> handleCustomersSubtree -> handleCustomerAccounts
	
Principal UserID
	
accounts.ListByCustomerOwner (OwnerUserID, CustomerID)
	
AccountsResponse


POST /api/customers/{id}/accounts
	
requireAuth -> handleCustomersSubtree -> handleCustomerAccounts
	
Principal UserID
	
accounts.Create (OwnerUserID, CustomerID)
	
AccountResponse


GET /api/customers/{id}/transactions
	
requireAuth -> handleCustomersSubtree -> handleCustomerTransactions
	
Principal UserID
	
transactions.ListByCustomerOwner (OwnerUserID, CustomerID)
	
TransactionsResponse


GET /api/customers/{id}/edd
	
requireAuth -> handleCustomersSubtree -> handleCustomerEDD
	
Principal UserID
	
edd.GetByOwnerCustomer (OwnerUserID, CustomerID)
	
EDDOwnerView (Includes ConfidentialComment)


POST /api/customers/{id}/edd
	
requireAuth -> handleCustomersSubtree -> handleCustomerEDD
	
Principal UserID
	
edd.Create -> recordAudit (Fields: source_of_funds, risk_rationale, confidential_comment)
	
EDDOwnerView


PATCH /api/customers/{id}/edd
	
requireAuth -> handleCustomersSubtree -> handleCustomerEDD
	
Principal UserID
	
edd.GetByOwnerCustomer (Prev) -> edd.UpdateByOwnerCustomer -> recordAudit
	
EDDOwnerView


GET /api/accounts/{id}
	
requireAuth -> handleAccountsSubtree
	
Principal UserID
	
accounts.GetByOwner (OwnerUserID, AccountID)
	
AccountResponse


POST /api/transactions
	
requireAuth -> handleTransactionsRoot
	
Principal UserID
	
transactions.Create -> risk.ScoreTransaction -> alerts.Create (if Suspicious)
	
TransactionResponse (with RiskScore)


GET /api/transactions/{id}
	
requireAuth -> handleTransactionsSubtree
	
Principal UserID
	
transactions.GetByOwner (OwnerUserID, TransactionID)
	
TransactionResponse


GET /api/alerts/queue
	
requireAuth -> handleAlertsQueue
	
Principal UserID
	
alerts.ListByOwner (OwnerUserID)
	
AlertsResponse


GET /api/alerts/{id}
	
requireAuth -> handleAlertsSubtree -> handleGetAlert
	
Principal UserID
	
alerts.GetByOwner (OwnerUserID, AlertID)
	
AlertResponse


POST /api/alerts/{id}/claim
	
requireAuth -> handleAlertsSubtree -> handleClaimAlert
	
Principal UserID
	
alerts.Claim (OwnerUserID, AssignedUserID=OwnerUserID)
	
AlertResponse


POST /api/alerts/{id}/triage
	
requireAuth -> handleAlertsSubtree -> handleTriageAlert
	
Principal UserID
	
alerts.Triage (OwnerUserID, Status)
	
AlertResponse


POST /api/alerts/{id}/case
	
requireAuth -> handleAlertsSubtree -> handleCreateCaseFromAlert
	
Principal UserID
	
cases.CreateFromAlert -> recordAudit -> networkRooms.EnqueueCaseCandidate
	
CaseResponse


GET /api/cases/{id}
	
requireAuth -> handleCasesSubtree -> handleGetCase
	
Principal UserID
	
cases.GetByOwner (OwnerUserID, CaseID)
	
CaseResponse


GET /api/cases/{id}/notes
	
requireAuth -> handleCasesSubtree -> handleCaseNotes
	
Principal UserID
	
cases.ListNotesByOwner (OwnerUserID, CaseID)
	
CaseNotesResponse (Body exposed)


POST /api/cases/{id}/notes
	
requireAuth -> handleCasesSubtree -> handleCaseNotes
	
Principal UserID
	
cases.CreateNote -> recordAudit (Field: case_note.body)
	
CaseNoteResponse


PATCH /api/cases/{id}/status
	
requireAuth -> handleCasesSubtree -> handleUpdateCaseStatus
	
Principal UserID
	
cases.UpdateStatus -> recordAudit
	
CaseResponse


GET /api/cases/{id}/duplicates
	
requireAuth -> handleCasesSubtree -> handleCaseDuplicateCandidates
	
Principal UserID
	
cases.FindDuplicateCandidatesByOwner
	
CaseDuplicateCandidatesResponse


GET /api/cases/{id}/duplicates/{cid}/merge-preview
	
requireAuth -> handleCasesSubtree -> handleCaseDuplicateMergePreview
	
Principal UserID
	
cases.FindDuplicateCandidatesByOwner -> cases.ResolveMatchEvidence (Source: private notes)
	
CaseDuplicateMergePreviewResponse


GET /api/cases/{id}/timeline
	
requireAuth -> handleCasesSubtree -> handleCaseTimeline
	
Principal UserID
	
audit.ListCaseTimelineByOwner
	
CaseTimelineResponse


GET /api/entities/{hint}/activity
	
requireAuth -> handleEntitiesSubtree
	
Principal UserID + EntityHint Ownership Check
	
audit.ListEntityActivityByRequester -> entityActivityViewsForActivityStream
	
EntityActivityResponse


GET /api/graph/entities/{hint}
	
requireAuth -> handleGraphEntitiesSubtree -> handleGraphEntity
	
Principal UserID + graph.HasEntityAccess
	
graph.GetEntitySummary
	
GraphEntityView


GET /api/graph/entities/{hint}/related-cases
	
requireAuth -> handleGraphEntitiesSubtree -> handleGraphRelatedCases
	
Principal UserID + graph.HasEntityAccess
	
graph.ListRelatedCases
	
GraphRelatedCasesResponse


GET /api/graph/entities/{hint}/edd-summaries
	
requireAuth -> handleGraphEntitiesSubtree -> handleGraphEDDSummaries
	
Principal UserID + graph.HasEntityAccess
	
graph.ListEDDSummaries -> graphEDDSummariesResponseForEntityReview -> graph.ListReviewMaterials (SQL: selects confidential_comment)
	
entityReviewEDDGraphSummariesResponse


POST /api/disputes
	
requireAuth -> handleDisputesRoot
	
Principal UserID
	
exports.CreateDispute
	
DisputeResponse


POST /api/disputes/{id}/export
	
requireAuth -> handleDisputesSubtree
	
Principal UserID
	
exports.GetDisputeByOwner -> handleCreateCaseExport
	
ExportResponse


POST /api/cases/{id}/exports
	
requireAuth -> handleCasesSubtree -> handleCreateCaseExport
	
Principal UserID
	
buildExportBundle -> exports.CreateExport -> exports.CreateExportItem
	
ExportResponse


GET /api/exports/{id}
	
requireAuth -> handleExportsSubtree
	
Principal UserID
	
exports.GetExportByOwner -> decodeExportBundle
	
ExportResponse


GET /api/network/rooms
	
requireAuth -> handleNetworkRoomsRoot
	
Principal UserID
	
networkRooms.ListRoomsForUser
	
NetworkRoomsResponse


GET /api/network/rooms/{id}
	
requireAuth -> handleNetworkRoomsSubtree
	
Principal UserID
	
networkRooms.GetRoomForUser -> networkRooms.ListParticipants
	
NetworkRoomDetailResponse


POST /api/network/rooms/{id}/join
	
requireAuth -> handleNetworkRoomsSubtree
	
Principal UserID
	
networkRooms.JoinRoom (Checks ownership of attached cases)
	
NetworkRoomParticipantView


GET /api/network/rooms/{id}/dossier
	
requireAuth -> handleNetworkRoomsSubtree
	
Principal UserID
	
networkRooms.GetRoomForUser -> networkRoomDossierResponseForSharedRoom -> networkrepo.BuildExtendedDossier (via ListExtendedDossierCases)
	
networkRoomDetailDossierView


Worker: aml-worker
	
run -> processNetworkRooms
	
Environment Config
	
networkroom.ProcessDirtyBatch -> processDirtyCandidate -> materializeCandidateArtifactsWithLimit (SQL: selects confidential_comment and body)
	
DB Writes (network_room_artifacts)
(B) Sensitive Field Trace
Sensitive Field / Source
	
Reader / Policy Context
	
Audience / Decision
	
Sink / Serialization


users.password_hash
	
auth.FindUserByUsername
	
Internal Auth Only
	
bcrypt.CompareHashAndPassword (Memory)


sessions.token_hash
	
auth.FindSessionByTokenHash
	
Internal Auth Only
	
ConstantTimeTokenHashEqual (Memory)


edd_records.confidential_comment
	
httpapi.handleCustomerEDD (GET/PATCH)
	
Owner Analyst
	
EDDOwnerView.ConfidentialComment (JSON Response)


edd_records.confidential_comment
	
graph.ListReviewMaterials (via analystNarrativeColumn)
	
Entity Graph Viewer (via HasEntityAccess)
	
ReviewMaterial.AnalystNarrative -> AssessmentSummaryPolicy.Build -> entityReviewEDDGraphSummaryView.AssessmentSummary (JSON)


edd_records.source_of_funds
	
httpapi.handleCustomerEDD
	
Owner Analyst
	
EDDOwnerView.SourceOfFunds (JSON Response)


edd_records.risk_rationale
	
httpapi.handleCustomerEDD
	
Owner Analyst
	
EDDOwnerView.RiskRationale (JSON Response)


case_notes.body
	
httpapi.handleCaseNotes (GET)
	
Case Owner
	
CaseNoteResponse.Body (JSON Response)


case_notes.body
	
casework.ResolveMatchEvidence
	
Duplicate Candidate Reviewer
	
CaseSimilarityEvidence.Excerpt -> MatchExplanationBuilder.Build -> CaseDuplicateMergePreviewResponse.MatchExplanation (JSON)


case_notes.body
	
networkroom.materializeCandidateArtifactsWithLimit
	
Network Room Participant (via Worker)
	
CollaborationArtifact.Content -> network_room_artifacts.content (DB) -> DossierContextBlock.Content (JSON Dossier)


audit_events.diff_json
	
audit.RedactedDiffJSON
	
Audit System
	
Redacted via classification.IsProtectedSourceField -> audit.Event.DiffJSON (DB)


audit_events.diff_json
	
httpapi.caseAuditChangeResponses
	
Case Timeline Viewer
	
CaseAuditChangeResponse (JSON). Restricted fields replaced with "restricted_field".


audit_events.diff_json
	
exporting.safeAuditSummary
	
Export Bundle Consumer
	
ExportAuditSummary.ChangedFields. Restricted fields replaced with "restricted_field".


transactions.counterparty_fingerprint
	
risk.Score
	
Risk Engine
	
Memory (Scoring Logic)


customers.entity_hint
	
graph.HasEntityAccess / audit.ListEntityActivityByRequester
	
Entity Graph Viewer
	
Access Control Gate
Unresolved Edges
internal/projection/contracts.go: Defines Contract structs and AllowedJSONFields but no active enforcement logic was found in the provided HTTP handlers or repositories. It appears to be a dormant policy definition.
internal/exporting/export_linked_evidence.go: Contains linkedCaseExportAvailable() and appendExportLinkedCaseData, but the implementation is minimal and relies on CaseSnapshot population which occurs in httpapi.buildExportBundle. The exact filtering logic for "linked" evidence beyond the scopes map is localized to ExportItemBuilder.allows.
RECEIVED-dc0edce2298e
