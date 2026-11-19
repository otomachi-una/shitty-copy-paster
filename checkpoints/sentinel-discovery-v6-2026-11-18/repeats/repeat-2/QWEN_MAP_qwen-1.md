(A) Entry Point Inventory
Entry Point
	
Handler / Function
	
Authorization / Object Gate
	
Call Chain (Key Functions)
	
Output / Sink


POST /api/auth/register
	
handleRegister
	
None (Public)
	
auth.Register -> auth.CreateUser -> auth.CreateSession
	
JSON: AuthResponse (includes RawToken)


POST /api/auth/login
	
handleLogin
	
None (Public)
	
auth.Login -> auth.FindUserByUsername -> auth.CheckPassword -> auth.CreateSession
	
JSON: AuthResponse (includes RawToken)


GET /api/auth/me
	
handleMe
	
requireAuth (Bearer Token)
	
auth.CurrentUser -> authz.WithPrincipal
	
JSON: MeResponse


POST /api/customers
	
handleCustomersRoot
	
requireAuth
	
cust.Create
	
JSON: CustomerResponse


GET /api/customers/{id}
	
handleGetCustomer
	
requireAuth + Owner Check (GetByOwner)
	
cust.GetByOwner
	
JSON: CustomerResponse


GET /api/customers/{id}/accounts
	
handleCustomerAccounts
	
requireAuth + Owner Check (ListByCustomerOwner)
	
acct.ListByCustomerOwner
	
JSON: AccountsResponse


POST /api/customers/{id}/accounts
	
handleCustomerAccounts
	
requireAuth + Owner Check (Create)
	
acct.Create
	
JSON: AccountResponse


GET /api/customers/{id}/transactions
	
handleCustomerTransactions
	
requireAuth + Owner Check (ListByCustomerOwner)
	
txn.ListByCustomerOwner
	
JSON: TransactionsResponse


GET/POST/PATCH /api/customers/{id}/edd
	
handleCustomerEDD
	
requireAuth + Owner Check (GetByOwnerCustomer)
	
edd.GetByOwnerCustomer, edd.Create, edd.UpdateByOwnerCustomer
	
JSON: EDDOwnerView (Includes ConfidentialComment, SourceOfFunds)


GET /api/accounts/{id}
	
handleAccountsSubtree
	
requireAuth + Owner Check (GetByOwner)
	
acct.GetByOwner
	
JSON: AccountResponse


POST /api/transactions
	
handleTransactionsRoot
	
requireAuth + Owner Check (Create)
	
txn.Create -> risk.ScoreTransaction -> alert.Create (if suspicious)
	
JSON: TransactionResponse


GET /api/transactions/{id}
	
handleTransactionsSubtree
	
requireAuth + Owner Check (GetByOwner)
	
txn.GetByOwner
	
JSON: TransactionResponse


GET /api/alerts/queue
	
handleAlertsQueue
	
requireAuth + Owner Filter (ListByOwner)
	
alert.ListByOwner
	
JSON: AlertsResponse


GET /api/alerts/{id}
	
handleGetAlert
	
requireAuth + Owner Check (GetByOwner)
	
alert.GetByOwner
	
JSON: AlertResponse


POST /api/alerts/{id}/claim
	
handleClaimAlert
	
requireAuth + Owner Check (Claim)
	
alert.Claim
	
JSON: AlertResponse


POST /api/alerts/{id}/triage
	
handleTriageAlert
	
requireAuth + Owner Check (Triage)
	
alert.Triage
	
JSON: AlertResponse


POST /api/alerts/{id}/case
	
handleCreateCaseFromAlert
	
requireAuth + Owner Check (CreateFromAlert)
	
casework.CreateFromAlert -> audit.Create -> networkroom.EnqueueCaseCandidate
	
JSON: CaseResponse


GET /api/cases/{id}
	
handleGetCase
	
requireAuth + Owner Check (GetByOwner)
	
casework.GetByOwner
	
JSON: CaseResponse


PATCH /api/cases/{id}/status
	
handleUpdateCaseStatus
	
requireAuth + Owner Check (UpdateStatus)
	
casework.UpdateStatus -> audit.Create
	
JSON: CaseResponse


GET /api/cases/{id}/notes
	
handleCaseNotes
	
requireAuth + Owner Check (ListNotesByOwner)
	
casework.ListNotesByOwner
	
JSON: CaseNotesResponse (Includes Body)


POST /api/cases/{id}/notes
	
handleCaseNotes
	
requireAuth + Owner Check (CreateNote)
	
casework.CreateNote -> audit.Create
	
JSON: CaseNoteResponse (Includes Body)


GET /api/cases/{id}/duplicates
	
handleCaseDuplicateCandidates
	
requireAuth + Owner Check (FindDuplicateCandidatesByOwner)
	
casework.FindDuplicateCandidatesByOwner
	
JSON: CaseDuplicateCandidatesResponse


GET /api/cases/{id}/duplicates/{dupId}/merge-preview
	
handleCaseDuplicateMergePreview
	
requireAuth + Owner Check
	
casework.FindDuplicateCandidatesByOwner -> casework.ResolveMatchEvidence
	
JSON: CaseDuplicateMergePreviewResponse


GET /api/cases/{id}/timeline
	
handleCaseTimeline
	
requireAuth + Owner Check (GetByOwner then ListCaseTimelineByOwner)
	
audit.ListCaseTimelineByOwner
	
JSON: CaseTimelineResponse


POST /api/cases/{id}/exports
	
handleCreateCaseExport
	
requireAuth + Owner Check (GetByOwner)
	
buildExportBundle -> exports.CreateExport -> exports.CreateExportItem
	
JSON: ExportResponse


GET /api/exports/{id}
	
handleExportsSubtree
	
requireAuth + Owner Check (GetExportByOwner)
	
exports.GetExportByOwner
	
JSON: ExportResponse


POST /api/disputes
	
handleDisputesRoot
	
requireAuth + Owner Check (CreateDispute)
	
exports.CreateDispute
	
JSON: DisputeResponse


POST /api/disputes/{id}/export
	
handleDisputesSubtree
	
requireAuth + Owner Check (GetDisputeByOwner)
	
exports.GetDisputeByOwner -> handleCreateCaseExport
	
JSON: ExportResponse


GET /api/entities/{hint}/activity
	
handleEntitiesSubtree
	
requireAuth + Entity Access Check (ListEntityActivityByRequester)
	
audit.ListEntityActivityByRequester -> entityActivityViewsForActivityStream
	
JSON: EntityActivityResponse


GET /api/graph/entities/{hint}
	
handleGraphEntity
	
requireAuth + Entity Access Check (HasEntityAccess)
	
graph.GetEntitySummary
	
JSON: GraphEntityView


GET /api/graph/entities/{hint}/related-cases
	
handleGraphRelatedCases
	
requireAuth + Entity Access Check (HasEntityAccess)
	
graph.ListRelatedCases
	
JSON: GraphRelatedCasesResponse


GET /api/graph/entities/{hint}/edd-summaries
	
handleGraphEDDSummaries
	
requireAuth + Entity Access Check (HasEntityAccess)
	
graph.ListEDDSummaries -> graphEDDSummariesResponseForEntityReview -> graph.ListReviewEDDSummaries
	
JSON: EntityReviewEDDGraphSummariesResponse


GET /api/network/rooms
	
handleNetworkRoomsRoot
	
requireAuth
	
networkroom.ListRoomsForUser
	
JSON: NetworkRoomsResponse


GET /api/network/rooms/{id}
	
handleNetworkRoomsSubtree
	
requireAuth + Participant Check (GetRoomForUser)
	
networkroom.GetRoomForUser, networkroom.ListParticipants
	
JSON: NetworkRoomDetailResponse


POST /api/network/rooms/{id}/join
	
handleNetworkRoomsSubtree
	
requireAuth
	
networkroom.JoinRoom
	
JSON: NetworkRoomParticipantView


GET /api/network/rooms/{id}/dossier
	
handleNetworkRoomsSubtree
	
requireAuth + Participant Check (GetRoomForUser)
	
networkroom.GetRoomForUser -> networkRoomDossierResponseForSharedRoom -> networkroom.BuildExtendedDossier or BuildSafeDossier
	
JSON: NetworkRoomDetailDossierView or NetworkRoomDossierView


Worker: ProcessDirtyBatch
	
run / processNetworkRooms
	
System Worker (No User Auth)
	
networkroom.ClaimDirtyCandidates -> processDirtyCandidate -> MaterializeArtifact
	
DB Updates, Logs
(B) Sensitive Field & Reader Inventory
Sensitive Field / Data
	
Source (Schema/Write)
	
Reader / Helper
	
Policy / Context
	
Audience / Sink


password_hash
	
users table
	
auth.FindUserByUsername
	
Internal Auth Only
	
Memory (Comparison)


token_hash
	
sessions table
	
auth.FindSessionByTokenHash
	
Internal Auth Only
	
Memory (Lookup)


raw_token
	
auth.GenerateSessionToken
	
authResultResponse
	
Session Creation
	
JSON Response (/api/auth/*)


confidential_comment
	
edd_records table
	
edd.GetByOwnerCustomer
	
Owner Check
	
JSON: EDDOwnerView (/api/customers/{id}/edd)


confidential_comment
	
edd_records table
	
graph.ListReviewMaterials
	
Entity Access Check (HasEntityAccess)
	
JSON: AssessmentSummary (/api/graph/entities/{hint}/edd-summaries)


source_of_funds
	
edd_records table
	
edd.GetByOwnerCustomer
	
Owner Check
	
JSON: EDDOwnerView


risk_rationale
	
edd_records table
	
edd.GetByOwnerCustomer
	
Owner Check
	
JSON: EDDOwnerView


body (Case Note)
	
case_notes table
	
casework.ListNotesByOwner
	
Owner Check
	
JSON: CaseNoteResponse


body (Case Note)
	
case_notes table
	
networkroom.materializeCandidateArtifactsWithLimit
	
Worker (System)
	
DB: network_room_artifacts -> JSON: DossierContextBlock


diff_json
	
audit_events table
	
audit.RedactedDiffJSON
	
Audit Creation
	
DB: audit_events (Redacted)


diff_json
	
audit_events table
	
exportrepo.safeAuditSummary
	
Export Bundle Build
	
JSON: ExportAuditSummary (Field names only)


diff_json
	
audit_events table
	
httpapi.caseAuditChangeResponses
	
Case Timeline
	
JSON: CaseAuditChangeResponse (Redacted values)


entity_hint
	
customers table
	
graph.HasEntityAccess
	
Owner Check
	
Boolean Access Gate


typology_hint
	
cases table
	
networkroom.EnqueueCaseCandidate
	
Case Creation
	
DB: network_room_dirty_candidates


public_summary
	
cases table
	
casework.FindDuplicateCandidatesByOwner
	
Owner Check
	
JSON: CaseDuplicatePreviewView


bundle_json
	
exports table
	
exports.GetExportByOwner
	
Owner Check
	
JSON: ExportResponse
Unresolved Edges / Uncertainties
internal/risk/scoring.go: The Score function uses deriveTypology which checks countryWeight and fingerprintKeywordWeight. The logic for fingerprintWeight includes a modulo operation on rune sums ((sum % 3) * 5). This is a deterministic but potentially weak entropy source for risk scoring if the fingerprint is short or predictable.
internal/networkroom/repository.go: JoinRoom requires the user to own a case in the room (EXISTS SELECT ... FROM cases ca WHERE ca.owner_user_id = u.id). However, AttachCase does not explicitly check if the ActorUserID owns the case being attached, only that the case exists. The owner check is implicit in the JOIN cases c ON c.id = $3 without a WHERE c.owner_user_id = $1 clause in the INSERT ... SELECT statement for AttachCase. Correction: Looking closely at AttachCase SQL: SELECT nr.id, c.id, $4, $1 FROM network_rooms nr JOIN cases c ON c.id = $3 WHERE nr.id = $2. It does not verify c.owner_user_id. This allows any participant in a room (or potentially anyone with the room ID if JoinRoom didn't strictly enforce ownership of that specific case, though JoinRoom checks for any case owned by the user in the room) to attach cases they don't own? No, JoinRoom checks if the user owns a case in the room. AttachCase is called by processDirtyCandidate in the worker, which uses summary.ActorUserID (the owner of one of the cases in the cluster). So the worker attaches cases on behalf of the first actor it finds. This is a system-level action, not a user API action.
internal/httpapi/server.go: handleCreateCaseExport calls buildExportBundle. Inside buildExportBundle, it fetches linked cases via FindDuplicateCandidatesByOwner. It then calls populateExportLinkedCaseData. This function resolves match evidence. If the evidence source is ReviewContext, it pulls from case_notes where visibility = 'private'. This private data is then included in the export bundle if the scope allows. The redaction policy for exports is public_redacted, but ExportSourceMaterial content is added directly. IsSensitiveExportField is used in safeAuditSummary but not explicitly on ExportSourceMaterial.Content in appendExportSourceMaterials.
RECEIVED-fc7cf6eea142
