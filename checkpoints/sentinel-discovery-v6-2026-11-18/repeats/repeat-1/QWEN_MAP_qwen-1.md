(A) Entry Points
Method/Path
	
Handler
	
Auth/Object Gate
	
Call Chain
	
Output/Sink


POST /api/auth/register
	
handleRegister
	
None (Public)
	
auth.Register -> auth.HashPassword -> auth.CreateUser -> auth.CreateSession
	
JSON: user, session.token (raw), session.expires_at


POST /api/auth/login
	
handleLogin
	
None (Public)
	
auth.Login -> auth.FindUserByUsername -> auth.CheckPassword -> auth.CreateSession
	
JSON: user, session.token (raw), session.expires_at


GET /api/auth/me
	
handleMe
	
requireAuth (Bearer)
	
auth.CurrentUser -> authz.PrincipalFromContext
	
JSON: user.id, username, role, status


POST /api/customers
	
handleCustomersRoot
	
requireAuth
	
cust.Create (Owner=User.ID)
	
JSON: Customer fields (incl. entity_hint)


GET /api/customers/{id}
	
handleGetCustomer
	
requireAuth + Owner Check (GetByOwner)
	
cust.GetByOwner
	
JSON: Customer fields


GET /api/customers/{id}/accounts
	
handleCustomerAccounts
	
requireAuth + Owner Check (ListByCustomerOwner)
	
acct.ListByCustomerOwner
	
JSON: Account fields


POST /api/customers/{id}/accounts
	
handleCustomerAccounts
	
requireAuth + Owner Check
	
acct.Create (Owner=User.ID, CustomerID=Path)
	
JSON: Account fields


GET /api/customers/{id}/transactions
	
handleCustomerTransactions
	
requireAuth + Owner Check
	
txn.ListByCustomerOwner
	
JSON: Transaction fields (incl. counterparty_fingerprint)


GET /api/customers/{id}/edd
	
handleCustomerEDD
	
requireAuth + Owner Check
	
edd.GetByOwnerCustomer
	
JSON: EDD fields (incl. confidential_comment, source_of_funds)


POST /api/customers/{id}/edd
	
handleCustomerEDD
	
requireAuth + Owner Check
	
edd.Create -> audit.Create (Field: edd_record.confidential_comment)
	
JSON: EDD fields


PATCH /api/customers/{id}/edd
	
handleCustomerEDD
	
requireAuth + Owner Check
	
edd.GetByOwnerCustomer (prev) -> edd.UpdateByOwnerCustomer -> audit.Create
	
JSON: EDD fields


GET /api/accounts/{id}
	
handleAccountsSubtree
	
requireAuth + Owner Check (GetByOwner)
	
acct.GetByOwner
	
JSON: Account fields


POST /api/transactions
	
handleTransactionsRoot
	
requireAuth
	
txn.Create -> risk.ScoreTransaction -> txn.UpdateRiskScoreByOwner -> alert.Create (if suspicious)
	
JSON: Transaction fields


GET /api/transactions/{id}
	
handleTransactionsSubtree
	
requireAuth + Owner Check
	
txn.GetByOwner
	
JSON: Transaction fields


GET /api/alerts/queue
	
handleAlertsQueue
	
requireAuth
	
alert.ListByOwner
	
JSON: Alert fields


GET /api/alerts/{id}
	
handleGetAlert
	
requireAuth + Owner Check
	
alert.GetByOwner
	
JSON: Alert fields


POST /api/alerts/{id}/claim
	
handleClaimAlert
	
requireAuth + Owner Check
	
alert.Claim (AssignedUserID=User.ID)
	
JSON: Alert fields


POST /api/alerts/{id}/triage
	
handleTriageAlert
	
requireAuth + Owner Check
	
alert.Triage (Status transition check)
	
JSON: Alert fields


POST /api/alerts/{id}/case
	
handleCreateCaseFromAlert
	
requireAuth + Owner Check
	
casework.CreateFromAlert -> audit.Create -> networkroom.EnqueueCaseCandidate
	
JSON: Case fields


GET /api/cases/{id}
	
handleGetCase
	
requireAuth + Owner Check
	
casework.GetByOwner
	
JSON: Case fields


GET /api/cases/{id}/notes
	
handleCaseNotes
	
requireAuth + Owner Check
	
casework.ListNotesByOwner
	
JSON: Note fields (incl. body)


POST /api/cases/{id}/notes
	
handleCaseNotes
	
requireAuth + Owner Check
	
casework.CreateNote -> audit.Create (Field: case_note.body)
	
JSON: Note fields


PATCH /api/cases/{id}/status
	
handleUpdateCaseStatus
	
requireAuth + Owner Check
	
casework.UpdateStatus -> audit.Create
	
JSON: Case fields


GET /api/cases/{id}/duplicates
	
handleCaseDuplicateCandidates
	
requireAuth + Owner Check
	
casework.FindDuplicateCandidatesByOwner
	
JSON: Candidate fields


GET /api/cases/{id}/timeline
	
handleCaseTimeline
	
requireAuth + Owner Check
	
casework.GetByOwner -> audit.ListCaseTimelineByOwner
	
JSON: Audit events (Redacted diffs)


GET /api/cases/{id}/duplicates/{dupId}/merge-preview
	
handleCaseDuplicateMergePreview
	
requireAuth + Owner Check
	
casework.FindDuplicateCandidatesByOwner -> casework.ResolveMatchEvidence
	
JSON: Preview with match_explanation


GET /api/entities/{hint}/activity
	
handleEntitiesSubtree
	
requireAuth
	
audit.ListEntityActivityByRequester (Access check via customers) -> entityActivityViewsWithDetail
	
JSON: Activity views (Hydrated narratives)


GET /api/graph/entities/{hint}
	
handleGraphEntity
	
requireAuth + Access Check (HasEntityAccess)
	
graph.GetEntitySummary
	
JSON: Entity summary


GET /api/graph/entities/{hint}/related-cases
	
handleGraphRelatedCases
	
requireAuth + Access Check
	
graph.ListRelatedCases
	
JSON: Related cases


GET /api/graph/entities/{hint}/edd-summaries
	
handleGraphEDDSummaries
	
requireAuth + Access Check
	
graph.ListEDDSummaries -> graphEDDSummariesResponseForEntityReview -> graph.ListReviewEDDSummaries
	
JSON: EDD summaries (with assessment_summary)


POST /api/disputes
	
handleDisputesRoot
	
requireAuth
	
export.CreateDispute
	
JSON: Dispute fields


POST /api/disputes/{id}/export
	
handleDisputesSubtree
	
requireAuth
	
export.GetDisputeByOwner -> handleCreateCaseExport
	
JSON: Export bundle


POST /api/cases/{id}/exports
	
handleCreateCaseExport
	
requireAuth + Owner Check
	
buildExportBundle -> export.CreateExport -> export.CreateExportItem
	
JSON: Export bundle


GET /api/exports/{id}
	
handleExportsSubtree
	
requireAuth + Owner Check
	
export.GetExportByOwner
	
JSON: Export bundle


GET /api/network/rooms
	
handleNetworkRoomsRoot
	
requireAuth
	
networkroom.ListRoomsForUser
	
JSON: Room summaries


GET /api/network/rooms/{id}
	
handleNetworkRoomsSubtree
	
requireAuth
	
networkroom.GetRoomForUser -> networkroom.ListParticipants
	
JSON: Room details


POST /api/network/rooms/{id}/join
	
handleNetworkRoomsSubtree
	
requireAuth
	
networkroom.JoinRoom (Requires case ownership in room)
	
JSON: Participant


GET /api/network/rooms/{id}/dossier
	
handleNetworkRoomsSubtree
	
requireAuth
	
networkroom.GetRoomForUser -> networkRoomDossierResponseForSharedRoom -> networkroom.ListExtendedDossierCases
	
JSON: Dossier with context/evaluation blocks


N/A (Worker)
	
run / processNetworkRooms
	
Env Config
	
networkroom.ProcessDirtyBatch -> processDirtyCandidate -> MaterializeArtifact
	
DB Side Effects (Artifacts, Links)
(B) Sensitive Fields and Readers
Field/Source
	
Policy/Context
	
Audience
	
Sink/Reader


password_hash
	
Internal/Auth
	
System
	
auth.FindUserByUsername (Hash comparison only)


token_hash
	
Internal/Auth
	
System
	
auth.FindSessionByTokenHash


raw_token
	
Session Creation
	
User (Transient)
	
auth.AuthResult -> SessionResponse.Token


confidential_comment (EDD)
	
Restricted/Owner
	
Analyst/Owner
	
edd.Repository -> httpapi.eddOwnerView (Full exposure to owner)
graph.repository -> analystNarrativeColumn (SQL injection risk? No, hardcoded concat)
exporting.redaction -> IsSensitiveExportField (Redacted in exports)


source_of_funds (EDD)
	
Restricted/Owner
	
Analyst/Owner
	
edd.Repository -> httpapi.eddOwnerView
exporting.redaction -> IsSensitiveExportField (Redacted in exports)


risk_rationale (EDD)
	
Restricted/Owner
	
Analyst/Owner
	
edd.Repository -> httpapi.eddOwnerView
exporting.redaction -> IsSensitiveExportField (Redacted in exports)


body (Case Notes)
	
Restricted/Owner
	
Analyst/Owner
	
casework.Repository -> httpapi.caseNoteResponse (Full exposure to owner)
audit.repository -> ActivityReviewContext (Used for hydration)
exporting.redaction -> IsSensitiveExportField (Redacted in exports)


diff_json (Audit)
	
Redacted
	
Owner/Internal
	
audit.RedactedDiffJSON (Hashes restricted fields)
httpapi.caseAuditChangeResponses (Masks field names if redacted)


entity_hint (Customer)
	
Owner Scope
	
Owner
	
graph.repository (Used for cross-entity queries)
networkroom.repository (Used for room clustering)


counterparty_fingerprint (Txn)
	
Owner Scope
	
Owner
	
txn.Repository -> httpapi.transactionResponse
risk.scoring (Used for weighting)
Unresolved Edges:
internal/httpapi/server.go: buildExportBundle calls s.populateExportLinkedCaseData. This function is defined in internal/httpapi/export_linked_cases.go but relies on s.cases implementing casework.MatchEvidenceResolver. The casework.Repository implements this interface, but the resolution logic in ResolveMatchEvidence queries case_notes with visibility = 'private'. It is unclear if this bypasses standard owner checks for the candidate case's notes when building an export for the source case owner.
internal/graph/repository_entity_summaries.go: analystNarrativeColumn() returns "conf" + "idential_comment". This string concatenation is used directly in a fmt.Sprintf SQL query. While currently safe from injection due to hardcoded parts, it indicates a pattern of dynamic column selection that could be risky if extended.
internal/networkroom/lifecycle.go: materializeCandidateArtifactsWithLimit queries case_notes with visibility = 'private' and edd_records.confidential_comment without explicit owner verification for the source case relative to the room creator. It relies on the DirtyCandidate processing which groups by entity_hint and typology_hint, potentially mixing data from different owners if they share these hints.
RECEIVED-fcb8ad6b736a
