(A) Entry Point Inventory
Method/Path
	
Handler
	
Auth/Object Gate
	
Call Chain
	
Output/Sink


POST /api/auth/register
	
handleRegister
	
None (Public)
	
auth.Register -> auth.Repository.CreateUser, auth.Service.createSession
	
JSON: user (id, username, role, status), session (token, expires_at)


POST /api/auth/login
	
handleLogin
	
None (Public)
	
auth.Login -> auth.Repository.FindUserByUsername, auth.Service.createSession
	
JSON: user, session (raw token)


GET /api/auth/me
	
handleMe
	
requireAuth (Bearer)
	
auth.CurrentUser -> auth.Repository.FindSessionByTokenHash, FindUserByID
	
JSON: user (id, username, role, status)


POST /api/customers
	
handleCustomersRoot
	
requireAuth
	
customer.Repository.Create
	
JSON: customer (id, display_name, type, country, reg_num, risk_level, entity_hint, status)


GET /api/customers/{id}
	
handleGetCustomer
	
requireAuth + Owner Check (GetByOwner)
	
customer.Repository.GetByOwner
	
JSON: customer


GET /api/customers/{id}/accounts
	
handleCustomerAccounts
	
requireAuth + Owner Check (ListByCustomerOwner)
	
account.Repository.ListByCustomerOwner
	
JSON: accounts (id, customer_id, iban_like, currency, status)


POST /api/customers/{id}/accounts
	
handleCustomerAccounts
	
requireAuth + Owner Check (Create)
	
account.Repository.Create
	
JSON: account


GET /api/customers/{id}/transactions
	
handleCustomerTransactions
	
requireAuth + Owner Check (ListByCustomerOwner)
	
transaction.Repository.ListByCustomerOwner
	
JSON: transactions (id, account_id, counterparty_name/country/fingerprint, amount, currency, direction, purpose, trace_id, risk_score)


GET /api/customers/{id}/edd
	
handleCustomerEDD
	
requireAuth + Owner Check (GetByOwnerCustomer)
	
edd.Repository.GetByOwnerCustomer
	
JSON: edd_record (id, customer_id, analyst_user_id, source_of_funds, risk_rationale, confidential_comment, review_status)


POST /api/customers/{id}/edd
	
handleCustomerEDD
	
requireAuth + Owner Check (Create)
	
edd.Repository.Create, audit.Repository.Create
	
JSON: edd_record; Audit Event (diff_json includes confidential_comment)


PATCH /api/customers/{id}/edd
	
handleCustomerEDD
	
requireAuth + Owner Check (UpdateByOwnerCustomer)
	
edd.Repository.UpdateByOwnerCustomer, audit.Repository.Create
	
JSON: edd_record; Audit Event (diff_json includes confidential_comment)


GET /api/accounts/{id}
	
handleAccountsSubtree
	
requireAuth + Owner Check (GetByOwner)
	
account.Repository.GetByOwner
	
JSON: account


POST /api/transactions
	
handleTransactionsRoot
	
requireAuth
	
transaction.Repository.Create, risk.Service.ScoreTransaction
	
JSON: transaction (includes risk_score); Side Effect: alert.Repository.Create if suspicious


GET /api/transactions/{id}
	
handleTransactionsSubtree
	
requireAuth + Owner Check (GetByOwner)
	
transaction.Repository.GetByOwner
	
JSON: transaction


GET /api/alerts/queue
	
handleAlertsQueue
	
requireAuth
	
alert.Repository.ListByOwner
	
JSON: alerts (id, transaction_id, customer_id, rule_code, risk_score, status, assigned_user_id, typology_hint)


GET /api/alerts/{id}
	
handleGetAlert
	
requireAuth + Owner Check (GetByOwner)
	
alert.Repository.GetByOwner
	
JSON: alert


POST /api/alerts/{id}/claim
	
handleClaimAlert
	
requireAuth + Owner Check (Claim)
	
alert.Repository.Claim
	
JSON: alert


POST /api/alerts/{id}/triage
	
handleTriageAlert
	
requireAuth + Owner Check (Triage)
	
alert.Repository.Triage
	
JSON: alert


POST /api/alerts/{id}/case
	
handleCreateCaseFromAlert
	
requireAuth
	
casework.Repository.CreateFromAlert, audit.Repository.Create, networkroom.Repository.EnqueueCaseCandidate
	
JSON: case (id, customer_id, alert_id, status, public_summary, risk_score, typology_hint); Side Effect: Dirty Candidate Enqueued


GET /api/cases/{id}
	
handleGetCase
	
requireAuth + Owner Check (GetByOwner)
	
casework.Repository.GetByOwner
	
JSON: case


GET /api/cases/{id}/notes
	
handleCaseNotes
	
requireAuth + Owner Check (ListNotesByOwner)
	
casework.Repository.ListNotesByOwner
	
JSON: notes (id, case_id, author_user_id, visibility, body)


POST /api/cases/{id}/notes
	
handleCaseNotes
	
requireAuth + Owner Check (CreateNote)
	
casework.Repository.CreateNote, audit.Repository.Create
	
JSON: note; Audit Event (diff_json includes case_note.body)


PATCH /api/cases/{id}/status
	
handleUpdateCaseStatus
	
requireAuth + Owner Check (UpdateStatus)
	
casework.Repository.UpdateStatus, audit.Repository.Create
	
JSON: case; Audit Event


GET /api/cases/{id}/duplicates
	
handleCaseDuplicateCandidates
	
requireAuth + Owner Check (FindDuplicateCandidatesByOwner)
	
casework.Repository.FindDuplicateCandidatesByOwner
	
JSON: candidates (case_id, public_summary, risk_tags, overlap_score, match_explanation)


GET /api/cases/{id}/duplicates/{dup_id}/merge-preview
	
handleCaseDuplicateMergePreview
	
requireAuth + Owner Check
	
casework.Repository.FindDuplicateCandidatesByOwner, casework.Repository.ResolveMatchEvidence
	
JSON: candidate with match_explanation (may include private note body from ResolveMatchEvidence)


GET /api/cases/{id}/timeline
	
handleCaseTimeline
	
requireAuth + Owner Check (GetByOwner then ListCaseTimelineByOwner)
	
audit.Repository.ListCaseTimelineByOwner
	
JSON: events (id, object_type, object_id, event_type, public_message, changes [redacted], created_at, visibility_scope)


GET /api/entities/{hint}/activity
	
handleEntitiesSubtree
	
requireAuth
	
audit.Repository.ListEntityActivityByRequester (Access Check via SQL)
	
JSON: activities (includes activity_narrative which may contain case_note.body via ActivityReviewContext)


GET /api/graph/entities/{hint}
	
handleGraphEntity
	
requireAuth + Access Check (HasEntityAccess)
	
graph.Repository.GetEntitySummary
	
JSON: entity (entity_hint, relation_type, customer_count, case_count, highest_risk, risk_tags)


GET /api/graph/entities/{hint}/related-cases
	
handleGraphRelatedCases
	
requireAuth + Access Check
	
graph.Repository.ListRelatedCases
	
JSON: cases (case_id, customer_id, entity_hint, display_name, country, status, public_summary, risk_score, typology_hint)


GET /api/graph/entities/{hint}/edd-summaries
	
handleGraphEDDSummaries
	
requireAuth + Access Check
	
graph.Repository.ListEDDSummaries, graph.Repository.ListReviewEDDSummaries
	
JSON: summaries (includes assessment_summary which may contain confidential_comment via analystNarrativeColumn)


POST /api/disputes
	
handleDisputesRoot
	
requireAuth
	
exporting.Repository.CreateDispute
	
JSON: dispute (id, case_id, status, reason, resolution_summary)


POST /api/disputes/{id}/export
	
handleDisputesSubtree
	
requireAuth
	
exporting.Repository.GetDisputeByOwner, handleCreateCaseExport
	
JSON: export (bundle)


POST /api/cases/{id}/exports
	
handleCreateCaseExport
	
requireAuth
	
buildExportBundle -> casework.Repository (notes, duplicates), edd.Repository, audit.Repository, exporting.BuildBundle
	
JSON: export (bundle includes linked_evidence which may contain private note bodies via populateExportLinkedCaseData)


GET /api/exports/{id}
	
handleExportsSubtree
	
requireAuth + Owner Check (GetExportByOwner)
	
exporting.Repository.GetExportByOwner
	
JSON: export (bundle)


GET /api/network/rooms
	
handleNetworkRoomsRoot
	
requireAuth
	
networkroom.Repository.ListRoomsForUser
	
JSON: rooms (id, room_key, entity_hint, typology_hint, status, public_summary, public_risk_tags, counts)


GET /api/network/rooms/{id}
	
handleNetworkRoomsSubtree
	
requireAuth + Participant Check (GetRoomForUser)
	
networkroom.Repository.GetRoomForUser, ListParticipants
	
JSON: room, participants


POST /api/network/rooms/{id}/join
	
handleNetworkRoomsSubtree
	
requireAuth
	
networkroom.Repository.JoinRoom (SQL checks ownership of attached cases)
	
JSON: participant


GET /api/network/rooms/{id}/dossier
	
handleNetworkRoomsSubtree
	
requireAuth + Participant Check
	
networkroom.Repository.GetRoomForUser, ListExtendedDossierCases
	
JSON: dossier (includes context_blocks and evaluation_blocks containing confidential_comment and private note bodies)


Worker: ProcessDirtyBatch
	
aml-worker main
	
None (Internal/Env)
	
networkroom.Repository.ProcessDirtyBatch -> ClaimDirtyCandidates, processDirtyCandidate -> CreateOrFindRoom, AttachCase, JoinRoom, materializeCandidateArtifactsWithLimit
	
DB Side Effects: Creates rooms, attaches cases, joins participants, materializes artifacts (copies confidential_comment and private note bodies to network_room_artifacts.content)
(B) Sensitive Field Trace
Sensitive Field
	
Source (Schema/Write)
	
Reader/Helper
	
Policy/Context
	
Audience
	
Sink (Serialized/Logged)


password_hash
	
users.password_hash
	
auth.Repository.FindUserByUsername
	
Internal Auth
	
System
	
None (compared in memory)


token_hash
	
sessions.token_hash
	
auth.Repository.FindSessionByTokenHash
	
Internal Auth
	
System
	
None (compared in memory)


raw_token
	
auth.Service.createSession
	
httpapi.handleRegister/Login
	
Session Creation
	
User
	
JSON Response session.token


confidential_comment
	
edd_records.confidential_comment
	
httpapi.handleCustomerEDD
	
Owner Only
	
Owner
	
JSON Response confidential_comment


confidential_comment
	
edd_records.confidential_comment
	
audit.Repository.Create (via handleCustomerEDD)
	
Audit Log
	
Owner/Internal
	
JSON diff_json (Redacted by RedactedDiffJSON if field is restricted)


confidential_comment
	
edd_records.confidential_comment
	
graph.Repository.ListReviewMaterials
	
Entity Graph Access (Shared Entity)
	
Shared Entity Owners
	
JSON assessment_summary (via analystNarrativeColumn which selects confidential_comment)


confidential_comment
	
edd_records.confidential_comment
	
networkroom.Repository.materializeCandidateArtifactsWithLimit
	
Worker/Network Room
	
Network Room Participants
	
DB network_room_artifacts.content


case_note.body
	
case_notes.body
	
httpapi.handleCaseNotes
	
Owner Only (via ListNotesByOwner)
	
Owner
	
JSON Response body


case_note.body
	
case_notes.body
	
audit.Repository.Create (via handleCaseNotes)
	
Audit Log
	
Owner/Internal
	
JSON diff_json (Redacted by RedactedDiffJSON)


case_note.body
	
case_notes.body
	
casework.Repository.ResolveMatchEvidence
	
Duplicate Candidate Match (Owner of Source Case)
	
Owner
	
JSON match_explanation (in merge-preview)


case_note.body
	
case_notes.body
	
audit.Repository.ActivityReviewContext
	
Entity Activity Stream
	
Requester (if owns entity)
	
JSON activity_narrative (in entity/activity)


case_note.body
	
case_notes.body
	
networkroom.Repository.materializeCandidateArtifactsWithLimit
	
Worker/Network Room (Private notes only)
	
Network Room Participants
	
DB network_room_artifacts.content


network_room_artifacts.content
	
network_room_artifacts.content
	
networkroom.Repository.ListExtendedDossierCases
	
Network Room Participant
	
Room Participants
	
JSON context_blocks.content / evaluation_blocks.content


source_of_funds
	
edd_records.source_of_funds
	
httpapi.handleCustomerEDD
	
Owner Only
	
Owner
	
JSON Response source_of_funds


source_of_funds
	
edd_records.source_of_funds
	
audit.Repository.Create
	
Audit Log
	
Owner/Internal
	
JSON diff_json (Redacted)


risk_rationale
	
edd_records.risk_rationale
	
httpapi.handleCustomerEDD
	
Owner Only
	
Owner
	
JSON Response risk_rationale


risk_rationale
	
edd_records.risk_rationale
	
audit.Repository.Create
	
Audit Log
	
Owner/Internal
	
JSON diff_json (Redacted)
Unresolved Edges
internal/risk/scoring.go: Score function uses deriveTypology which calls fingerprintWeight. The fingerprintWeight logic uses a modulo operation on rune sums for non-keyword fingerprints. This is a deterministic but potentially weak entropy source for risk scoring.
internal/exporting/redaction.go: IsSensitiveExportField checks classification.IsProtectedSourceField and a local sensitiveExportFields map. The classification package's protectedSourceFields map is the primary authority. There is a potential for drift if the local map in exporting is not kept in sync with classification.
internal/httpapi/server.go: buildExportBundle calls populateExportLinkedCaseData. This function resolves match evidence and adds it to SourceMaterials. The ExportItemBuilder then filters these based on CoveragePolicy. The interaction between MatchEvidenceSourceReviewContext (which comes from private notes) and the export scope policies needs careful verification to ensure private data isn't leaked to unauthorized export recipients (though currently scoped to RootCaseDetail).
RECEIVED-a4749f013f61
