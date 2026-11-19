(A) Confirmed Findings and Reproductions
Finding 1: Broken Object Level Authorization (BOLA) / Information Disclosure in Case Match Evidence
Affected Paths: GET /api/cases/{sourceCaseID}/duplicates/{duplicateCaseID}/merge-preview and POST /api/cases/{sourceCaseID}/exports
Affected Functions: handleCaseDuplicateMergePreview, buildExportBundle, populateExportLinkedCaseData, and ResolveMatchEvidence in internal/casework/repository.go.
Attacker-Controlled Input: sourceCaseID (must be owned by the attacker), duplicateCaseID (any case ID in the system), and the DedupHint string (fully controlled by the attacker when creating a case via POST /api/alerts/{id}/case).
Source-to-Sink Path:
Attacker creates a case (sourceCaseID) and sets its DedupHint to a known, guessed, or common value (e.g., "target_entity").
Attacker calls GET /api/cases/{sourceCaseID}/duplicates, which returns all cases in the system sharing that DedupHint, revealing the duplicateCaseID of a victim's case.
Attacker calls GET /api/cases/{sourceCaseID}/duplicates/{duplicateCaseID}/merge-preview (or POST /api/cases/{sourceCaseID}/exports).
The server invokes ResolveMatchEvidence with the attacker's sourceCaseID and the victim's duplicateCaseID.
ResolveMatchEvidence verifies the attacker owns the sourceCaseID and retrieves its dedup_hint.
It then executes a SQL query to fetch case_notes for the duplicateCaseID where visibility = 'private' and the dedup_hint matches. Critically, it does not verify that the attacker owns the duplicateCaseID.
The private note body is returned directly to the attacker in the MatchExplanation field (for merge-preview) or the LinkedEvidence array (for exports).
Missing Control: Absence of an owner_user_id authorization check for the CandidateCaseID in the ResolveMatchEvidence SQL query.
Concrete Impact: An authenticated attacker can read the private investigation notes of any case in the system, bypassing tenant/user isolation, provided they can match its dedup_hint.
Minimal Reproduction:
Victim creates Case V with dedup_hint = "shared_entity".
Victim adds a private note to Case V: {"visibility": "private", "body": "SECRET_VICTIM_NOTE"}.
Attacker creates Case A via POST /api/alerts/{id}/case with {"dedup_hint": "shared_entity"}.
Attacker calls GET /api/cases/{Case A}/duplicates and observes Case V in the candidates array.
Attacker calls GET /api/cases/{Case A}/duplicates/{Case V}/merge-preview.
Expected Evidence: The JSON response contains "match_explanation": "SECRET_VICTIM_NOTE".
(B) Unresolved Leads
Network Room Artifact Materialization: The background worker (processDirtyCandidate in internal/networkroom/lifecycle.go) automatically groups cases by entity_hint and typology_hint, materializing private case notes and confidential_comment EDD records into network_room_artifacts. Any user who owns a case in that room can read these artifacts via GET /api/network/rooms/{id}/dossier. While this represents aggressive cross-user data sharing, the service contract (entity graph/network room design) appears to intentionally share these specific projections (DossierContextBlock, DossierEvaluationBlock) among collaborators investigating the same entity. Marked as intentional design, but warrants architectural review.
(C) Compact Coverage Ledgers
Entry Point Ledger
Entry Point
	
Finding ID / Status


POST /api/auth/register
	
Reviewed, no confirmed finding


POST /api/auth/login
	
Reviewed, no confirmed finding


GET /api/auth/me
	
Reviewed, no confirmed finding


POST /api/customers
	
Reviewed, no confirmed finding


GET /api/customers/{id}
	
Reviewed, no confirmed finding


GET/POST /api/customers/{id}/accounts
	
Reviewed, no confirmed finding


GET /api/customers/{id}/transactions
	
Reviewed, no confirmed finding


GET/POST/PATCH /api/customers/{id}/edd
	
Reviewed, no confirmed finding


GET /api/accounts/{id}
	
Reviewed, no confirmed finding


POST /api/transactions
	
Reviewed, no confirmed finding


GET /api/transactions/{id}
	
Reviewed, no confirmed finding


GET /api/alerts/queue
	
Reviewed, no confirmed finding


GET /api/alerts/{id}
	
Reviewed, no confirmed finding


POST /api/alerts/{id}/claim
	
Reviewed, no confirmed finding


POST /api/alerts/{id}/triage
	
Reviewed, no confirmed finding


POST /api/alerts/{id}/case
	
Reviewed, no confirmed finding


GET /api/cases/{id}
	
Reviewed, no confirmed finding


GET/POST /api/cases/{id}/notes
	
Reviewed, no confirmed finding


PATCH /api/cases/{id}/status
	
Reviewed, no confirmed finding


GET /api/cases/{id}/duplicates
	
Reviewed, no confirmed finding (returns only public fields)


GET /api/cases/{id}/duplicates/{dupId}/merge-preview
	
Finding 1


GET /api/cases/{id}/timeline
	
Reviewed, no confirmed finding


POST /api/cases/{id}/exports
	
Finding 1 (alternate sink path)


GET /api/exports/{id}
	
Reviewed, no confirmed finding


POST /api/disputes
	
Reviewed, no confirmed finding


POST /api/disputes/{id}/export
	
Reviewed, no confirmed finding


GET /api/entities/{hint}/activity
	
Reviewed, no confirmed finding (intentional entity graph sharing)


GET /api/graph/entities/{hint}
	
Reviewed, no confirmed finding


GET /api/graph/entities/{hint}/related-cases
	
Reviewed, no confirmed finding


GET /api/graph/entities/{hint}/edd-summaries
	
Reviewed, no confirmed finding (intentional entity graph sharing)


GET /api/network/rooms
	
Reviewed, no confirmed finding


GET/POST /api/network/rooms/{id}
	
Reviewed, no confirmed finding


GET /api/network/rooms/{id}/dossier
	
Reviewed, no confirmed finding (intentional network room sharing)


Worker: ProcessDirtyBatch
	
Reviewed, no confirmed finding (system-level grouping)
Sensitive Field / Reader Flow Ledger
Sensitive Field
	
Reader / Helper
	
Policy / Context
	
Finding ID / Status


password_hash
	
auth.FindUserByUsername
	
Internal Auth Only
	
Reviewed, no confirmed finding


token_hash / raw_token
	
auth.FindSessionByTokenHash / authResultResponse
	
Internal Auth / Session Creation
	
Reviewed, no confirmed finding


confidential_comment (EDD)
	
edd.GetByOwnerCustomer
	
Owner Check
	
Reviewed, no confirmed finding


confidential_comment (EDD)
	
graph.ListReviewMaterials
	
Entity Access Check (HasEntityAccess)
	
Reviewed, no confirmed finding (intentional sharing)


body (Case Note, private)
	
casework.ListNotesByOwner
	
Owner Check
	
Reviewed, no confirmed finding


body (Case Note, private)
	
casework.ResolveMatchEvidence
	
Missing Candidate Ownership Check
	
Finding 1


diff_json (Audit)
	
audit.RedactedDiffJSON
	
Audit Creation
	
Reviewed, no confirmed finding (properly redacted)


diff_json (Audit)
	
exportrepo.safeAuditSummary
	
Export Bundle Build
	
Reviewed, no confirmed finding (field names only)
File Map Path Ledger
File Path
	
Finding ID / Status


Dockerfile, Makefile, README.md, docker-compose.yml
	
Reviewed, no confirmed finding


cmd/aml-api/main.go, cmd/aml-migrate/main.go, cmd/aml-worker/main.go
	
Reviewed, no confirmed finding


internal/account/repository.go
	
Reviewed, no confirmed finding


internal/alert/repository.go
	
Reviewed, no confirmed finding


internal/audit/activity_hydration.go, internal/audit/repository.go
	
Reviewed, no confirmed finding


internal/auth/repository.go, internal/auth/service.go
	
Reviewed, no confirmed finding


internal/authz/*.go
	
Reviewed, no confirmed finding


internal/casework/matching_evidence.go, internal/casework/repository.go
	
Finding 1 (ResolveMatchEvidence)


internal/classification/*.go
	
Reviewed, no confirmed finding


internal/config/*.go
	
Reviewed, no confirmed finding


internal/customer/repository.go
	
Reviewed, no confirmed finding


internal/db/db.go, internal/db/migrate.go
	
Reviewed, no confirmed finding


internal/edd/repository.go
	
Reviewed, no confirmed finding


internal/exporting/*.go
	
Reviewed, no confirmed finding


internal/graph/*.go
	
Reviewed, no confirmed finding


internal/httpapi/*.go
	
Finding 1 (handlers invoking vulnerable logic)


internal/logging/doc.go
	
Reviewed, no confirmed finding


internal/networkroom/*.go
	
Reviewed, no confirmed finding (intentional sharing model)


internal/projection/contracts.go
	
Reviewed, no confirmed finding


internal/risk/scoring.go
	
Reviewed, no confirmed finding


internal/transaction/repository.go
	
Reviewed, no confirmed finding


migrations/*.sql
	
Reviewed, no confirmed finding
