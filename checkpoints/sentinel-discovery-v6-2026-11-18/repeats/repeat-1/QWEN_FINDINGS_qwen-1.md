(A) Confirmed Findings
IDOR in Entity Graph EDD Summaries (Leaking confidential_comment)
Affected Path: GET /api/graph/entities/{hint}/edd-summaries
Function: graph.ListReviewMaterials
Attacker Input: entityHint in URL path
Required Access: Authenticated user who owns ANY customer with the same entity_hint.
Source-to-Sink: edd_records.confidential_comment → ListReviewMaterials (via hardcoded analystNarrativeColumn()) → ReviewMaterial.AnalystNarrative → AssessmentSummaryPolicy.Build → ReviewEDDSummary.AssessmentSummary → entityReviewEDDGraphSummaryViews → JSON response.
Missing Control: The SQL query filters by entity_hint matching a customer owned by the requester, but fails to filter edd_records by the requester's ownership. It returns EDD records of ALL customers sharing that hint.
Impact: Attacker can read the confidential_comment and risk_rationale of other users' EDD records.
Reproduction:
Attacker creates Customer A with entity_hint: "shared_entity".
Victim creates Customer B with entity_hint: "shared_entity" and an EDD record with review_status: "IN_REVIEW" and confidential_comment: "secret_funds".
Attacker requests GET /api/graph/entities/shared_entity/edd-summaries.
Evidence: Response JSON contains "assessment_summary": "secret_funds" for the victim's EDD record.
IDOR in Case Duplicate Merge Preview (Leaking private case notes)
Affected Path: GET /api/cases/{id}/duplicates/{dupId}/merge-preview
Function: casework.ResolveMatchEvidence
Attacker Input: sourceCaseID (owned by attacker), duplicateCaseID (owned by victim)
Required Access: Authenticated user who owns the sourceCaseID.
Source-to-Sink: case_notes.body (where visibility = 'private') → ResolveMatchEvidence → CaseSimilarityEvidence.Excerpt → MatchExplanationBuilder.Build → caseMatchDuplicateMergePreviewResponse.MatchExplanation → JSON response.
Missing Control: ResolveMatchEvidence verifies ownership of SourceCaseID, but when querying case_notes for CandidateCaseID, it only checks c.dedup_hint, completely omitting an ownership check for the candidate case.
Impact: Attacker can read the full body of private case notes belonging to any case that shares a dedup_hint with a case they own.
Reproduction:
Attacker creates Case 1 with dedup_hint: "hint123".
Victim creates Case 2 with dedup_hint: "hint123" and adds a private case note with body: "internal suspicion".
Attacker requests GET /api/cases/1/duplicates/2/merge-preview.
Evidence: Response JSON contains "match_explanation": "internal suspicion".
IDOR in Export Bundle Generation (Leaking private case notes and confidential_comment)
Affected Path: POST /api/cases/{id}/exports (and POST /api/disputes/{id}/export)
Function: httpapi.populateExportLinkedCaseData → casework.ResolveMatchEvidence → exporting.ExportItemBuilder.Build
Attacker Input: caseID (owned by attacker), allowed_scopes: ["linked_cases"]
Required Access: Authenticated user who owns the root caseID.
Source-to-Sink: case_notes.body / edd_records.confidential_comment → ResolveMatchEvidence → ExportSourceMaterial.Content → ExportItemBuilder.Build (skips IsSensitiveExportField check for Content) → ExportBundle.LinkedEvidence → JSON response.
Missing Control: Inherits the missing ownership check in ResolveMatchEvidence (Finding 2), compounded by ExportItemBuilder.Build failing to redact material.Content even though it contains sensitive data.
Impact: Attacker can generate an export bundle that contains the private case notes and confidential_comment of other users' cases linked via dedup_hint.
Reproduction:
Attacker creates Case 1 with dedup_hint: "hint123".
Victim creates Case 2 with dedup_hint: "hint123" and a private case note with body: "do not export".
Attacker requests POST /api/cases/1/exports with {"purpose": "case_review", "allowed_scopes": ["linked_cases"]}.
Evidence: Response JSON linked_evidence array contains an object with "content": "do not export".
IDOR in Entity Activity Stream (Leaking private case note bodies)
Affected Path: GET /api/entities/{hint}/activity
Function: audit.ActivityReviewContext
Attacker Input: entityHint in URL path
Required Access: Authenticated user who owns ANY customer with the same entity_hint.
Source-to-Sink: case_notes.body → ActivityReviewContext → ActivityHydrator.caseNoteResolver → EntityActivityView.ActivityText → JSON response.
Missing Control: ListEntityActivityByRequester grants access if the user owns ANY customer with the hint. ActivityReviewContext then fetches the case note body using only cn.id, ca.id, and entity_hint, without verifying that the requester owns the specific case or customer the note belongs to.
Impact: Attacker can read the full body of private case notes belonging to other users who share the same entity_hint, bypassing the redaction applied to the audit diff_json.
Reproduction:
Attacker creates Customer A with entity_hint: "shared".
Victim creates Customer B with entity_hint: "shared", creates a case, and adds a private case note with body: "secret note".
Attacker requests GET /api/entities/shared/activity.
Evidence: Response JSON activities array contains an object with "activity_narrative": "secret note".
IDOR in Network Room Dossier (Leaking private case notes and confidential_comment)
Affected Path: GET /api/network/rooms/{id}/dossier
Function: networkroom.ListExtendedDossierCases
Attacker Input: roomID
Required Access: Authenticated user who owns ANY case in the network room.
Source-to-Sink: case_notes.body / edd_records.confidential_comment → networkroom.materializeCandidateArtifactsWithLimit (background worker) → network_room_artifacts.content → ListExtendedDossierCases → ExtendedCaseDossierSummary.ContextBlocks / EvaluationBlocks → JSON response.
Missing Control: JoinRoom allows a user to join if they own ANY case in the room. ListExtendedDossierCases then returns ALL artifacts in the room to ANY participant, without filtering by case ownership. The worker materializes artifacts from ALL cases in the room regardless of owner.
Impact: Attacker can read private case notes and confidential_comment of all other cases in the network room.
Reproduction:
Attacker creates Case A with entity_hint: "room_hint", typology_hint: "typology".
Victim creates Case B with entity_hint: "room_hint", typology_hint: "typology", and a private case note with body: "room secret".
Worker processes dirty candidates, creating Room 1 and attaching both cases, materializing artifacts.
Attacker requests POST /api/network/rooms/1/join (succeeds because they own Case A).
Attacker requests GET /api/network/rooms/1/dossier.
Evidence: Response JSON cases array contains a context_blocks or evaluation_blocks entry with "content": "room secret" originating from Case B.
(B) Unresolved Leads
None. All identified cross-user data flows are confirmed vulnerabilities based on missing ownership checks on sensitive fields.
(C) Compact Coverage Ledgers
Entry Points Ledger:
POST /api/auth/register: handleRegister (reviewed, no confirmed finding)
POST /api/auth/login: handleLogin (reviewed, no confirmed finding)
GET /api/auth/me: handleMe (reviewed, no confirmed finding)
POST /api/customers: handleCustomersRoot (reviewed, no confirmed finding)
GET /api/customers/{id}: handleGetCustomer (reviewed, no confirmed finding)
GET /api/customers/{id}/accounts: handleCustomerAccounts (reviewed, no confirmed finding)
POST /api/customers/{id}/accounts: handleCustomerAccounts (reviewed, no confirmed finding)
GET /api/customers/{id}/transactions: handleCustomerTransactions (reviewed, no confirmed finding)
GET /api/customers/{id}/edd: handleCustomerEDD (reviewed, no confirmed finding)
POST /api/customers/{id}/edd: handleCustomerEDD (reviewed, no confirmed finding)
PATCH /api/customers/{id}/edd: handleCustomerEDD (reviewed, no confirmed finding)
GET /api/accounts/{id}: handleAccountsSubtree (reviewed, no confirmed finding)
POST /api/transactions: handleTransactionsRoot (reviewed, no confirmed finding)
GET /api/transactions/{id}: handleTransactionsSubtree (reviewed, no confirmed finding)
GET /api/alerts/queue: handleAlertsQueue (reviewed, no confirmed finding)
GET /api/alerts/{id}: handleGetAlert (reviewed, no confirmed finding)
POST /api/alerts/{id}/claim: handleClaimAlert (reviewed, no confirmed finding)
POST /api/alerts/{id}/triage: handleTriageAlert (reviewed, no confirmed finding)
POST /api/alerts/{id}/case: handleCreateCaseFromAlert (reviewed, no confirmed finding)
GET /api/cases/{id}: handleGetCase (reviewed, no confirmed finding)
GET /api/cases/{id}/notes: handleCaseNotes (reviewed, no confirmed finding)
POST /api/cases/{id}/notes: handleCaseNotes (reviewed, no confirmed finding)
PATCH /api/cases/{id}/status: handleUpdateCaseStatus (reviewed, no confirmed finding)
GET /api/cases/{id}/duplicates: handleCaseDuplicateCandidates (reviewed, no confirmed finding)
GET /api/cases/{id}/timeline: handleCaseTimeline (reviewed, no confirmed finding)
GET /api/cases/{id}/duplicates/{dupId}/merge-preview: handleCaseDuplicateMergePreview (Finding 2, Finding 3)
GET /api/entities/{hint}/activity: handleEntitiesSubtree (Finding 4)
GET /api/graph/entities/{hint}: handleGraphEntity (reviewed, no confirmed finding)
GET /api/graph/entities/{hint}/related-cases: handleGraphRelatedCases (reviewed, no confirmed finding)
GET /api/graph/entities/{hint}/edd-summaries: handleGraphEDDSummaries (Finding 1)
POST /api/disputes: handleDisputesRoot (reviewed, no confirmed finding)
POST /api/disputes/{id}/export: handleDisputesSubtree (Finding 3)
POST /api/cases/{id}/exports: handleCreateCaseExport (Finding 3)
GET /api/exports/{id}: handleExportsSubtree (reviewed, no confirmed finding)
GET /api/network/rooms: handleNetworkRoomsRoot (reviewed, no confirmed finding)
GET /api/network/rooms/{id}: handleNetworkRoomsSubtree (reviewed, no confirmed finding)
POST /api/network/rooms/{id}/join: handleNetworkRoomsSubtree (Finding 5)
GET /api/network/rooms/{id}/dossier: handleNetworkRoomsSubtree (Finding 5)
Worker processNetworkRooms: run / processDirtyCandidate (Finding 5)
Sensitive Field/Reader Flow Ledger:
password_hash: Auth service only (reviewed, no confirmed finding)
token_hash: Auth service only (reviewed, no confirmed finding)
raw_token: Returned to authenticating user only (reviewed, no confirmed finding)
confidential_comment (EDD): edd.Repository → httpapi.eddOwnerView (reviewed, no confirmed finding); graph.ListReviewMaterials (Finding 1); networkroom.materializeCandidateArtifactsWithLimit (Finding 5)
source_of_funds / risk_rationale (EDD): edd.Repository → httpapi.eddOwnerView (reviewed, no confirmed finding); graph.ListReviewMaterials (Finding 1)
body (Case Notes): casework.Repository → httpapi.caseNoteResponse (reviewed, no confirmed finding); audit.ActivityReviewContext (Finding 4); casework.ResolveMatchEvidence (Finding 2, Finding 3); networkroom.materializeCandidateArtifactsWithLimit (Finding 5)
diff_json (Audit): audit.RedactedDiffJSON (reviewed, no confirmed finding)
entity_hint (Customer): Used for grouping queries (reviewed, no confirmed finding)
counterparty_fingerprint (Txn): txn.Repository → httpapi.transactionResponse (reviewed, no confirmed finding)
File Map Path Ledger:
Dockerfile, Makefile, README.md, docker-compose.yml: (reviewed, no confirmed finding)
cmd/aml-api/main.go, cmd/aml-migrate/main.go, cmd/aml-worker/main.go: (reviewed, no confirmed finding)
internal/account/repository.go: (reviewed, no confirmed finding)
internal/alert/repository.go: (reviewed, no confirmed finding)
internal/audit/activity_hydration.go: (Finding 4)
internal/audit/repository.go: (Finding 4)
internal/auth/repository.go, internal/auth/service.go: (reviewed, no confirmed finding)
internal/authz/doc.go, internal/authz/principal.go, internal/authz/scope_contract.go: (reviewed, no confirmed finding)
internal/casework/matching_evidence.go: (Finding 2, Finding 3)
internal/casework/repository.go: (Finding 2, Finding 3)
internal/classification/catalog.go, internal/classification/policy_labels.go: (reviewed, no confirmed finding)
internal/config/database.go, internal/config/doc.go: (reviewed, no confirmed finding)
internal/customer/repository.go: (reviewed, no confirmed finding)
internal/db/db.go, internal/db/migrate.go: (reviewed, no confirmed finding)
internal/edd/repository.go: (Finding 1)
internal/exporting/export_linked_evidence.go: (Finding 3)
internal/exporting/redaction.go: (Finding 3)
internal/exporting/repository.go: (Finding 3)
internal/graph/assessment_summary.go: (Finding 1)
internal/graph/repository.go: (reviewed, no confirmed finding)
internal/graph/repository_entity_summaries.go: (Finding 1)
internal/httpapi/activity_views.go: (Finding 4)
internal/httpapi/dedup_merge_preview.go: (Finding 2)
internal/httpapi/doc.go: (reviewed, no confirmed finding)
internal/httpapi/entity_review_summaries.go: (Finding 1)
internal/httpapi/export_linked_cases.go: (Finding 3)
internal/httpapi/network_room_context.go: (Finding 5)
internal/httpapi/server.go: (Findings 1, 2, 3, 4, 5)
internal/logging/doc.go: (reviewed, no confirmed finding)
internal/networkroom/dossier_context.go: (Finding 5)
internal/networkroom/lifecycle.go: (Finding 5)
internal/networkroom/repository.go: (Finding 5)
internal/networkroom/repository_context.go: (Finding 5)
internal/projection/contracts.go: (reviewed, no confirmed finding)
internal/risk/scoring.go: (reviewed, no confirmed finding)
internal/transaction/repository.go: (reviewed, no confirmed finding)
migrations/*.sql: (reviewed, no confirmed finding)
