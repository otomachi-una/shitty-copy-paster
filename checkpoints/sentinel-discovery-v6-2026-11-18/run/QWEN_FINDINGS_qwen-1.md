(A) Confirmed Findings
VULN-01: Cross-Tenant Information Leak via Entity Graph EDD Summaries
Affected Path: GET /api/graph/entities/{hint}/edd-summaries
Handler/Function: httpapi.handleGraphEDDSummaries → graph.Repository.ListReviewEDDSummaries → graph.Repository.ListReviewMaterials
Attacker Input: hint (entity_hint string), authenticated user token.
Source-to-Sink Path: The SQL query in ListReviewMaterials checks if the requester owns any customer with the given entity_hint. If true, it selects er.confidential_comment (aliased as analyst_narrative) for all EDD records associated with any customer sharing that entity_hint, without verifying owner_user_id on the specific EDD record or customer being read. This value is passed to ExtendedAssessmentSummaryPolicy().Build(), which returns it as AssessmentSummary if the review status is DRAFT, IN_REVIEW, or APPROVED.
Missing Control: Missing row-level ownership check (c.owner_user_id = $1) in the main SELECT clause of ListReviewMaterials. The EXISTS clause only validates graph-level access, not record-level access.
Impact: An attacker can read the confidential_comment (a protected/restricted field) of EDD records belonging to other users' customers.
Reproduction:
Attacker creates Customer A with entity_hint = "shared_entity".
Victim creates Customer B with entity_hint = "shared_entity" and an EDD record with confidential_comment = "SECRET_VICTIM_DATA" and review_status = "IN_REVIEW".
Attacker calls GET /api/graph/entities/shared_entity/edd-summaries.
Expected Evidence: The JSON response summaries array contains an object where assessment_summary equals "SECRET_VICTIM_DATA".
VULN-02: Insecure Direct Object Reference (IDOR) in Case Duplicate Merge Preview
Affected Path: GET /api/cases/{id}/duplicates/{dup_id}/merge-preview
Handler/Function: httpapi.handleCaseDuplicateMergePreview → casework.Repository.FindDuplicateCandidatesByOwner → casework.Repository.ResolveMatchEvidence
Attacker Input: id (source case ID), dup_id (candidate case ID), authenticated user token.
Source-to-Sink Path: FindDuplicateCandidatesByOwner returns cases matching the dedup_hint without verifying that the requester owns those candidate cases. The handler then passes this unowned candidateCaseID to ResolveMatchEvidence. The SQL query in ResolveMatchEvidence selects cn.body where cn.visibility = 'private' for the candidate case (c.id = $1) without any owner_user_id check. The excerpt is returned in the MatchExplanation field.
Missing Control: Missing ownership validation on the candidate case in both FindDuplicateCandidatesByOwner and ResolveMatchEvidence.
Impact: An attacker can read the full body of private case notes belonging to any case in the system, provided they can obtain its case_id and dedup_hint (which are leaked by the /duplicates endpoint itself).
Reproduction:
Attacker creates Case 1 with dedup_hint = "hint123".
Victim creates Case 2 with dedup_hint = "hint123" and adds a private case note with body = "SECRET_NOTE".
Attacker calls GET /api/cases/1/duplicates. The response candidates array includes Case 2's case_id.
Attacker calls GET /api/cases/1/duplicates/{Case2_ID}/merge-preview.
Expected Evidence: The JSON response candidate.match_explanation contains "SECRET_NOTE".
VULN-03: Cross-Tenant Information Leak via Entity Activity Stream
Affected Path: GET /api/entities/{hint}/activity
Handler/Function: httpapi.handleEntitiesSubtree → audit.Repository.ListEntityActivityByRequester → audit.ActivityHydrator.caseNoteResolver → audit.Repository.ActivityReviewContext
Attacker Input: hint (entity_hint string), authenticated user token.
Source-to-Sink Path: ListEntityActivityByRequester verifies the requester owns a customer with the entity_hint, then fetches audit events for all cases with that entity_hint. When hydrating a case_note event, ActivityReviewContext fetches the cn.body of the note using only cn.id, ca.id, and entity_hint, without verifying that the requester owns the specific case or note.
Missing Control: Missing ownership check (ca.owner_user_id = $requester) in the ActivityReviewContext SQL query.
Impact: An attacker can read the full body of private case notes belonging to other users' cases, as long as they share an entity_hint.
Reproduction:
Attacker creates Customer A with entity_hint = "shared_entity".
Victim creates a Case for Customer B (entity_hint = "shared_entity") and adds a private note with body = "PRIVATE_NOTE_BODY".
Attacker calls GET /api/entities/shared_entity/activity.
Expected Evidence: The activities array in the JSON response contains an item where activity_narrative equals "PRIVATE_NOTE_BODY".
VULN-04: Privilege Escalation / Information Leak via Network Room Artifact Materialization
Affected Path: Background Worker (aml-worker) → GET /api/network/rooms/{id}/dossier
Handler/Function: networkroom.Repository.ProcessDirtyBatch → materializeCandidateArtifactsWithLimit AND networkroom.Repository.ListExtendedDossierCases
Attacker Input: Authenticated user token, room_id.
Source-to-Sink Path: The background worker blindly copies private case notes (cn.visibility = 'private') and confidential_comment from EDD records into the shared network_room_artifacts table for all cases in a network room. Any user who is a participant in the room (which requires owning just one case in the room, validated by JoinRoom) can retrieve these artifacts via /dossier, gaining access to protected fields of cases owned by other users.
Missing Control: The worker does not apply redaction or access control per-artifact when materializing data into a shared space, violating the protectedSourceFields policy defined in classification.
Impact: Protected fields (confidential_comment, private note bodies) are declassified and leaked to other users who share a network room.
Reproduction:
Attacker creates Case A with entity_hint = "X", typology_hint = "Y".
Victim creates Case B with entity_hint = "X", typology_hint = "Y", and adds a private note with body = "SECRET_ROOM_DATA".
The worker processes the dirty candidate, creates a network room, attaches both cases, adds both owners as participants, and materializes the private note into network_room_artifacts.
Attacker calls GET /api/network/rooms/{room_id}/dossier.
Expected Evidence: The JSON response cases array contains an item where context_blocks or evaluation_blocks has content: "SECRET_ROOM_DATA".
VULN-05: Information Leak in Case Export via Linked Case Evidence
Affected Path: POST /api/cases/{id}/exports
Handler/Function: httpapi.handleCreateCaseExport → buildExportBundle → populateExportLinkedCaseData → casework.Repository.ResolveMatchEvidence
Attacker Input: id (case ID), JSON body with allowed_scopes, authenticated user token.
Source-to-Sink Path: When building an export bundle, the system fetches linked cases (which may be owned by other users due to the flaw in FindDuplicateCandidatesByOwner identified in VULN-02) and calls ResolveMatchEvidence. This function leaks private case notes from the linked candidate case into the export's linked_evidence without verifying ownership of the candidate case.
Missing Control: Same root cause as VULN-02; ResolveMatchEvidence lacks an ownership check for the candidate case.
Impact: An attacker exporting their own case can cause the system to include private notes from other users' linked cases in the export bundle.
Reproduction:
Attacker creates Case 1 with dedup_hint = "export_leak".
Victim creates Case 2 with dedup_hint = "export_leak" and a private note with body = "EXPORTED_SECRET".
Attacker calls POST /api/cases/1/exports with {"purpose": "case_review", "allowed_scopes": ["linked_cases"]}.
Expected Evidence: The resulting JSON response bundle.linked_evidence array contains an object with content: "EXPORTED_SECRET" and evidence_excerpt: "EXPORTED_SECRET".
(B) Unresolved Leads
Risk Scoring Heuristic Weakness: internal/risk/scoring.go fingerprintWeight uses a modulo operation on the sum of rune values for non-keyword fingerprints. While deterministic and potentially gameable, it functions as a business-logic heuristic rather than a traditional security vulnerability. No direct exploit path identified.
Export Redaction Map Drift: internal/exporting/redaction.go maintains a local sensitiveExportFields map alongside classification.IsProtectedSourceField. While currently synchronized, this dual-source-of-truth pattern risks future desynchronization. No active exploit identified.
(C) Coverage Ledgers
Entry Point Ledger
POST /api/auth/register: Reviewed, no confirmed finding.
POST /api/auth/login: Reviewed, no confirmed finding.
GET /api/auth/me: Reviewed, no confirmed finding.
POST /api/customers: Reviewed, no confirmed finding.
GET /api/customers/{id}: Reviewed, no confirmed finding.
GET /api/customers/{id}/accounts: Reviewed, no confirmed finding.
POST /api/customers/{id}/accounts: Reviewed, no confirmed finding.
GET /api/customers/{id}/transactions: Reviewed, no confirmed finding.
GET /api/customers/{id}/edd: Reviewed, no confirmed finding.
POST /api/customers/{id}/edd: Reviewed, no confirmed finding (audit redaction works).
PATCH /api/customers/{id}/edd: Reviewed, no confirmed finding (audit redaction works).
GET /api/accounts/{id}: Reviewed, no confirmed finding.
POST /api/transactions: Reviewed, no confirmed finding.
GET /api/transactions/{id}: Reviewed, no confirmed finding.
GET /api/alerts/queue: Reviewed, no confirmed finding.
GET /api/alerts/{id}: Reviewed, no confirmed finding.
POST /api/alerts/{id}/claim: Reviewed, no confirmed finding.
POST /api/alerts/{id}/triage: Reviewed, no confirmed finding.
POST /api/alerts/{id}/case: Reviewed, no confirmed finding.
GET /api/cases/{id}: Reviewed, no confirmed finding.
GET /api/cases/{id}/notes: Reviewed, no confirmed finding.
POST /api/cases/{id}/notes: Reviewed, no confirmed finding (audit redaction works).
PATCH /api/cases/{id}/status: Reviewed, no confirmed finding.
GET /api/cases/{id}/duplicates: Reviewed, no confirmed finding (but enables VULN-02/05).
GET /api/cases/{id}/duplicates/{dup_id}/merge-preview: VULN-02, VULN-05.
GET /api/cases/{id}/timeline: Reviewed, no confirmed finding (audit redaction works).
GET /api/entities/{hint}/activity: VULN-03.
GET /api/graph/entities/{hint}: Reviewed, no confirmed finding.
GET /api/graph/entities/{hint}/related-cases: Reviewed, no confirmed finding.
GET /api/graph/entities/{hint}/edd-summaries: VULN-01.
POST /api/disputes: Reviewed, no confirmed finding.
POST /api/disputes/{id}/export: Reviewed, no confirmed finding (delegates to export handler).
POST /api/cases/{id}/exports: VULN-05.
GET /api/exports/{id}: Reviewed, no confirmed finding (audit redaction works).
GET /api/network/rooms: Reviewed, no confirmed finding.
GET /api/network/rooms/{id}: Reviewed, no confirmed finding.
POST /api/network/rooms/{id}/join: Reviewed, no confirmed finding.
GET /api/network/rooms/{id}/dossier: VULN-04.
Worker: ProcessDirtyBatch: VULN-04.
Sensitive Field / Reader Flow Ledger
password_hash: Source: users. Reader: auth.Repository.FindUserByUsername. Sink: In-memory comparison. Reviewed, no confirmed finding.
token_hash / raw_token: Source: auth.Service. Reader: httpapi.handleLogin/Register. Sink: JSON response. Reviewed, no confirmed finding.
confidential_comment: Source: edd_records. Reader: httpapi.handleCustomerEDD (Owner only, OK). Reader: audit.Repository.Create (Redacted, OK). Reader: graph.Repository.ListReviewMaterials (VULN-01). Reader: networkroom.Repository.materializeCandidateArtifactsWithLimit (VULN-04).
case_note.body: Source: case_notes. Reader: httpapi.handleCaseNotes (Owner only, OK). Reader: audit.Repository.Create (Redacted, OK). Reader: casework.Repository.ResolveMatchEvidence (VULN-02, VULN-05). Reader: audit.Repository.ActivityReviewContext (VULN-03). Reader: networkroom.Repository.materializeCandidateArtifactsWithLimit (VULN-04).
source_of_funds / risk_rationale: Source: edd_records. Reader: httpapi.handleCustomerEDD (Owner only, OK). Reader: audit.Repository.Create (Redacted, OK). Reviewed, no confirmed finding.
File Map Path Ledger
Dockerfile, Makefile, README.md, docker-compose.yml: Reviewed, no confirmed finding.
cmd/aml-api/main.go, cmd/aml-migrate/main.go, cmd/aml-worker/main.go: Reviewed, no confirmed finding.
internal/account/repository.go: Reviewed, no confirmed finding.
internal/alert/repository.go: Reviewed, no confirmed finding.
internal/audit/activity_hydration.go: Reviewed, no confirmed finding.
internal/audit/repository.go: Reviewed, no confirmed finding (redaction logic is sound).
internal/auth/repository.go, internal/auth/service.go: Reviewed, no confirmed finding.
internal/authz/doc.go, internal/authz/principal.go, internal/authz/scope_contract.go: Reviewed, no confirmed finding.
internal/casework/matching_evidence.go: Reviewed, no confirmed finding.
internal/casework/repository.go: VULN-02, VULN-05 (FindDuplicateCandidatesByOwner, ResolveMatchEvidence).
internal/classification/catalog.go, internal/classification/policy_labels.go: Reviewed, no confirmed finding.
internal/config/database.go, internal/config/doc.go: Reviewed, no confirmed finding.
internal/customer/repository.go: Reviewed, no confirmed finding.
internal/db/db.go, internal/db/migrate.go: Reviewed, no confirmed finding.
internal/edd/repository.go: Reviewed, no confirmed finding.
internal/exporting/export_linked_evidence.go, internal/exporting/redaction.go, internal/exporting/repository.go: Reviewed, no confirmed finding (redaction logic is sound).
internal/graph/assessment_summary.go: Reviewed, no confirmed finding.
internal/graph/repository.go: VULN-01 (ListReviewMaterials).
internal/graph/repository_entity_summaries.go: Reviewed, no confirmed finding.
internal/httpapi/activity_views.go, internal/httpapi/dedup_merge_preview.go, internal/httpapi/doc.go, internal/httpapi/entity_review_summaries.go, internal/httpapi/export_linked_cases.go, internal/httpapi/network_room_context.go, internal/httpapi/server.go: VULN-01, VULN-02, VULN-03, VULN-04, VULN-05 (handler orchestration of flawed repository methods).
internal/logging/doc.go: Reviewed, no confirmed finding.
internal/networkroom/dossier_context.go, internal/networkroom/lifecycle.go, internal/networkroom/repository.go, internal/networkroom/repository_context.go: VULN-04 (materializeCandidateArtifactsWithLimit).
internal/projection/contracts.go: Reviewed, no confirmed finding.
internal/risk/scoring.go: Reviewed, no confirmed finding.
internal/transaction/repository.go: Reviewed, no confirmed finding.
migrations/000001_create_users_sessions.sql through migrations/000011_network_room_dirty_candidates.sql: Reviewed, no confirmed finding (schema constraints are correctly defined; flaws are in query logic).
