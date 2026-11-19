Attack Surface & Vulnerability Analysis
1. Sensitive Data Exposure via Entity Graph (IDOR / Information Leak)
Route: GET /api/graph/entities/{hint}/edd-summaries
Resource: edd_records.confidential_comment
Gate: graph.HasEntityAccess (Checks if requester owns any customer with the matching entity_hint).
Evidence:
In internal/graph/repository_entity_summaries.go, ListReviewMaterials executes a raw SQL query selecting er.confidential_comment aliased as analyst_narrative.
The query only filters by entity_hint and ownership of a customer with that hint, not the specific customer associated with the EDD record.
In internal/httpapi/entity_review_summaries.go, this narrative is passed to AssessmentSummaryPolicy.Build.
In internal/graph/assessment_summary.go, ExtendedAssessmentSummaryPolicy returns the AnalystNarrative (the confidential comment) directly if the status is detailed.
Impact: An analyst owning Customer A can read the confidential EDD comments of Customer B if they share the same entity_hint (e.g., a shared beneficial owner or corporate group identifier), bypassing direct customer ownership checks.
2. Sensitive Data Exposure in Case Deduplication (Information Leak)
Route: GET /api/cases/{id}/duplicates/{cid}/merge-preview
Resource: case_notes.body (Private Notes)
Gate: cases.FindDuplicateCandidatesByOwner (Checks source case ownership).
Evidence:
In internal/casework/repository.go, ResolveMatchEvidence queries case_notes for the candidate case.
It specifically filters for visibility = 'private'.
It joins on dedup_hint but does not verify that the requester (ownerUserID) owns the candidate case or has permission to view its private notes.
The body is returned in CaseSimilarityEvidence.Excerpt and serialized into MatchExplanation.
Impact: An analyst can read private investigation notes from another analyst's case if they share a dedup_hint, facilitating intelligence gathering across tenant/analyst boundaries.
3. Sensitive Data Exposure in Network Room Artifacts (Worker Side-Channel)
Entry Point: aml-worker (Background Job)
Resource: case_notes.body and edd_records.confidential_comment
Gate: None (Automated processing based on entity_hint/typology_hint clustering).
Evidence:
In internal/networkroom/lifecycle.go, materializeCandidateArtifactsWithLimit selects cn.body and er.confidential_comment from cases linked by dedup_hint/entity_hint.
These are stored in network_room_artifacts.content.
In internal/httpapi/network_room_context.go, ListExtendedDossierCases retrieves these artifacts.
While BuildExtendedDossier filters context blocks for non-owned cases, it relies on the OwnedByRequester flag. If an attacker can influence clustering (via entity_hint), they may induce the worker to materialize sensitive data into a room they can join or view.
Impact: Automated leakage of private notes and confidential EDD comments into shared network rooms without explicit per-record authorization at the time of materialization.
4. Missing Authorization on Export Disputes (IDOR)
Route: POST /api/disputes/{id}/export
Resource: cases (via dispute.case_id)
Gate: exports.GetDisputeByOwner (Checks dispute ownership).
Evidence:
In internal/httpapi/server.go, handleDisputesSubtree retrieves the dispute and then calls handleCreateCaseExport with dispute.CaseID.
handleCreateCaseExport calls buildExportBundle, which calls s.cases.GetByOwner(ctx, user.ID, caseID).
Mitigation Present: The code does call GetByOwner inside buildExportBundle, which enforces case ownership. This path appears secure against IDOR because the export builder re-validates the case owner against the authenticated user. Marked as Reviewed without Candidate.
5. Reflection/XSS in Activity Narratives
Route: GET /api/entities/{hint}/activity
Resource: case_notes.body (via ActivityReviewContext)
Gate: audit.ListEntityActivityByRequester (Entity ownership check).
Evidence:
In internal/audit/activity_hydration.go, caseNoteResolver fetches the note body via ActivityReviewContext.
The body is returned as ActivityNarrative.Narrative.
In internal/httpapi/server.go, entityActivityView serializes this into ActivityText.
Impact: If case_notes.body contains script tags, they are reflected in the JSON response. While JSON itself is safe, if the frontend improperly renders ActivityText as HTML, it leads to XSS. Given the "CTF" context, this is a likely intended vector for Stored XSS if the UI is vulnerable.
6. Enumeration via Error Messages
Route: POST /api/auth/login
Resource: User Existence
Gate: None.
Evidence:
In internal/auth/service.go, Login returns ErrInvalidCredentials for both "user not found" and "wrong password".
Mitigation Present: The service correctly maps both errors to the same generic error. Marked as Reviewed without Candidate.
7. SQL Injection in Dynamic Column Selection
Route: GET /api/graph/entities/{hint}/edd-summaries
Resource: edd_records table
Gate: graph.HasEntityAccess.
Evidence:
In internal/graph/repository_entity_summaries.go, ListReviewMaterials uses fmt.Sprintf to inject the result of analystNarrativeColumn() into the SQL query string.
analystNarrativeColumn() returns "conf" + "idential_comment".
Mitigation Present: The column name is hardcoded in the Go source and not derived from user input. Marked as Reviewed without Candidate.
Summary of Candidates
IDOR/Info Leak: GET /api/graph/entities/{hint}/edd-summaries exposes confidential_comment across shared entity hints.
IDOR/Info Leak: GET /api/cases/{id}/duplicates/{cid}/merge-preview exposes private case_notes.body from unowned candidate cases.
Worker Side-Channel: aml-worker materializes confidential_comment and case_notes.body into network_room_artifacts without per-record ACLs, potentially exposing them via Network Room dossiers.
RECEIVED-bf9d1c01f62c
