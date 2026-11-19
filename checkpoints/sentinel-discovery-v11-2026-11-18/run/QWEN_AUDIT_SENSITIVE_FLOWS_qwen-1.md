Source-to-Sink Trace: Sensitive Fields
1. edd_records.confidential_comment
Source: migrations/000004_create_edd_records.sql (Table definition, NOT NULL).
Write Path: internal/httpapi/server.go -> handleCustomerEDD (POST/PATCH) -> edd.Create/UpdateByOwnerCustomer.
Gate: owner_user_id check in SQL WHERE clause.
Read Path A (Direct Owner Access):
internal/httpapi/server.go -> handleCustomerEDD (GET) -> edd.GetByOwnerCustomer.
Sink: EDDOwnerView.ConfidentialComment -> JSON Response.
Status: Reviewed without Candidate (Authorized owner access).
Read Path B (Entity Graph Leak):
internal/httpapi/server.go -> handleGraphEDDSummaries -> graphEDDSummariesResponseForEntityReview.
internal/graph/repository_entity_summaries.go -> ListReviewMaterials.
SQL: SELECT ... er.confidential_comment AS analyst_narrative ... WHERE lower(btrim(c.entity_hint)) = $2 AND EXISTS (SELECT 1 FROM customers owned WHERE owned.owner_user_id = $1 AND lower(btrim(owned.entity_hint)) = $2).
Policy Check: Checks if requester owns any customer with the same entity_hint. Does not check if requester owns the specific customer associated with the EDD record.
Sink: ReviewMaterial.AnalystNarrative -> AssessmentSummaryPolicy.Build -> entityReviewEDDGraphSummaryView.AssessmentSummary -> JSON Response.
Status: Candidate Finding (Cross-customer leakage via shared entity hint).
Read Path C (Worker Materialization):
cmd/aml-worker/main.go -> networkroom.ProcessDirtyBatch -> materializeCandidateArtifactsWithLimit.
SQL: SELECT ... er.confidential_comment ... FROM cases ca JOIN edd_records er ON er.customer_id = ca.customer_id WHERE ca.id = $1.
Policy Check: None at read time. Relies on dirty candidate clustering logic.
Sink: network_room_artifacts.content (DB).
Subsequent Read: internal/networkroom/repository_context.go -> ListExtendedDossierCases -> DossierEvaluationBlock.Content.
Final Sink: internal/httpapi/network_room_context.go -> networkRoomDetailDossierView -> JSON Response.
Mitigation: BuildExtendedDossier filters EvaluationBlocks for non-owned cases? No, it only filters ContextBlocks and EvaluationBlocks if !summary.OwnedByRequester. Wait, BuildExtendedDossier sets ScopeCoverageComplete = false if blocks exist for non-owned cases, but it still includes the blocks in the response (summary.EvaluationBlocks = boundedEvaluationBlocks(...)).
Status: Candidate Finding (Leakage into shared network rooms).
2. case_notes.body
Source: migrations/000003_create_alerts_cases_notes.sql (Table definition, visibility check).
Write Path: internal/httpapi/server.go -> handleCaseNotes (POST) -> casework.CreateNote.
Gate: owner_user_id check in SQL.
Read Path A (Direct Owner Access):
internal/httpapi/server.go -> handleCaseNotes (GET) -> casework.ListNotesByOwner.
Sink: CaseNoteResponse.Body -> JSON Response.
Status: Reviewed without Candidate (Authorized owner access).
Read Path B (Dedup Merge Preview Leak):
internal/httpapi/server.go -> handleCaseDuplicateMergePreview -> casework.ResolveMatchEvidence.
SQL: SELECT cn.body ... FROM cases c JOIN case_notes cn ON cn.case_id = c.id WHERE c.id = $1 AND c.dedup_hint = $2 AND cn.visibility = 'private'.
Policy Check: Checks ownership of the source case (request.OwnerUserID). Does not check ownership of the candidate case (request.CandidateCaseID) from which the notes are retrieved.
Sink: CaseSimilarityEvidence.Excerpt -> MatchExplanationBuilder.Build -> CaseDuplicateMergePreviewResponse.MatchExplanation -> JSON Response.
Status: Candidate Finding (Cross-analyst private note leakage).
Read Path C (Worker Materialization):
cmd/aml-worker/main.go -> materializeCandidateArtifactsWithLimit.
SQL: SELECT ... cn.body ... FROM cases ca JOIN case_notes cn ON cn.case_id = ca.id WHERE ca.id = $1 AND cn.visibility = 'private'.
Sink: network_room_artifacts.content (DB) -> DossierContextBlock.Content -> JSON Dossier.
Status: Candidate Finding (Same as EDD comment worker leak).
Read Path D (Activity Stream):
internal/httpapi/server.go -> handleEntitiesSubtree -> entityActivityViewsForActivityStream.
internal/audit/activity_hydration.go -> caseNoteResolver -> ActivityReviewContext.
SQL: SELECT cn.body ... FROM case_notes cn JOIN cases ca ... WHERE cn.id = $1 AND ca.id = $2 AND lower(btrim(c.entity_hint)) = $3.
Policy Check: ListEntityActivityByRequester already verified entity ownership.
Sink: ActivityNarrative.Narrative -> EntityActivityView.ActivityText -> JSON Response.
Status: Reviewed without Candidate (Controlled by entity ownership gate, though broad).
3. users.password_hash & sessions.token_hash
Source: migrations/000001_create_users_sessions.sql.
Read Path: internal/auth/service.go -> Login / CurrentUser.
Sink: Memory comparison (bcrypt.CompareHashAndPassword, subtle.ConstantTimeCompare).
Status: Reviewed without Candidate (Not exposed in responses/logs).
4. audit_events.diff_json
Source: internal/audit/repository.go -> Create (via RedactedDiffJSON).
Policy: IsRestrictedField checks against restrictedDiffFields (e.g., confidential_comment, body).
Read Path: internal/httpapi/server.go -> caseAuditChangeResponses.
Sink: CaseAuditChangeResponse. If Redacted is true, field name is replaced with "restricted_field". Values are omitted/replaced.
Status: Reviewed without Candidate (Properly redacted).
5. transactions.counterparty_fingerprint
Source: migrations/000002_create_customers_accounts_transactions.sql.
Read Path: internal/risk/scoring.go -> Score.
Sink: Memory (Scoring logic).
Read Path: internal/httpapi/server.go -> transactionResponse.
Sink: TransactionResponse.CounterpartyFingerprint -> JSON Response.
Gate: GetByOwner ensures transaction belongs to user.
Status: Reviewed without Candidate (Authorized owner access).
Candidate Findings Summary
EDD Confidential Comment Leak via Entity Graph: GET /api/graph/entities/{hint}/edd-summaries allows reading confidential_comment from any customer sharing an entity_hint with the requester, bypassing direct customer ownership.
Path: httpapi.handleGraphEDDSummaries -> graph.ListReviewMaterials -> SQL selects confidential_comment -> AssessmentSummaryPolicy.Build -> JSON.
Private Case Note Leak via Dedup Preview: GET /api/cases/{id}/duplicates/{cid}/merge-preview allows reading private case notes from candidate cases not owned by the requester.
Path: httpapi.handleCaseDuplicateMergePreview -> casework.ResolveMatchEvidence -> SQL selects cn.body where visibility='private' without candidate ownership check -> JSON.
Sensitive Data Materialization in Network Rooms: The aml-worker automatically copies confidential_comment and private case notes into network_room_artifacts based on clustering hints. These artifacts are then exposed in Network Room dossiers to participants who may not own the source records.
Path: worker.materializeCandidateArtifactsWithLimit -> DB network_room_artifacts -> networkroom.ListExtendedDossierCases -> httpapi.networkRoomDossierResponseForSharedRoom -> JSON.
RECEIVED-0fb317ce0cd2
