(A) Confirmed Findings
Finding 1: Cross-Customer Leakage of EDD Confidential Comments via Entity Graph
Title: IDOR — confidential_comment exposed through shared entity_hint in entity graph EDD summaries
Affected path: GET /api/graph/entities/{hint}/edd-summaries → httpapi.handleGraphEDDSummaries → httpapi.graphEDDSummariesResponseForEntityReview → graph.ListReviewEDDSummaries → graph.ListReviewMaterials → graph.AssessmentSummaryPolicy.Build (Extended) → entityReviewEDDGraphSummaryView.AssessmentSummary
Attacker-controlled input: URL path {hint} (entity_hint); requires authenticated analyst who owns at least one customer with that hint.
Source → sink: edd_records.confidential_comment (schema migrations/000004) → SQL SELECT ... er.confidential_comment AS analyst_narrative ... in internal/graph/repository_entity_summaries.go:ListReviewMaterials → ReviewMaterial.AnalystNarrative → ExtendedAssessmentSummaryPolicy.Build returns material.AnalystNarrative directly when isDetailedReviewStatus → serialized as AssessmentSummary in JSON response.
Violated invariant: confidential_comment must be readable only by the analyst who owns the specific customer of the EDD record.
Failing branch/argument: The WHERE clause in ListReviewMaterials filters only on lower(btrim(c.entity_hint)) = $2 plus EXISTS (SELECT 1 FROM customers owned WHERE owned.owner_user_id = $1 AND lower(btrim(owned.entity_hint)) = $2). There is no predicate tying the returned er.customer_id to the requester's owned customer. ExtendedAssessmentSummaryPolicy unconditionally returns the narrative when review status is DRAFT/IN_REVIEW/APPROVED.
Why other controls don't stop it: graph.HasEntityAccess (called earlier in handleGraphEntitiesSubtree) only confirms the requester owns some customer with the hint — it does not authorize per-record access to EDD fields. BuildSafeDossier/BuildExtendedDossier filtering is not in this path.
Impact: Any analyst can read another analyst's EDD confidential comments (source-of-funds narratives, risk rationale commentary) for any customer sharing an entity_hint — a common pattern for corporate groups, shared beneficial owners, or clustered entities.
Minimal reproduction:
Attacker registers, creates customer C_A with entity_hint = "group-acme".
Victim registers, creates customer C_V with entity_hint = "group-acme", creates EDD record with confidential_comment = "SECRET-RATIONALE-XYZ", status IN_REVIEW.
Attacker GET /api/graph/entities/group-acme/edd-summaries → response summaries[].assessment_summary == "SECRET-RATIONALE-XYZ".
Finding 2: Cross-Analyst Leakage of Private Case Notes via Duplicate Merge Preview
Title: IDOR — private case note bodies exposed through duplicate merge preview without candidate-case ownership check
Affected path: GET /api/cases/{sourceId}/duplicates/{candidateId}/merge-preview → httpapi.handleCaseDuplicateMergePreview → casework.FindDuplicateCandidatesByOwner (verifies source ownership only) → casework.ResolveMatchEvidence → SQL on case_notes → httpapi.caseDuplicateMergePreviewResponse → casework.MatchExplanationBuilder.Build → JSON match_explanation.
Attacker-controlled input: URL path {sourceId} (must be owned) and {candidateId} (need not be owned); attacker sets dedup_hint on their own case to match victim's case.
Source → sink: case_notes.body where visibility = 'private' → SQL in internal/casework/repository.go:ResolveMatchEvidence:
  SELECT cn.id, cn.case_id, ..., cn.body, ...
  FROM cases c JOIN case_notes cn ON cn.case_id = c.id
  WHERE c.id = $1 AND c.dedup_hint = $2 AND cn.visibility = 'private'
with $1 = request.CandidateCaseID, $2 = source case dedup_hint. The function first verifies ownership of the source case only, never the candidate. Body flows into CaseSimilarityEvidence.Excerpt (weight 90, source review_context_excerpt) → MatchExplanationBuilder.Build prefers MatchEvidenceSourceReviewContext → returned as match_explanation.
Violated invariant: Private case note bodies must be readable only by the case owner (and author).
Failing branch/argument: ResolveMatchEvidence takes MatchEvidenceRequest{OwnerUserID, SourceCaseID, CandidateCaseID} and only validates OwnerUserID against SourceCaseID. The case_notes query joins on c.dedup_hint with no ownership predicate for the candidate. MatchExplanationBuilder prioritizes ReviewContext excerpts, so the leaked body is the one actually returned.
Why other controls don't stop it: FindDuplicateCandidatesByOwner is called first and returns only candidates sharing the source's dedup_hint, but it does not gate the subsequent ResolveMatchEvidence on candidate ownership. The HTTP handler iterates the candidate list and calls the resolver for any match.
Impact: An analyst can exfiltrate another analyst's private investigation notes by creating a case with a matching dedup_hint (user-controlled at POST /api/alerts/{id}/case).
Minimal reproduction:
Victim creates case V with dedup_hint = "tx-abc123", adds private note "VICTIM-SECRET-ANALYSIS".
Attacker creates case A with dedup_hint = "tx-abc123".
Attacker GET /api/cases/A/duplicates/V/merge-preview → response candidate.match_explanation == "VICTIM-SECRET-ANALYSIS".
Finding 3: Worker-Materialized Confidential Comments and Private Notes Leaked via Network Room Dossiers
Title: Confused-deputy / missing per-record ACL — aml-worker copies confidential_comment and private note bodies into network_room_artifacts, which are then served to any room participant regardless of source-case ownership
Affected path (write): cmd/aml-worker/main.go:run → networkroom.ProcessDirtyBatch → processDirtyCandidate → materializeCandidateArtifactsWithLimit → SQL UNION selecting cn.body and er.confidential_comment → MaterializeArtifact → network_room_artifacts.content.
Affected path (read): GET /api/network/rooms/{id}/dossier → httpapi.networkRoomDossierResponseForSharedRoom → networkroom.ListExtendedDossierCases (reads artifacts) → networkroom.BuildExtendedDossier → JSON cases[].context_blocks[].content and cases[].evaluation_blocks[].content.
Attacker-controlled input: Attacker must be a room participant (joined via POST /api/network/rooms/{id}/join, which is gated on owning any case in the room). Attacker does not need to own the specific source case whose notes/comments were materialized.
Source → sink (write): internal/networkroom/lifecycle.go:materializeCandidateArtifactsWithLimit SQL:
  SELECT ca.id, ca.customer_id, 'room_context', 'collaboration_context', $2, cn.body
  FROM cases ca JOIN case_notes cn ON cn.case_id = ca.id
  WHERE ca.id = $1 AND cn.visibility = 'private' AND btrim(cn.body) <> ''
  UNION ALL
  SELECT ca.id, ca.customer_id, 'assessment_summary', 'evaluation_summary', $2, er.confidential_comment
  FROM cases ca JOIN edd_records er ON er.customer_id = ca.customer_id
  WHERE ca.id = $1 AND btrim(er.confidential_comment) <> ''
Stored with coverage_policy = classification.RoomCoverageSourceMaterial ("source_scope").
Source → sink (read): internal/networkroom/repository_context.go:ListExtendedDossierCases returns all artifacts for the room to any participant. internal/networkroom/dossier_context.go:BuildExtendedDossier for non-owned cases calls boundedContextBlocks / boundedEvaluationBlocks, which only trim/validate — they do not filter out source_scope/sensitive content. The blocks are assigned to summary.ContextBlocks / summary.EvaluationBlocks and serialized.
Violated invariant: private case notes and confidential_comment must not be exposed to analysts who do not own the source record, even inside a shared network room.
Failing branch/argument: BuildExtendedDossier branch if !summary.OwnedByRequester still populates the blocks (summary.ContextBlocks = boundedContextBlocks(c.ContextBlocks)); it only flips ScopeCoverageComplete = false when blocks are non-empty. No filter on CoveragePolicy or content sensitivity.
Why other controls don't stop it: JoinRoom gates on owning any case in the room, not the specific case whose artifacts are being read. ListExtendedDossierCases has no per-artifact ownership filter. boundedContextBlocks/boundedEvaluationBlocks do not consult the coverage policy.
Impact: Any room participant can read private notes and confidential EDD comments from any other participant's case that the worker happened to cluster into the room.
Minimal reproduction:
Victim owns case V in room R, adds private note "VICTIM-NOTE" and EDD confidential_comment "VICTIM-EDD".
Worker processes dirty candidate covering V's entity/typology, materializes both into network_room_artifacts.
Attacker joins room R (owning any other case in R).
Attacker GET /api/network/rooms/R/dossier → response includes cases[?].context_blocks[].content == "VICTIM-NOTE" and cases[?].evaluation_blocks[].content == "VICTIM-EDD".
Finding 4: Export Bundle Persists Private Notes from Linked Cases as "Matching Evidence"
Title: IDOR via export — linked-case private note bodies are persisted into exports.bundle_json / export_items.payload_json and retrievable via GET /api/exports/{id}
Affected path: POST /api/cases/{sourceId}/exports → httpapi.handleCreateCaseExport → httpapi.buildExportBundle → httpapi.populateExportLinkedCaseData → casework.ResolveMatchEvidence (same as Finding 2) → exporting.appendExportLinkedCaseData → exporting.ExportItemBuilder.Build → exporting.CreateExport + CreateExportItem → persisted bundle_json/payload_json. Read: GET /api/exports/{id} → httpapi.handleExportsSubtree → decodeExportBundle → JSON bundle.linked_evidence[].content / evidence_excerpt.
Attacker-controlled input: POST body allowed_scopes must include linked_cases; attacker controls dedup_hint on source case.
Source → sink: Same SQL in ResolveMatchEvidence as Finding 2. In populateExportLinkedCaseData (internal/httpapi/export_linked_cases.go), each evidence item with source MatchEvidenceSourceReviewContext is appended as ExportSourceMaterial{ItemType: "case_matching_evidence", SourceClass: "review_context_excerpt", Content: item.Excerpt, EvidenceExcerpt: item.Excerpt, CoveragePolicy: ExportScopeRootCaseDetail}. appendExportLinkedCaseData (internal/exporting/export_linked_evidence.go) forwards to ExportItemBuilder.Build, whose allows returns true because CoveragePolicy == ExportScopeRootCaseDetail matches the root traversal scope. The material is serialized into bundle.LinkedEvidence and also persisted row-by-row via CreateExportItem with payload_json.
Violated invariant: Private note bodies from a candidate case must not be persisted into another analyst's export bundle.
Failing branch/argument: ExportItemBuilder.allows only checks CoveragePolicy against the traversal scope; it does not re-verify that the source record is owned by the requester. ExportScopeRootCaseDetail is the root scope, but the material originated from a linked case — the policy is applied to the wrong record.
Why other controls don't stop it: buildExportBundle verifies root-case ownership but never re-checks ownership of each linked case before calling populateExportLinkedCaseData. BuildBundle sorts and emits LinkedEvidence without filtering by source ownership. The stored export_items rows inherit the same content.
Impact: Private investigation notes are durably persisted in the exports subsystem and retrievable any time before expires_at, widening the exposure window beyond the live merge-preview request.
Minimal reproduction:
Victim creates case V with dedup_hint = "shared", private note "VICTIM-SECRET".
Attacker creates case A with dedup_hint = "shared".
Attacker POST /api/cases/A/exports body {"purpose":"case_review","allowed_scopes":["root_case","linked_cases"]} → response bundle.linked_evidence[].content == "VICTIM-SECRET".
Attacker GET /api/exports/{id} → same content returned from persisted bundle_json.
Finding 5: Activity Stream Escalates to collaborator_detail and Exposes Private Note Bodies on the Basis of Entity-Hint Co-Ownership Alone
Title: Policy-direction error — ActivityDetailCollaborator is granted on the basis of a redacted-field change in the audit diff, not on actual case collaboration; private note body is then fetched and returned
Affected path: GET /api/entities/{hint}/activity → httpapi.handleEntitiesSubtree → audit.ListEntityActivityByRequester (entity-hint ownership gate) → httpapi.entityActivityViewsForActivityStream → httpapi.entityActivityViewsWithDetail with detail-selector:
  if event.ObjectType == "case_note" && hasControlledActivityChange(event.DiffJSON) {
      return auditrepo.ActivityDetailCollaborator
  }
→ audit.ActivityHydrator.Hydrate → caseNoteResolver → audit.ActivityReviewContext → SQL SELECT cn.body FROM case_notes cn JOIN cases ca ... WHERE cn.id = $1 AND ca.id = $2 AND lower(btrim(c.entity_hint)) = $3 → ActivityNarrative.Narrative → EntityActivityView.ActivityText.
Attacker-controlled input: URL path {hint}; attacker must own any customer with that hint.
Source → sink: case_notes.body → ActivityReviewContext (SQL filters only on entity_hint, not case ownership) → ActivityNarrative.Narrative → EntityActivityView.ActivityText in JSON.
Violated invariant: Private note bodies must not be returned to analysts who are not collaborators on the specific case.
Failing branch/argument: The detail-level selector in entityActivityViewsForActivityStream promotes to ActivityDetailCollaborator based solely on hasControlledActivityChange (presence of any redacted field in the audit diff). The audience remains ActivityAudienceRelatedEntity, but caseNoteResolver only checks req.DetailLevel == ActivityDetailCollaborator — it ignores audience. ActivityReviewContext SQL has no case-ownership predicate.
Why other controls don't stop it: ListEntityActivityByRequester gates on entity-hint ownership, which is the same over-broad gate as Finding 1. The audience/detail-level contract in internal/audit/activity_hydration.go is not enforced against actual collaboration.
Impact: An analyst co-owning an entity hint can read private note bodies of cases they do not own, via the activity stream, whenever a case-note audit event has a redacted-field change.
Minimal reproduction:
Victim owns customer C_V with entity_hint = "group-acme", case V, updates a case note with a redacted field change.
Attacker owns customer C_A with entity_hint = "group-acme".
Attacker GET /api/entities/group-acme/activity → response activities[?].activity_narrative == "<victim's private note body>" and activity_detail_level == "collaborator_detail".
(B) Unresolved Leads
Projection contract enforcement gap: internal/projection/contracts.go defines Contract.AllowedJSONFields for owner and side views, but no caller in the supplied source enforces these allowlists at serialization time. Marked unconfirmed because an external component (gateway, middleware, or UI-layer contract check) could enforce them; within the supplied tree there is no sink that reads AllowedJSONFields.
Audit diff plaintext for source_of_funds / risk_rationale: These fields are in exporting.sensitiveExportFields but not in audit.restrictedDiffFields, so they are stored as plaintext in audit_events.diff_json and returned as plaintext in GET /api/cases/{id}/timeline. The timeline endpoint is gated on case ownership, and the case owner is the EDD owner, so this appears authorized — but it is an inconsistency with the export redaction policy. Unconfirmed as a vulnerability because no cross-user sink was identified.
Dormant linkedCaseExportAvailable / auditActivityViewsAvailable / caseMatchPreviewAvailable / networkRoomContextAvailable / entityReviewSummariesAvailable flags: These functions return true unconditionally and are not consulted by any caller in the supplied source. No security impact observed.
(C) Coverage Ledgers
Entry-point ledger (one row per route/entry, with finding IDs or "reviewed, no confirmed finding"):
POST /api/auth/register — reviewed, no confirmed finding (generic auth errors, no enumeration).
POST /api/auth/login — reviewed, no confirmed finding.
GET /api/auth/me — reviewed, no confirmed finding.
POST /api/customers — reviewed, no confirmed finding (owner bound by principal).
GET /api/customers/{id} — reviewed, no confirmed finding (GetByOwner).
GET /api/customers/{id}/accounts — reviewed, no confirmed finding.
POST /api/customers/{id}/accounts — reviewed, no confirmed finding.
GET /api/customers/{id}/transactions — reviewed, no confirmed finding.
GET /api/customers/{id}/edd — reviewed, no confirmed finding (owner-only).
POST /api/customers/{id}/edd — reviewed, no confirmed finding.
PATCH /api/customers/{id}/edd — reviewed, no confirmed finding.
GET /api/accounts/{id} — reviewed, no confirmed finding.
POST /api/transactions — reviewed, no confirmed finding.
GET /api/transactions/{id} — reviewed, no confirmed finding.
GET /api/alerts/queue — reviewed, no confirmed finding.
GET /api/alerts/{id} — reviewed, no confirmed finding.
POST /api/alerts/{id}/claim — reviewed, no confirmed finding (AssignedUserID == OwnerUserID enforced).
POST /api/alerts/{id}/triage — reviewed, no confirmed finding.
POST /api/alerts/{id}/case — reviewed, no confirmed finding (case ownership bound to alert owner).
GET /api/cases/{id} — reviewed, no confirmed finding.
GET /api/cases/{id}/notes — reviewed, no confirmed finding.
POST /api/cases/{id}/notes — reviewed, no confirmed finding.
PATCH /api/cases/{id}/status — reviewed, no confirmed finding.
GET /api/cases/{id}/duplicates — reviewed, no confirmed finding (returns only public preview fields).
GET /api/cases/{id}/duplicates/{cid}/merge-preview — Finding 2, Finding 4.
GET /api/cases/{id}/timeline — reviewed, no confirmed finding (owner-gated; see unresolved lead on plaintext EDD fields).
POST /api/cases/{id}/exports — Finding 4.
GET /api/cases/{id}/exports (not routed; exports are under /api/exports/{id}) — n/a.
GET /api/exports/{id} — Finding 4 (read side of persisted leak).
POST /api/disputes — reviewed, no confirmed finding.
POST /api/disputes/{id}/export — reviewed, no confirmed finding (re-routes through handleCreateCaseExport which re-verifies case ownership via buildExportBundle; the linked-case leak in Finding 4 still applies through this entry).
GET /api/entities/{hint}/activity — Finding 5.
GET /api/graph/entities/{hint} — reviewed, no confirmed finding (aggregates only).
GET /api/graph/entities/{hint}/related-cases — reviewed, no confirmed finding (public case fields only).
GET /api/graph/entities/{hint}/edd-summaries — Finding 1.
GET /api/network/rooms — reviewed, no confirmed finding.
GET /api/network/rooms/{id} — reviewed, no confirmed finding.
POST /api/network/rooms/{id}/join — reviewed, no confirmed finding (gated on owning a case in the room).
GET /api/network/rooms/{id}/dossier — Finding 3.
GET /healthz, GET /readyz — reviewed, no confirmed finding (static).
aml-migrate CLI — reviewed, no confirmed finding.
aml-worker background loop — Finding 3 (write side).
Sensitive-field / reader ledger:
users.password_hash → auth.FindUserByUsername → bcrypt.CompareHashAndPassword (memory only). Reviewed, no confirmed finding.
sessions.token_hash → auth.FindSessionByTokenHash → constant-time compare (memory only). Reviewed, no confirmed finding.
auth.RawToken → returned once at register/login over JSON/TLS. Reviewed, no confirmed finding.
edd_records.confidential_comment → readers: handleCustomerEDD (owner, OK); graph.ListReviewMaterials (Finding 1); materializeCandidateArtifactsWithLimit (Finding 3).
edd_records.source_of_funds, edd_records.risk_rationale → readers: handleCustomerEDD (owner, OK); graph.ListReviewMaterials (included in ReviewMaterial.RiskSummary fallback path — lower priority than AnalystNarrative); audit diff stored plaintext (unresolved lead).
case_notes.body (visibility=private) → readers: handleCaseNotes (owner, OK); casework.ResolveMatchEvidence (Finding 2, Finding 4); materializeCandidateArtifactsWithLimit (Finding 3); audit.ActivityReviewContext (Finding 5).
audit_events.diff_json → readers: caseAuditChangeResponses (redacts restrictedDiffFields), exporting.safeAuditSummary (redacts sensitiveExportFields), exportAuditChanges (passes raw values into AuditChangeSnapshot but ExportAuditSummary emits only field names). Reviewed, no confirmed finding for the export path; unresolved lead for timeline plaintext of source_of_funds/risk_rationale.
transactions.counterparty_fingerprint → readers: risk.Score (memory), transactionResponse (owner-gated). Reviewed, no confirmed finding.
customers.entity_hint → used as access-control key in graph/audit/network-room paths; user-controlled at customer creation. Findings 1, 3, 5 rely on this over-broad gate.
File-map ledger (every file marked reviewed):
Dockerfile, Makefile, README.md, docker-compose.yml — reviewed, no confirmed finding.
cmd/aml-api/main.go, cmd/aml-migrate/main.go, cmd/aml-worker/main.go — reviewed; worker is the write side of Finding 3.
internal/account/repository.go, internal/alert/repository.go, internal/auth/repository.go, internal/auth/service.go, internal/customer/repository.go, internal/transaction/repository.go, internal/edd/repository.go — reviewed, no confirmed finding (owner-gated SQL).
internal/audit/repository.go — reviewed, no confirmed finding; unresolved lead on restrictedDiffFields vs sensitiveExportFields mismatch.
internal/audit/activity_hydration.go — Finding 5.
internal/authz/doc.go, internal/authz/principal.go, internal/authz/scope_contract.go — reviewed, no confirmed finding (contracts are declarative; not enforced in code).
internal/casework/matching_evidence.go — reviewed, no confirmed finding (pure builder).
internal/casework/repository.go — Finding 2, Finding 4 (via ResolveMatchEvidence).
internal/classification/catalog.go, internal/classification/policy_labels.go — reviewed, no confirmed finding.
internal/config/database.go, internal/config/doc.go — reviewed, no confirmed finding.
internal/db/db.go, internal/db/migrate.go — reviewed, no confirmed finding.
internal/exporting/export_linked_evidence.go — Finding 4.
internal/exporting/redaction.go, internal/exporting/repository.go — reviewed, no confirmed finding.
internal/graph/assessment_summary.go — Finding 1.
internal/graph/repository.go — reviewed, no confirmed finding.
internal/graph/repository_entity_summaries.go — Finding 1.
internal/httpapi/activity_views.go — Finding 5.
internal/httpapi/dedup_merge_preview.go — Finding 2.
internal/httpapi/doc.go — reviewed, no confirmed finding.
internal/httpapi/entity_review_summaries.go — Finding 1.
internal/httpapi/export_linked_cases.go — Finding 4.
internal/httpapi/network_room_context.go — Finding 3.
internal/httpapi/server.go — routes into Findings 1, 2, 3, 4, 5; all other routes reviewed, no confirmed finding.
internal/logging/doc.go — reviewed, no confirmed finding.
internal/networkroom/dossier_context.go — Finding 3.
internal/networkroom/lifecycle.go — Finding 3.
internal/networkroom/repository.go — reviewed, no confirmed finding.
internal/networkroom/repository_context.go — Finding 3.
internal/projection/contracts.go — reviewed; unresolved lead (allowlists not enforced in supplied source).
internal/risk/scoring.go — reviewed, no confirmed finding.
migrations/000001 through 000011 — reviewed, no confirmed finding (schema only).
RECEIVED-dc0edce2298e
