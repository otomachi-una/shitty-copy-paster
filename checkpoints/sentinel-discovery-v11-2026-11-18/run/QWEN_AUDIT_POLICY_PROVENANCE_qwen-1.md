Policy and Object-Provenance Pass
1. Network Room Artifact Coverage Policy Bypass
Invariant: private case notes and confidential_comment EDD records must not be exposed to non-owners in shared network room dossiers, regardless of clustering hints.
Failing Branch/Argument:
internal/networkroom/lifecycle.go -> materializeCandidateArtifactsWithLimit writes sensitive content (cn.body, er.confidential_comment) into network_room_artifacts with CoveragePolicy: classification.RoomCoverageSourceMaterial ("source_scope").
internal/networkroom/repository_context.go -> ListExtendedDossierCases reads these artifacts and populates ContextBlocks and EvaluationBlocks.
internal/networkroom/dossier_context.go -> boundedContextBlocks and boundedEvaluationBlocks validate IDs and trim spaces but do not filter based on CoveragePolicy or content sensitivity.
internal/networkroom/dossier_context.go -> BuildExtendedDossier includes these blocks in the response for non-owned cases (!summary.OwnedByRequester), setting ScopeCoverageComplete = false but still exposing the data.
Sink: networkRoomDetailDossierView -> JSON response.
2. Export Linked Case Private Note Leakage
Invariant: private case notes from linked/duplicate cases should not be exported as "matching evidence" for the root case, as they belong to a different investigation context.
Failing Branch/Argument:
internal/httpapi/export_linked_cases.go -> populateExportLinkedCaseData calls cases.ResolveMatchEvidence, which explicitly queries case_notes where visibility = 'private'.
It creates ExportSourceMaterial with CoveragePolicy: exportrepo.ExportScopeRootCaseDetail.
internal/exporting/redaction.go -> ExportItemBuilder.allows permits this material when the export context scope is ExportScopeRootCaseDetail.
The full note.Body is serialized into the linked_evidence array.
Sink: ExportBundleView.LinkedEvidence -> JSON response.
3. Entity Graph Confidential Comment Exposure
Invariant: confidential_comment is restricted to the specific customer owner and must not be exposed via entity graph summaries, even if customers share an entity_hint.
Failing Branch/Argument:
internal/graph/repository_entity_summaries.go -> ListReviewMaterials executes a SQL query selecting er.confidential_comment aliased as analyst_narrative for all customers matching the entity_hint.
internal/graph/assessment_summary.go -> ExtendedAssessmentSummaryPolicy.Build returns this AnalystNarrative directly if the review status is detailed.
The policy check (HasEntityAccess) only verifies ownership of any customer with the hint, not the specific customer owning the EDD record.
Sink: entityReviewEDDGraphSummaryView.AssessmentSummary -> JSON response.
4. Activity Stream Collaborator Detail Escalation
Invariant: collaborator_detail (which exposes private note bodies) should only be granted to actual collaborators on the specific case, not just entity co-owners.
Failing Branch/Argument:
internal/httpapi/activity_views.go -> entityActivityViewsForActivityStream sets DetailLevel = ActivityDetailCollaborator based solely on hasControlledActivityChange (presence of restricted fields in the audit diff), without verifying the requester's collaborator status on the case.
internal/audit/activity_hydration.go -> caseNoteResolver then fetches the note body via ActivityReviewContext because the detail level is elevated.
The SQL in ActivityReviewContext only checks entity hint ownership, not case ownership or collaboration.
Sink: EntityActivityView.ActivityText -> JSON response.
Unresolved Leads
Audit Diff Redaction Inconsistency: internal/exporting/redaction.go defines sensitiveExportFields including source_of_funds and risk_rationale, but internal/audit/repository.go restrictedDiffFields does not include them. Consequently, these fields are stored in plaintext in audit_events.diff_json. While the export summary (safeAuditSummary) redacts the field name, the HTTP timeline (caseAuditChangeResponses) exposes the plaintext values. This may violate least privilege if the timeline is accessed by roles other than the direct EDD owner.
Projection Contract Enforcement: internal/projection/contracts.go defines Contract structs with AllowedJSONFields but no active enforcement logic was found in the HTTP handlers or repositories. It appears to be a dormant policy definition or enforced by an external component not in the source tree.
RECEIVED-b3d34042bb17
