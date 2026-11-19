# Sentinel AML Reference Fixes

Reference fixes for planned Sentinel AML vulnerability waves belong here.

This directory is intentionally a skeleton until the matching exploit evidence
exists and the corresponding reference-fix wave opens. Fixes must be narrow:
they restore authorization, ownership, projection, or redaction boundaries while
preserving normal owner PUT/GET, CHECK/HAVOC, and the affected business module.

Fixes must not use debug/admin endpoints, direct database checker access,
checker-only shortcuts, public credentials, raw flags, or feature-disable
workarounds.

## AML-1: Dedup Merge-Preview Projection

Artifact: `aml_dedup_preview.patch`

Purpose: remove the vulnerable merge-preview evidence-source priority that used
review-context material as `candidate.match_explanation` in the
`aml1_vulnerable` profile.

Scope: the patch keeps
`GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview` and the
duplicate-candidate list intact, but makes the tagged AML-1 profile build match
explanations from public evidence sources only.

Expected blocked exploit: `sploits/sentinel_aml/aml_dedup_preview.py` should
fail because `candidate.match_explanation` no longer contains the review
context marker.

Anti-coarse-fix warning: do not remove deduplication, disable duplicate
candidate discovery, hide public summaries, special-case checker data, or route
around normal owner case-note APIs. The fix is only the side-view projection
boundary.

## AML-2: Related-Entity Activity Hydration

Artifact: `aml_audit_timeline.patch`

Purpose: remove the vulnerable AML-2 related-entity activity hydration policy
that treated a related viewer as `collaborator_detail` for case-note activity in
the `audit_detail_view` / `aml2_vulnerable` profile.

Scope: the patch keeps owner `GET /api/cases/{case_id}/timeline`, related
`GET /api/entities/{entity_hint}/activity`, audit event creation, redacted
change evidence, and owner note access through `GET /api/cases/{case_id}/notes`.
Related-entity activity readers may see scoped `activity_narrative` and
`restricted_field` evidence, but controlled values remain `[redacted]` and
`redacted` stays `true`.

Expected blocked exploit: `sploits/sentinel_aml/aml_audit_timeline.py` should
fail because the fixed entity activity side view no longer returns the owner
review context in `activity_narrative`.

Anti-coarse-fix warning: do not remove audit logging, disable timeline or
entity-activity routes, hide all case-note events, bypass owner note APIs,
special-case checker data, or add debug/admin lookup paths. The fix is only the
related activity side-view redaction boundary.

## AML-3: Related-Graph EDD Summary Projection

Artifact: `aml_related_graph.patch`

Purpose: remove the vulnerable AML-3 graph assessment-summary policy fallback
that selected analyst narrative material for related graph EDD summaries in the
`aml3_vulnerable` profile.

Scope: the patch keeps `GET /api/graph/entities/{entity_hint}`,
`GET /api/graph/entities/{entity_hint}/related-cases`, and
`GET /api/graph/entities/{entity_hint}/edd-summaries` available. Graph side
views continue to return `assessment_summary`, but `AssessmentSummaryPolicy`
selects public risk rationale or safe review captions for graph audiences.
Owner EDD access remains through `GET /api/customers/{customer_id}/edd`.

Expected blocked exploit: `sploits/sentinel_aml/aml_related_graph.py` should
fail because `summaries[].assessment_summary` no longer contains the owner
analyst narrative and instead carries public risk rationale or safe fallback
text.

Anti-coarse-fix warning: do not remove graph endpoints, disable clustering,
hide public related-case or EDD summary evidence, bypass owner EDD APIs,
special-case checker data, or add debug/admin/direct-database paths. The fix is
only the graph side-view visibility boundary.

## AML-4: Regulatory Export Recursive Redaction

Artifact: `aml_export_redaction.patch`

Purpose: remove the vulnerable AML-4 export profile behavior where recursive
linked-case traversal reused the root export context and allowed
root-detail source material into `bundle.linked_evidence[]` as neutral export
evidence content.

Scope: the patch keeps `POST /api/cases/{case_id}/exports`,
`POST /api/disputes`, `POST /api/disputes/{dispute_id}/export`, and
`GET /api/exports/{export_id}` available. Root and linked cases keep public
case shells, public summaries, redaction policy, audit summaries, EDD summaries,
and export item metadata, but recursive redaction applies across linked cases,
notes, evidence, audit material, and EDD-derived material.

Expected blocked exploit: `sploits/sentinel_aml/aml_export_redaction.py` should
fail because fixed export output rebinds linked traversal to
`linked_case_summary`, so root-detail source material is not emitted through
`linked_evidence` content.

Anti-coarse-fix warning: do not remove export endpoints, disable dispute export
creation, hide linked public case evidence, bypass owner note or owner EDD APIs,
special-case checker data, or add debug/admin/direct-database paths. The fix is
only the recursive export context boundary.

## AML-5: Network-Room Collaboration Artifact Scope

Artifact: `aml_network_room.patch`

Purpose: remove the vulnerable AML-5 network-room dossier path where
source-scope collaboration artifacts were materialized into recipient-visible
dossiers as neutral room context and evaluation content.

Scope: the patch keeps network-room creation, join, room summary, and dossier
responses available. Dossiers keep public room summaries, typology/risk tags,
case identifiers, public case summaries, requester ownership markers, and
room coverage metadata, but source-scope material remains behind the owner
case-note and owner EDD APIs.

Expected blocked exploit: `sploits/sentinel_aml/aml_network_room.py` should fail
because fixed dossier output no longer contains source-scope
`context_blocks[].content` or `evaluation_blocks[].content`.

Anti-coarse-fix warning: do not remove network-room endpoints, disable joins or
dossier generation, hide public room/case evidence, copy source-scope material
under renamed fields, special-case checker data, or add debug/admin/direct-
database paths. The fix is only the network-room collaboration artifact scope
boundary.
