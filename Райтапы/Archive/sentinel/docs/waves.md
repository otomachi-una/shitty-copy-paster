# Sentinel AML — Development Waves

This file decomposes Sentinel AML into sequential waves. It is intentionally explicit so orchestrator review can see when secure features, checker flows, planned vulnerabilities, exploits, fixes, and final validation are allowed.

## Global Gates

- Every wave requires tests, docs, a handoff report, and source-of-truth consistency.
- No planned vulnerability may be introduced before the secure normal workflow and checker-relevant gates for that feature pass.
- No exploit script may be added before the matching planned vulnerability wave closes.
- No reference fix may be added before exploit evidence for that vulnerability exists.
- Checker traffic must use normal HTTP APIs only.
- Hidden debug/admin endpoints, direct DB checker access, public credentials, artificial flag fields, and generic DB model serialization are forbidden unless a later source document explicitly changes that contract.

## Wave List

| Wave | Name | Status | Primary output |
| --- | --- | --- | --- |
| W01 | Repository, ForcAD, and docs foundation | complete | Buildable skeleton, ForcAD config, placeholder checker/sploit dirs, docs gate. |
| W02 | PostgreSQL auth/session foundation | complete | Users/sessions migration, auth repository/service/API, local toolchain gate, live PostgreSQL gate, and docs canonicalization fixes. |
| W03 | Customer/account/transaction domain slice | complete | Owner-scoped customers, accounts, transactions, offline dependency gate, transaction input hardening, and roadmap/duplicate-error fixes. |
| W04 | Risk scoring, alerts, and owner case workflow | complete | Deterministic risk-score calculation, alert generation, owner-scoped alert/case/private-note APIs, and Wave 04 validation gate. |
| W05 | EDD workflow | complete | Secure confidential due-diligence records, owner EDD APIs, live integration, visibility regression, and Wave 05 validation gate accepted. |
| W06 | Visibility and projection hardening | complete | Projection allowlists, HTTP leak regression, cross-owner authorization matrix, and Wave 06 validation gate accepted. |
| W07 | Dedup preview secure baseline | complete | Secure dedup metadata, candidate discovery, public-only list/merge-preview endpoints, anti-AML-1 tests, and Wave 07 validation gate accepted. |
| W08 | Audit timeline secure baseline | complete | Secure audit persistence, redacted owner case timeline API, anti-AML-2 tests, and Wave 08 validation gate accepted. |
| W09 | Related graph secure baseline | complete | Secure graph persistence, metadata-only graph APIs, anti-AML-3 tests, and Wave 09 validation gate accepted. |
| W10 | Export redaction and network-room secure baselines | complete | Secure export/dispute APIs, references-only network-room APIs, anti-AML-4/anti-AML-5 tests, and Wave 10 validation gate accepted. |
| W11 | Checker PUT/GET for case notes | complete | Place 1 lifecycle for `CaseNote.body` via normal APIs and Wave 11 validation gate complete. |
| W12 | Checker PUT/GET for EDD records | complete | Place 2 lifecycle for `EDDRecord.confidential_comment` via normal APIs and Wave 12 validation gate accepted. |
| W13 | Checker integration and HAVOC | complete | Strong CHECK/HAVOC, optional noise/retention, PUT/GET regression preservation, and liveness fixes are accepted by current-branch Wave 16 aggregate validation; W13 gates are historical point-in-time checks. |
| W14 | Vulnerability 1: dedup preview | complete | Controlled `aml1_vulnerable` dedup merge-preview profile accepted by Wave 16 aggregate reconciliation; no standalone W14 accepted review artifact is fabricated. |
| W15 | Vulnerability 2: audit timeline | complete | Controlled `aml2_vulnerable` audit timeline profile accepted by Wave 16 aggregate reconciliation; no standalone W15 accepted review artifact is fabricated. |
| W16 | Vulnerability 3: related graph | complete | Orchestrator `make wave16-gate` acceptance validates the controlled `aml3_vulnerable` graph EDD-summary profile and secure default graph behavior. |
| W17 | Vulnerability 4: export redaction | complete | Controlled `aml4_vulnerable` dispute export profile is accepted by W17-F01 deterministic `timeout 300 make wave17-gate` evidence; exploit/fix work remains locked. |
| W18 | Vulnerability 5: network room | complete | Controlled `aml5_vulnerable` network-room dossier profile is accepted after W18-F01/F02/F03 deterministic wrapper and archive-hygiene evidence; exploit/fix work remains staged. |
| W19 | Exploit 1: dedup preview | complete | Reference exploit `aml_dedup_preview.py` is accepted for AML-1 using public attack data and normal HTTP APIs only; `wave_19_validation_summary.md` records T01/T02/T03 evidence. |
| W20 | Exploit 2: audit timeline | complete | Reference exploit `aml_audit_timeline.py` is accepted for AML-2 after W20-F01/W20-F02 reconciliation and exit-0 `timeout 300 make wave20-gate` re-review evidence; Wave 21 is the next allowed exploit wave, and all fix waves remain locked. |
| W21 | Exploit 3: related graph | complete | Reference exploit `aml_related_graph.py` is accepted for AML-3 using public place 2 attack data and the related graph EDD summary side view. |
| W22 | Exploit 4: export redaction | complete | Reference exploit `aml_export_redaction.py` is accepted for AML-4 using public place 1 attack data and the dispute export linked-case private-note side view. |
| W23 | Exploit 5: network room | complete | Reference exploit `aml_network_room.py` is accepted for AML-5 using public place 2 attack data and the network-room dossier side view. |
| W24 | Fix 1: dedup preview | complete | AML-1 reference fix artifact, Wave 24 gate, matrix update, exploit-blocked evidence, anti-coarse-fix evidence, and gate-liveness reconciliation are complete as the prerequisite for Wave 25. |
| W25 | Fix 2: audit timeline | complete | AML-2 reference fix artifact, Wave 25 gate, matrix update, exploit-blocked evidence, anti-coarse-fix evidence, and documentation alignment are accepted as the prerequisite for Wave 26. |
| W26 | Fix 3: related graph | complete | AML-3 reference fix artifact, Wave 26 gate, matrix update, exploit-blocked evidence, anti-coarse-fix evidence, and documentation alignment are accepted as the prerequisite for Wave 27. |
| W27 | Fix 4: export redaction | complete | AML-4 reference fix artifact, Wave 27 gate, matrix update, exploit-blocked evidence, anti-coarse-fix evidence, documentation alignment, and W27-F01/W27-F02 reconciliation are complete. |
| W28 | Fix 5: network room | complete | AML-5 reference fix artifact, Wave 28 gate, final fix-cell matrix alignment, exploit-blocked evidence, anti-coarse-fix evidence, and documentation recovery are complete. |
| W29 | Regression and anti-coarse-fix matrix | complete | Full competition matrix gate and end-to-end checker/exploit/fix regression evidence are accepted after W29-F01 fixed the aggregate timeout and recorded exact `timeout 300 make wave29-gate` exit-0 evidence. Final readiness is not claimed. |
| W30 | Historical final validation and packaging | historical packaging evidence | `wave30-gate` remains package-inclusive review evidence, including archive generation, but no longer serves as the active archive-free stability gate. Final competition readiness is not self-claimed. |
| W31 | Historical release-candidate handoff metadata | historical handoff evidence | Durable release-candidate metadata was recorded for review context only; it does not issue a final candidate or mark final competition readiness done. |
| W32 | Runtime/A-D stability candidate | ready for orchestrator review | Archive-free aggregate stability evidence covers checker, five sploits, five fixes, vulnerable profiles, release-profile Go tests, Go vet/build, docs tree, ForcAD config, and runtime smoke without final archive, player bundle, manifest, or checksum generation. |
| W33+ | Player/admin packaging and productization | artifact-first build outputs under review | W33-AF1 adds deterministic player-service and admin/organizer transfer archives, manifests, and SHA-256 checksums under `out/`; final package promotion and competition-readiness acceptance remain deferred to orchestrator review. |

## Wave Details

### W01 — Repository, ForcAD, and Docs Foundation

Delivered buildable Go entrypoints, canonical docs, ForcAD config, checker/sploit placeholder layout, validation scripts, and Wave 01 handoffs. Product APIs, migrations, auth, checker behavior, vulnerabilities, exploits, and fixes were excluded.

### W02 — PostgreSQL Auth/Session Foundation

Implements PostgreSQL migration support for `users` and `sessions`, auth repository/service behavior, explicit HTTP DTOs, register/login/me routes, local toolchain reproducibility gates, and a live PostgreSQL migration/auth integration path.

Wave 02 was recorded as `needs fixes` until W02-F01, W02-F02, and W02-F03 passed. It is now complete and unlocks the accepted Wave 03 workstream.

### W03 — Customer/Account/Transaction Domain Slice

Defines the first non-auth product slice after auth is stable: customers, accounts, transactions, owner-scoped repositories, owner HTTP APIs, live integration gates, offline vendored dependency policy, and hardened transaction input ownership. Domain uniqueness errors for customer registration numbers, account `iban_like` values, and transaction `trace_id` values map to stable `409` responses.

Wave 03 is complete after W03-F01, W03-F02, and W03-F03. Cases, notes, EDD, relationships, audit events, vulnerabilities, checker PUT/GET, public attack data, and reference exploits remain forbidden in Wave 03.

### W04 — Risk Scoring, Alerts, and Owner Case Workflow

Adds deterministic server-side risk scoring inputs, alert generation from normal transactions, owner alert queue/claim/triage workflows, owner case creation/read/status workflows, and private owner-only case-note APIs. This wave introduces the secure case owner path needed by later checker and visibility waves, but it must not add checker behavior, planned vulnerabilities, public attack data, side-view leaks, EDD, graph/export/network-room behavior, or reference exploits.

Wave 04 is complete after W04-T01, W04-T02, W04-T03, and W04-T04.

### W05 — EDD Workflow

Adds secure enhanced due-diligence records, confidential comments, owner EDD HTTP APIs, live integration, visibility regression tests, and a Wave 05 validation gate. This wave prepares `EDDRecord.confidential_comment` for later checker use but does not implement checker behavior, public attack data, side-view leaks, exploits, or fixes.

Wave 05 is complete after W05-T01, W05-T02, W05-T03, and W05-T04.

### W06 — Visibility and Projection Hardening

Adds presenter allowlists, a route-level HTTP Leak Regression suite, and a Cross-Owner Authorization Matrix across current customer/account/transaction, alert/case/note, and EDD owner workflows. This wave proves DB models are not serialized directly, private note/EDD fields appear only in owner note/EDD DTO contexts, and future public, audit, graph, export, network, checker, debug, and admin routes remain absent.

Wave 06 is complete after W06-T01, W06-T02, W06-T03, and W06-T04.

### W07 — Dedup Preview Secure Baseline

Implements secure `cases.dedup_hint` metadata, owner-verified duplicate candidate discovery, authenticated `GET /api/cases/{case_id}/duplicates`, authenticated `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`, public-only `CaseDuplicatePreviewView` projections, HTTP leak regression probes, Anti-AML-1 tests, and the Wave 07 validation gate.

Wave 07 is complete after W07-T01, W07-T02, W07-T03, and W07-T04. At Wave 07 closure, AML-1 remained future-only until Wave 14; the current AML-1 behavior is now governed by the W14 section and `docs/09_vulnerability_matrix.md`.

### W08 — Audit Timeline Secure Baseline

Implements `000006_create_audit_events.sql`, `internal/audit` redaction primitives, owner workflow instrumentation, authenticated `GET /api/cases/{case_id}/timeline`, `owner_case_audit` projection allowlists, Anti-AML-2 regression tests, and the Wave 08 validation gate.

Timeline DTOs expose only safe audit metadata and redacted changes. They must not expose raw `diff_json`, actor/owner IDs, `CaseNote.body`, `EDDRecord.confidential_comment`, value hashes, credentials, session material, checker-private markers, public attack data, or planned AML-2 behavior.

Wave 08 is complete after W08-T01, W08-T02, W08-T03, and W08-T04. AML-2 remains future-only until Wave 15.

### W09 — Related Graph Secure Baseline

Implements `000007_create_entity_graph.sql`, `internal/graph` secure repository primitives, authenticated metadata-only graph endpoints, graph projection allowlists, graph HTTP visibility probes, Anti-AML-3 tests, and the Wave 09 validation gate.

Wave 09 is complete after W09-T01, W09-T02, W09-T03, and W09-T04. AML-3 remains future-only until Wave 16.

### W10 — Export Redaction and Network-Room Secure Baselines

Implements `000008_create_exports_disputes.sql`, `internal/exporting` secure recursive redaction primitives, authenticated export/dispute HTTP APIs, `000009_create_network_rooms.sql`, `internal/networkroom` references-first room and safe dossier primitives, authenticated network-room list/detail/join/dossier APIs, projection allowlists, Anti-AML-4 and Anti-AML-5 leak regression tests, and the Wave 10 validation gate.

Wave 10 is complete after W10-T01, W10-T02, W10-T03, W10-T04, and W10-T05.
AML-4 is now governed by the Wave 17 `aml4_vulnerable` profile section and
`docs/09_vulnerability_matrix.md`; AML-5 is now governed by the accepted Wave
18 `aml5_vulnerable` profile section.

### W11 — Checker PUT/GET for Case Notes

Implements real checker lifecycle behavior for place 1, storing flags through
normal case-note APIs in `CaseNote.body`. Public attack data remains
credential-free and flag-free, and checker-private state remains separate.
Checker GET reads only the owner case-note view. Wave 11 remains `needs fixes`
until W11-T01, W11-T02, W11-T03, W11-T04, and W11-T05 pass legacy context
checks; the current status ledger marks Wave 11 complete. Place 2 is active in
Wave 12. CHECK/HAVOC remains Wave 13. Planned vulnerability waves remain
locked.

### W12 — Checker PUT/GET for EDD Records

Implements real checker lifecycle behavior for place 2, storing flags through
normal owner EDD APIs in `EDDRecord.confidential_comment`. PUT registers and
authenticates a checker-owned analyst, creates a checker-owned customer, and
creates an EDD record with the raw flag only in `confidential_comment`. GET
uses the private checker state to authenticate as the owner and reads only
`GET /api/customers/{customer_id}/edd`. Public attack data remains
credential-free and flag-free, checker-private state remains separate and
MACed, and cross-place private-state confusion is rejected. Wave 12 is complete
after W12-T01 through W12-T05 and AD-C0 accepted the active two-place checker.

### W13 — Checker Integration and HAVOC

Completes checker integration across both places with strong CHECK/HAVOC,
optional `putnoise`/`getnoise`, retention smoke, and regression preservation for
both flag-store PUT/GET paths. `make wave13-gate` runs checker PUT/GET tests,
CHECK/HAVOC tests, Go test/vet, docs tree, the Wave 13 gate, and ForcAD config
validation. W13-F01 fixes the fake HTTP server lifecycle issue that previously
let checker unittest discovery produce successful dots without process exit.
ADR-0003 marks `make wave13-gate` as a point-in-time historical gate after
planned vulnerability profiles exist. The current branch is governed by
aggregate gates such as `make wave16-gate`, which the orchestrator review host
reported exiting 0. That aggregate acceptance reconciles Wave 13 as complete
without requiring the historical Wave 13 no-vulnerability-marker check to pass
on a branch that now intentionally contains AML-1, AML-2, and AML-3 profiles.

### W14 — Vulnerability 1: Dedup Preview

Implements the planned AML-1 dedup-preview vulnerability only in the
`aml1_vulnerable` source profile. The affected endpoint is
`GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`; when
the requester owns the source case and the duplicate is a valid dedup
candidate, the tagged profile adds duplicate `private_notes[].body` to the
merge-preview response. The default profile remains the secure public-only
dedup baseline. `docs/09_vulnerability_matrix.md` is the source of truth for
the allowed vulnerable behavior and protected-field exclusions.

AML-1 must not expose EDD confidential comments, EDD narrative fields, audit
diffs, credentials, sessions, checker-private state, public attack data, raw
database rows, debug/admin controls, or unrelated projections. Checker GET
continues to read owner case notes and owner EDD records directly, not
merge-preview.

The reference exploit `sploits/sentinel_aml/aml_dedup_preview.py` is accepted
under Wave 19 authority. It uses only public place 1 attack data,
attacker-owned setup, and the normal merge-preview side view. The AML-1
reference fix is accepted under Wave 24 as
`fixes/sentinel_aml/aml_dedup_preview.patch`. This snapshot does not fabricate a standalone accepted
Wave 14 review artifact; Wave 14 is reconciled as complete by the current-branch
Wave 16 aggregate gate described in ADR-0003.

### W15 — Vulnerability 2: Audit Timeline

Implements the planned AML-2 audit-timeline vulnerability only in the
`aml2_vulnerable` source profile. The affected endpoint is
`GET /api/cases/{case_id}/timeline`; after normal authentication and owner case
validation, the tagged profile may expose owner `CaseNote.body` values as
`case_note.body` change records for `case_note` audit events. The default
profile remains the secure redacted audit baseline. `docs/09_vulnerability_matrix.md`
is the source of truth for the allowed vulnerable behavior and protected-field
exclusions.

AML-2 must not expose EDD confidential comments, EDD narrative fields, graph
data, export bundles, network-room dossiers, credentials, sessions,
checker-private state, public attack data, raw database rows, debug/admin
controls, or unrelated projections. Checker GET continues to read owner case
notes and owner EDD records directly, not audit timeline side views.

The reference exploit `sploits/sentinel_aml/aml_audit_timeline.py` is accepted
after Wave 20 review. The AML-2 reference fix is accepted under Wave 25 as
`fixes/sentinel_aml/aml_audit_timeline.patch`; it must redact audit diff values
while preserving event existence, timeline access, and owner note access.

This snapshot does not fabricate a standalone accepted Wave 15 review artifact.
Wave 15 is reconciled as complete by the current-branch Wave 16 aggregate gate
described in ADR-0003. Historical `make wave15-gate` may reject AML-3 markers
on this branch because AML-3 is now intentionally present.

### W16 — Vulnerability 3: Related Graph

Implements the planned AML-3 related-graph vulnerability only in the
`aml3_vulnerable` source profile. The affected endpoint is
`GET /api/graph/entities/{entity_hint}/edd-summaries`; after normal
authentication and the owned-`entity_hint` graph access check, the tagged
profile may add `confidential_comment` to related EDD summary items. The
default profile remains the secure metadata-only graph baseline.
`docs/09_vulnerability_matrix.md` is the source of truth for the allowed
vulnerable behavior and protected-field exclusions.

AML-3 must not expose `CaseNote.body`, EDD narrative fields, raw audit diffs,
export bundles, network-room dossiers, credentials, sessions, checker-private
state, public attack data, raw database rows, debug/admin controls, or
unrelated projections. Checker GET continues to read owner case notes and owner
EDD records directly, not graph side views.

The reference exploit `sploits/sentinel_aml/aml_related_graph.py` is accepted
under Wave 21 authority after Wave 20 acceptance. It uses public place 2
`EDDRecord` attack data, creates only attacker-owned graph participation,
requests only `GET /api/graph/entities/{entity_hint}/edd-summaries`, and
extracts only leaked `summaries[].confidential_comment`. The AML-3 reference
fix is accepted under Wave 26 as `fixes/sentinel_aml/aml_related_graph.patch`.
Wave 27 is accepted for AML-4, Wave 28 is accepted for AML-5, and Wave 29 is
accepted for full regression evidence. Wave 16 is complete after the orchestrator review host reported
`make wave16-gate` exiting 0.

### W17 — Vulnerability 4: Export Redaction

Implements the planned AML-4 export-redaction vulnerability only in the
`aml4_vulnerable` source profile. The affected process is authenticated
`POST /api/disputes/{dispute_id}/export`; after the requester owns the dispute
and root case, linked-case traversal may accidentally reuse the root export
context. That lets root-detail source material appear as product-neutral
`linked_evidence[]` entries with `content` / `evidence_excerpt` evidence.

The default profile remains the secure recursive export baseline for root
cases, linked cases, audit summaries, EDD summaries, and item metadata. AML-4
must not expose root private notes, `EDDRecord.confidential_comment`, EDD
narrative fields, raw audit diffs, credentials, sessions, checker-private
state, public attack data, graph data, network-room dossiers, raw database
rows, debug/admin controls, exploit behavior, or fix behavior.

Wave 17 is complete after W17-F01 recorded deterministic
`timeout 300 make wave17-gate` evidence with the AML-4 tagged sweep serialized
as `go test -p 1 -tags aml4_vulnerable ./...`. The reference exploit
`sploits/sentinel_aml/aml_export_redaction.py` is accepted under Wave 22
authority after Wave 21 acceptance, and the AML-4 reference fix is implemented
accepted under Wave 27 authority as
`fixes/sentinel_aml/aml_export_redaction.patch`.

### W18 — Vulnerability 5: Network Room

Implements the planned AML-5 network-room vulnerability only in the
`aml5_vulnerable` source profile. The affected endpoint is
`GET /api/network/rooms/{room_id}/dossier`; after normal authentication,
network-room materialization, and eligible participant scope, the tagged
profile may expose bounded source-scope collaboration artifacts as
`context_blocks` and `evaluation_blocks`.

The default profile remains the secure references-first network-room baseline:
room participation normally grants room metadata, participant metadata, public
case shells, public risk tags, ownership markers, and
`scope_coverage_complete`, not access to owner-only case-note or EDD material.

AML-5 must not expose own-case private note bodies through the dossier,
unrelated case notes, EDD `source_of_funds`, EDD `risk_rationale`, raw audit
diffs, credentials, sessions, checker-private state, public attack data, graph
or export expansions, raw database rows, debug/admin controls, exploit
behavior, or fix behavior.

Wave 18 is complete after W18-F01/F02/F03 evidence. The authoritative
`timeout 300 make wave18-gate` command exits 0 after running default Go tests,
the deterministic package-by-package AML-5 tagged runner, Go vet, docs,
competition-matrix, ForcAD, and archive-hygiene validation. W18-F02 also proves
the deliverable tree is free of `.gocache*`, `.appdata*`, Python bytecode/cache
directories, IDE metadata, local coverage outputs, and temporary archive files.
The reference exploit `sploits/sentinel_aml/aml_network_room.py` is accepted
under Wave 23, and the AML-5 reference fix is accepted under Wave 28 as
`fixes/sentinel_aml/aml_network_room.patch`. Wave 19 through Wave 23 are
accepted; Wave 24 provides the AML-1 reference fix; Wave 25 provides the AML-2
reference fix; Wave 26 provides the AML-3 reference fix; Wave 27 provides the
AML-4 reference fix; Wave 28 provides the AML-5 reference fix; Wave 29 is
accepted for full matrix regression, Wave 30/W31 remain historical
package-inclusive review context, and Wave 32 is ready for orchestrator review
as an archive-free runtime/A-D stability candidate.

### W19-W23 — Reference Exploits

Each exploit wave adds exactly one reference exploit for its matching accepted vulnerability:

- W19: `aml_dedup_preview.py`
- W20: `aml_audit_timeline.py`
- W21: `aml_related_graph.py`
- W22: `aml_export_redaction.py`
- W23: `aml_network_room.py`

Exploit waves must use public attack data and normal service APIs only. They must not require direct database access, hidden routes, leaked credentials, or unrelated vulnerabilities.

Wave 19 implements only `aml_dedup_preview.py` and is accepted after
orchestrator review. The exploit registers and logs in as an attacker, creates
its own customer/account/transaction/alert/case chain with the victim
`dedup_hint`, calls
`GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`, and
prints only the flag-like token from leaked `candidate.private_notes[].body`.

Wave 20 implements only `aml_audit_timeline.py` and is accepted after
W20-F01/W20-F02 reconciliation plus exit-0 `timeout 300 make wave20-gate`
re-review evidence. The exploit registers and logs in as an attacker, uses
public place 1 locator data, calls only the normal
`GET /api/cases/{case_id}/timeline` side view, and prints only the flag-like
token from exposed `case_note.body` audit change material. Wave 20 acceptance
unlocked only the Wave 21 AML-3 reference exploit scope.

Wave 21 implements only `aml_related_graph.py` and is accepted. The exploit
registers and logs in as an attacker, uses public place 2 `EDDRecord` locator
data, creates only attacker-owned graph participation with the victim
`entity_hint`, calls only
`GET /api/graph/entities/{entity_hint}/edd-summaries`, and prints only the
flag-like token from leaked `summaries[].confidential_comment`. Wave 21
acceptance unlocked only the Wave 22 AML-4 reference exploit scope.

Wave 22 implements only `aml_export_redaction.py` and is accepted. The
exploit registers and logs in as an attacker, uses public place 1
`CaseNote.body` locator data, creates an attacker-owned duplicate-linked case
and dispute, calls only normal dispute export APIs and stored export readback,
and prints only the flag-like token from leaked
`bundle.linked_evidence[]` content. Wave 22 acceptance unlocked only Wave 23
for the AML-5 reference exploit and did not unlock any reference fix wave.

W22-T01 implements the exploit, W22-T02 implements the gate and matrix
alignment, and W22-T03 records documentation/status alignment plus
`docs/wave_reports/wave_22_validation_summary.md`. Wave 22 is now complete.

Wave 23 implements only `aml_network_room.py` and is accepted. The exploit
registers and logs in as an attacker, uses public place 2 `EDDRecord` locator
data, creates attacker-owned eligible network-room participation, discovers and
joins a room through normal network-room APIs, calls only
`GET /api/network/rooms/{room_id}/dossier`, and prints only the flag-like token
from `context_blocks[].content` or `evaluation_blocks[].content`. W23-T01 implements the exploit,
W23-T02 implements the five-exploit gate and matrix alignment, and W23-T03
records documentation/status alignment plus
`docs/wave_reports/wave_23_validation_summary.md`. Wave 23 acceptance opens
only Wave 24 for AML-1 reference-fix work.

### W24-W28 — Reference Fixes

Each fix wave addresses exactly one accepted exploit without disabling unrelated product behavior:

- W24: dedup preview fix through
  `fixes/sentinel_aml/aml_dedup_preview.patch`,
  `scripts/check_wave24_gate.py`, exploit-blocked tests, anti-coarse-fix tests,
  and the bounded release/offline Go test recipe.
- W25: audit timeline fix, accepted through
  `fixes/sentinel_aml/aml_audit_timeline.patch`,
  `scripts/check_wave25_gate.py`, exploit-blocked tests, anti-coarse-fix tests,
  competition matrix alignment, and `docs/wave_reports/wave_25_validation_summary.md`.
- W26: related graph fix, accepted through
  `fixes/sentinel_aml/aml_related_graph.patch`,
  `scripts/check_wave26_gate.py`, exploit-blocked tests, anti-coarse-fix tests,
  competition matrix alignment, the package-by-package release/offline Go test
  runner `scripts/run_go_release_tests.py`, and
  `docs/wave_reports/wave_26_validation_summary.md`.
- W27: export redaction fix, accepted through
  `fixes/sentinel_aml/aml_export_redaction.patch`,
  `scripts/check_wave27_gate.py`, exploit-blocked tests, anti-coarse-fix tests,
  competition matrix alignment, W27-F01 runner liveness stabilization, and
  `docs/wave_reports/wave_27_validation_summary.md`.
- W28: network room fix, accepted through
  `fixes/sentinel_aml/aml_network_room.patch`,
  `scripts/check_wave28_gate.py`, exploit-blocked tests, anti-coarse-fix tests,
  competition matrix final fix-cell alignment, W28-F01/W28-F02 corrective
  evidence, and `docs/wave_reports/wave_28_validation_summary.md`.

Each fix must keep CHECK/HAVOC green and add regression tests proving the exploit no longer succeeds.

### W29 — Regression and Anti-Coarse-Fix Matrix

Complete after Wave 28 acceptance, W29-F01 exact aggregate gate success, and
orchestrator acceptance. It runs the full competition matrix gate plus
end-to-end checker, exploit, vulnerable-profile, fixed-proof, and
anti-coarse-fix regression evidence together. The first orchestrator review
marked the wave `needs fixes` because the aggregate gate timed out; W29-F01
recorded exact GNU-style `timeout 300 make wave29-gate` exit-0 evidence after
the liveness fix, and W29-F02 reconciled the status ledgers before acceptance.
This wave blocks feature shutdowns, broad endpoint removal, direct
DB/debug/admin shortcuts, sensitive field renames, or documentation-only
masking of failed validation. Wave 29 does not claim final competition
readiness; Wave 32 now owns the active archive-free stability checkpoint, and
Wave 33+ owns future package/productization work.

### W30 — Historical Final Validation and Packaging

Ready for orchestrator review after Wave 29 acceptance. It freezes
source-of-truth docs, validates package reproducibility, confirms no active
foreign docs or root-level prompt pools remain, verifies ForcAD layout, records
final checker/exploit/fix matrix evidence, reconciles DoD/risk/status ledgers,
and produces final release-review handoffs. W30-T01 creates the
release-readiness manifest, W30-T02 adds deterministic release archive
packaging, W30-T03 records final validation evidence, and W30-T04 closes the
documentation/risk ledger for review. W30-F02 adds `wave30-gate` as the single
final acceptance command; it delegates to the stabilized Wave 29 evidence and
adds Wave 30 validation plus release archive generation. Wave 30 does not
itself claim final competition readiness; acceptance remains orchestrator-only,
and its package-inclusive evidence is now historical context for the W32
stability/package split.

### W31 — Historical Release-Candidate Metadata

Records durable release-candidate package metadata for review context after the
Wave 30 package-inclusive gate. W31 metadata does not issue the final release
candidate and does not mark final competition readiness done. It remains a
historical packaging reference while W32 validates service stability without
creating archives.

### W32 — Runtime/A-D Stability Candidate

Ready for orchestrator review as the active stability checkpoint before
packaging. W32 validates the service, checker, five reference sploits, five
reference fixes, vulnerable profiles, release-profile Go tests, Go vet/build,
ForcAD config, docs tree, and live runtime smoke path without final archive
creation, player bundle creation, final manifest generation, or checksum
generation.

W32-T01 adds `make ad-stability-gate` and
`scripts/check_ad_stability_gate.py`; exact evidence is
`timeout 300 make ad-stability-gate` exiting 0 in the target environment.
W32-T02 records the checker scenario inventory for both flag stores and
CHECK/HAVOC coverage in
`docs/wave_reports/wave_32_checker_validation.md`. W32-T03 records all AML-1
through AML-5 sploit/fix matrix evidence in
`docs/wave_reports/wave_32_sploit_fix_matrix.md`. W32-T04 records runtime
smoke evidence in `docs/wave_reports/wave_32_runtime_smoke.md`, including
migrations, API health, worker restart safety, and representative normal
customer/account/transaction/case/EDD flows. W32-T05 reconciles roadmap,
source-of-truth, DoD, risk, and execution ledgers in
`docs/wave_reports/wave_32_stability_summary.md`.

### W33+ — Player/Admin Packaging and Productization

W33-AF1 adds artifact-first build outputs while keeping final
competition-readiness acceptance outside this repository-local change. The new
`make artifacts` target cleans `out/artifacts/`, `out/manifests/`, and
`out/checksums/`; builds the exact player-service artifact from the sanitized
player candidate; builds the admin/organizer artifact from the internal
repository inventory; writes `player_manifest.json` and `admin_manifest.json`;
and records SHA-256 checksums. `make artifact-gate` validates clean-output
behavior, archive/manifest inventory matching, checksum-byte matching, stale
file cleanup, and missing-artifact failure.

The admin/organizer artifact must preserve the W32/W34
checker/sploit/fix/runtime evidence, including two checker places, five
sploits, five fixes, tests, docs, gates, and CHECK/HAVOC coverage. The
player-service artifact remains derived from the sanitized player-service
builder and must not disclose organizer-only evidence. Durable package
promotion and final competition-readiness acceptance remain orchestrator-owned.

## Historical Review Notes

The Wave List above is authoritative. Prior review states are retained only for legacy gate context: `| W05 | EDD workflow | needs fixes |`, `| W06 | Visibility and projection hardening | needs fixes |`, `| W07 | Dedup preview secure baseline | needs fixes |`, `| W08 | Audit timeline secure baseline | needs fixes |`, `| W09 | Related graph secure baseline | needs fixes |`, `| W10 | Export redaction and network-room secure baselines | needs fixes |`, and `| W11 | Checker PUT/GET for case notes | needs fixes |`. Historical Wave 10 remains `needs fixes` until W10-T01, W10-T02, W10-T03, W10-T04, and W10-T05 pass legacy context checks.
