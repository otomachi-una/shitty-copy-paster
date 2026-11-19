# Sentinel AML — Visibility and Projection Model

Wave 18 keeps explicit response projections from authentication through owner-only customer, account, transaction, alert, case, private case-note, EDD owner views, secure dedup, redacted audit timeline, secure graph side-view metadata, secure export bundles, secure network-room dossiers, and tagged AML-1 through AML-5 vulnerable profiles. Source-controlled allowlist contracts live under `internal/projection`.

## Required Direction

Future API responses must use explicit projections rather than serializing database models directly. Visibility-sensitive data must be separated by owner, permitted collaborator, checker-private, and public views.

Projection code must be deny-by-default:

- each business response surface needs a named DTO or presenter output;
- allowlists must use explicit fields, not reflection-based all-field copying;
- database models must not be passed directly to HTTP JSON responses;
- owner-only fields may appear only in owner-authenticated views;
- future public, side, audit, export, graph, network, and duplicate-preview contracts must omit private note bodies and EDD confidential comments unless a source-of-truth update explicitly changes a named build-tag profile.

## Current Auth Projections

- Register and login responses return a `user` projection and a one-time raw session credential.
- `/api/auth/me` returns only the current `user` projection.
- User projections include `id`, `username`, `role`, `status`, and `created_at`.
- User projections exclude `password_hash`.
- Session projections include the raw token only when a new session is created.
- Session projections exclude stored token hashes, revocation metadata, and internal database row shape.

## Wave 03 Owner Projections

Customer projections include:

- `id`
- `display_name`
- `customer_type`
- `country`
- `registration_number`
- `risk_level`
- `entity_hint`
- `created_at`
- `status`

Customer projections exclude `owner_user_id`.

Account projections include:

- `id`
- `customer_id`
- `iban_like`
- `currency`
- `status`
- `created_at`

Transaction projections include:

- `id`
- `account_id`
- `counterparty_name`
- `counterparty_country`
- `counterparty_fingerprint`
- `amount`
- `currency`
- `direction`
- `purpose`
- `trace_id`
- `created_at`
- `risk_score`

`risk_score` is read-only in product projections. Clients cannot set it during transaction creation; Wave 04 may return the deterministic server-computed score after synchronous risk processing.

## Wave 04 Owner Investigation Projections

Alert projections include:

- `id`
- `transaction_id`
- `customer_id`
- `rule_code`
- `risk_score`
- `status`
- `assigned_user_id` when claimed
- `typology_hint`
- `created_at`
- `updated_at`

Case projections include:

- `id`
- `customer_id`
- `alert_id`
- `status`
- `public_summary`
- `risk_score`
- `typology_hint`
- `created_at`
- `updated_at`

Case note projections include:

- `id`
- `case_id`
- `author_user_id`
- `visibility`
- `body`
- `created_at`
- `updated_at`

Case note bodies are private business data and are returned only through owner-authorized `/api/cases/{case_id}/notes` paths. Cross-owner note reads fail closed and no public, checker, audit, export, graph, or network-room projection exists in Wave 04.

Owner projections do not expose public attack data, checker-private state, collaborator views, side views, internal DB row dumps, password hashes, stored token hashes, or `owner_user_id`.

## Wave 05 EDD Visibility

EDD records include `confidential_comment` as private business data. Wave 05 exposes it only through the authenticated owner EDD DTO for:

- `POST /api/customers/{customer_id}/edd`
- `GET /api/customers/{customer_id}/edd`
- `PATCH /api/customers/{customer_id}/edd`

Repository and HTTP access to EDD records is owner-scoped through `customers.owner_user_id`. Cross-owner reads and updates fail closed as not found.

`EDDRecord.confidential_comment` is the future place 2 field, but it is not active checker storage in Wave 05 and must not appear in logs, non-EDD owner views, public views, side views, alert queues, case shells, graph/export/network projections, or checker-only paths.

Visibility matrix for `confidential_comment`:

| Surface | Wave 05 Visibility |
| --- | --- |
| Owner EDD create/get/patch response | visible |
| Customer/account/transaction response | not visible |
| Alert queue, alert detail, case shell, case-note paths | not visible |
| Public attack-data or checker-only path | absent |
| Worker, export, graph, audit, network-room, or side-view projection | absent |
| Logs | not visible |

## Wave 06 Projection Contracts

Wave 06 formalizes projection allowlists in `internal/projection`. These structs are contracts for current owner views and placeholders for future safe views only; Wave 06 does not register new public, graph, export, network, audit, merge-preview, or checker routes.

Current owner projection contracts:

| Contract | JSON fields | Private field allowance |
| --- | --- | --- |
| `owner_customer` | `id`, `display_name`, `customer_type`, `country`, `registration_number`, `risk_level`, `entity_hint`, `created_at`, `status` | none |
| `owner_account` | `id`, `customer_id`, `iban_like`, `currency`, `status`, `created_at` | none |
| `owner_transaction` | `id`, `account_id`, `counterparty_name`, `counterparty_country`, `counterparty_fingerprint`, `amount`, `currency`, `direction`, `purpose`, `trace_id`, `created_at`, `risk_score` | none; `risk_score` remains server-owned |
| `owner_alert` | `id`, `transaction_id`, `customer_id`, `rule_code`, `risk_score`, `status`, `assigned_user_id`, `typology_hint`, `created_at`, `updated_at` | none |
| `owner_case` | `id`, `customer_id`, `alert_id`, `status`, `public_summary`, `risk_score`, `typology_hint`, `created_at`, `updated_at` | none |
| `owner_case_note` | `id`, `case_id`, `author_user_id`, `visibility`, `body`, `created_at`, `updated_at` | `body` is allowed only here |
| `owner_edd` | `id`, `customer_id`, `analyst_user_id`, `source_of_funds`, `risk_rationale`, `confidential_comment`, `review_status`, `created_at`, `updated_at` | `confidential_comment` is allowed only here |
| `case_duplicate_preview` | `case_id`, `public_summary`, `risk_tags`, `overlap_score`, `match_explanation` | public overlap metadata only |
| `graph_entity` | `entity_hint`, `relation_type`, `customer_count`, `case_count`, `highest_risk`, `risk_tags`, `updated_at` | safe entity-hint metadata only |
| `graph_related_case` | `case_id`, `customer_id`, `entity_hint`, `display_name`, `country`, `status`, `public_summary`, `risk_score`, `typology_hint`, `created_at`, `updated_at` | public case/customer metadata only |
| `edd_graph_summary` | `customer_id`, `entity_hint`, `review_status`, `risk_tags`, `created_at`, `updated_at` | EDD review metadata only |
| `network_room_summary` | `id`, `room_key`, `entity_hint`, `typology_hint`, `status`, `public_summary`, `public_risk_tags`, `case_count`, `participant_count`, `created_at`, `updated_at` | room metadata only |
| `network_room_case` | `case_id`, `customer_id`, `owned_by_requester`, `status`, `public_summary`, `risk_score`, `typology_hint`, `public_risk_tags`, `private_data_omitted`, `created_at`, `updated_at` | public case metadata only |
| `network_room_dossier` | `room`, `cases`, `redaction_policy`, `private_data_policy` | safe room and case summaries only |

Future safe projection placeholder contracts:

| Contract | JSON fields | Explicitly forbidden |
| --- | --- | --- |
| `future_public_case_shell` | `id`, `customer_id`, `status`, `public_summary`, `risk_score`, `typology_hint`, `created_at`, `updated_at` | `body`, `confidential_comment`, auth/session/checker-private fields |
| `future_duplicate_preview` | `candidate_customer_id`, `match_customer_id`, `display_name`, `country`, `risk_level`, `match_reason`, `confidence_bucket` | `body`, `confidential_comment`, transaction trace/fingerprint details, auth/session/checker-private fields |
| `future_audit_summary` | `id`, `event_type`, `object_type`, `object_id`, `created_at` | `body`, `confidential_comment`, actor credentials, auth/session/checker-private fields |
| `future_export_summary` | `id`, `kind`, `status`, `created_at`, `expires_at` | exported record bodies, `confidential_comment`, auth/session/checker-private fields |

Projection tests enforce that `body` appears only in the owner case-note contract, `confidential_comment` appears only in the owner EDD contract, and future safe contracts exclude password hashes, token hashes, checker-private markers, raw DB row fields, and owner-only identifiers.

`scripts/check_wave06_gate.py` treats these allowlists as the current projection authority and fails if the allowlist package, HTTP leak tests, or cross-owner matrix coverage are missing.

## Wave 06 HTTP Leak Regression

Wave 06 also plants high-entropy sentinel strings in one private case note and one EDD confidential comment during HTTP tests. Those strings are allowed only in:

| Sentinel | Allowed endpoint |
| --- | --- |
| private case-note body | `GET /api/cases/{case_id}/notes` for the owning user |
| EDD confidential comment | `GET /api/customers/{customer_id}/edd` for the owning user |

The same regression suite verifies both sentinel strings are absent from:

- unauthenticated owner note and EDD routes;
- cross-owner note and EDD routes;
- `/api/auth/me`;
- unsupported `/api/customers/{customer_id}/profile` and `/api/customers/{customer_id}/risk`;
- customer, account, transaction, alert queue, alert detail, and case shell responses;
- method-not-allowed and invalid-path JSON errors;
- secure Wave 09 `/api/graph/entities/{entity_hint}` graph side views plus absent `/api/graph`, `/api/exports`, `/api/network`, `/api/entities`, `/api/checker`, `/api/attack-data`, and `/api/public/attack-data` probes. Wave 07 intentionally turns `/api/cases/{case_id}/duplicates` into a secure public-only side-view; Wave 08 intentionally turns `/api/cases/{case_id}/timeline` into a secure owner-only redacted audit view; Wave 09 intentionally turns only `/api/graph/entities/{entity_hint}` subroutes into secure metadata side views.

This test is deliberately route-level: a future handler that accidentally includes either private sentinel in an unrelated response fails with the leaking endpoint named in the assertion.

## Wave 06 Cross-Owner Visibility Matrix

Cross-owner authorization is visibility control. Wave 06 tests represent the current owner-only matrix as a single HTTP scenario:

- object-scoped customer, account, transaction, alert, case, case-note, and EDD operations return `404 {"error":"not_found"}` to a different analyst;
- `GET /api/alerts/queue` returns `200 OK` but includes only alerts linked to the authenticated analyst's customers;
- fail-closed responses do not disclose resource existence, owner identity, private note bodies, or EDD confidential comments;
- malformed path IDs return `400 {"error":"invalid_path"}` without private fields;
- unauthenticated protected routes return `401 {"error":"unauthenticated"}` before ownership checks.

Graph entity visibility does not imply access to private case notes or EDD confidential comments. Future side-view waves must document and test their own allowlists before adding routes.

## Wave 07 Dedup Metadata Visibility

Wave 07 stores `dedup_hint` on `cases` as non-secret matching metadata. It is used by the casework repository to discover duplicate candidates after the source case is verified against the requesting owner.

The repository candidate result is intentionally limited to safe case/customer metadata: case ID, customer ID, display name, country, risk level, status, public summary, risk score, typology hint, dedup hint, and timestamps. It does not include `CaseNote.body`, `EDDRecord.confidential_comment`, audit diffs, credentials, session material, owner IDs, checker-private fields, or raw database rows.

W07-T02 exposes secure authenticated dedup routes:

- `GET /api/cases/{case_id}/duplicates`
- `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`

These endpoints use explicit `CaseDuplicatePreviewView` DTOs with only `case_id`, `public_summary`, `risk_tags`, `overlap_score`, and `match_explanation`. They do not expose `CaseNote.body`, `EDDRecord.confidential_comment`, `private_notes`, internal evidence, audit diffs, credentials, sessions, checker-private markers, or raw database rows.

W07-T03 anti-AML-1 regression coverage plants high-entropy victim `CaseNote.body` and `EDDRecord.confidential_comment` values on a duplicate candidate and verifies that both the duplicate list and merge-preview omit the private strings. The tests also lock the response shape to `case_id`, `public_summary`, `risk_tags`, `overlap_score`, and `match_explanation`, and source-check the dedup DTO/presenter for private store references.

`scripts/check_wave07_gate.py` is the historical Wave 07 visibility gate for this surface. It requires the secure dedup DTO/projection contract, anti-AML-1 tests, and absent graph/export/network/audit/checker/public attack-data routes on the Wave 07 branch; Wave 08 intentionally adds only the secure owner case timeline audit route.

Wave 14 introduces AML-1 as a source-profiled vulnerable variant selected by
the Go build tag `aml1_vulnerable`. The default profile remains public-only.
Only the tagged AML-1 profile changes the merge-preview projection for
`GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview` by
adding duplicate `private_notes[].body` values from the matched duplicate case.

The AML-1 profile does not change duplicate candidate discovery, the duplicate
list response, owner note APIs, owner EDD APIs, audit, graph, export, or
network-room projections. `CaseNote.body` is intentionally exposed only through
the AML-1 merge-preview vulnerable profile and normal owner case-note APIs.
`EDDRecord.confidential_comment` remains private owner data and must not appear
in AML-1 merge-preview output.

`docs/09_vulnerability_matrix.md` is the source of truth for AML-1 vulnerable
behavior, exploit/fix sequencing, and protected-field boundaries.

## Wave 08 Audit Timeline Visibility

Wave 08 introduces secure owner audit visibility. `audit_events.diff_json` remains a sanitized internal persistence field generated by `internal/audit` redaction helpers, and HTTP handlers expose only explicit audit DTOs.

Sensitive audit diff fields are denylisted before persistence, including:

- `body`
- `case_note.body`
- `confidential_comment`
- `edd_record.confidential_comment`
- passwords and password hashes
- tokens and token hashes
- authorization/session material
- checker-private markers
- artificial flag fields

Sensitive values are stored as `[redacted]` with deterministic `sha256:` hashes. Raw `CaseNote.body` and `EDDRecord.confidential_comment` values must not appear in `audit_events.diff_json`, audit repository outputs, logs, public views, dedup views, graph/export/network projections, or checker paths.

`GET /api/cases/{case_id}/timeline` is owner-scoped through the case owner boundary. Its response allowlist is:

| Projection | Allowed fields | Forbidden fields |
| --- | --- | --- |
| `owner_case_audit` | `id`, `object_type`, `object_id`, `event_type`, `public_message`, `changes`, `created_at`, `visibility_scope` | `actor_user_id`, `owner_user_id`, raw `diff_json`, `body`, `confidential_comment`, hashes, credentials, sessions, checker-private fields |
| `owner_case_audit.change` | `field`, `old`, `new`, `redacted` | raw sensitive field names, value hashes, raw private values |

When a timeline event represents a sensitive field change, the HTTP projection collapses the field label to `sensitive_field` and returns `[redacted]` values without hashes. EDD create/update events are recorded in audit persistence for future owner/customer activity, but Wave 08 does not expose a customer activity route.

Still absent in Wave 08:

- `/api/customers/{customer_id}/activity`
- `/api/entities/{entity_hint}/activity`
- raw audit/diff endpoints
- graph/export/network/checker/public attack-data/debug/admin endpoints

The secure audit baseline keeps private business values redacted unless a scoped vulnerable source profile is explicitly selected.

Wave 15 introduces that scoped AML-2 vulnerable variant behind the
`aml2_vulnerable` Go build tag. The default profile remains the secure redacted
timeline described above. In the tagged AML-2 profile, only the owner
`GET /api/cases/{case_id}/timeline` audit presenter changes: for `case_note`
events whose redacted field is `body` or `case_note.body`, the response may
show `case_note.body` and the corresponding `CaseNote.body` value. The
repository still stores redacted `audit_events.diff_json`; the tagged presenter
recovers the owner note through the normal owner-scoped case-note repository
path.

The AML-2 profile does not change owner case-note APIs, owner EDD APIs, dedup
views, graph views, export bundles, network-room dossiers, checker PUT/GET, or
public attack data. `EDDRecord.confidential_comment`, EDD narrative fields,
audit hashes, credentials, sessions, checker-private state, raw flags, and raw
database rows remain forbidden outside their existing owner-only paths.

`docs/09_vulnerability_matrix.md` is the source of truth for AML-2 vulnerable
behavior, exploit/fix sequencing, and protected-field boundaries.

Anti-AML-2 regression coverage includes:

- `TestAntiAML2AuditTimelineDoesNotExposePrivateStores`, which plants high-entropy note and EDD sentinels, confirms owner note/EDD paths still work, and verifies timeline plus deferred activity responses do not disclose those sentinels;
- `TestAuditHTTPDTOAndPresenterRejectAML2RawExposure`, which source-checks the audit DTO and presenter sections for raw private fields, raw `diff_json`, value hashes, credentials, session markers, checker-private markers, and artificial flag fields;
- projection tests for `owner_case_audit` and `owner_case_audit.change`, which keep audit response allowlists explicit.

`scripts/check_wave08_gate.py` is the historical visibility gate for the secure audit baseline. It requires the timeline allowlist, Anti-AML-2 tests, and continued absence of graph/export/network/checker/public attack-data/debug/admin routes on the Wave 08 branch.

## Wave 09 Related Graph Visibility

Wave 09 adds backend graph persistence, repository primitives, and three secure graph HTTP endpoints:

- `GET /api/graph/entities/{entity_hint}`
- `GET /api/graph/entities/{entity_hint}/related-cases`
- `GET /api/graph/entities/{entity_hint}/edd-summaries`

It does not add `/api/graph`, `/api/entities`, public attack-data, checker, debug, admin, export, or network routes.

Graph access is deliberately separate from private case-note and EDD authorization. A caller may request safe graph repository summaries only when they own at least one customer whose normalized `entity_hint` matches the requested hint. That access condition allows safe related-entity metadata; it does not grant access to private investigation bodies or confidential EDD comments.

Safe graph repository and HTTP outputs may include:

- normalized entity hint;
- relation type;
- related customer and case counts;
- public risk tags;
- case ID and customer ID;
- customer display name, country, and risk level;
- case status, public summary, risk score, and typology hint;
- EDD review status;
- timestamps.

Forbidden graph output and query fields:

- `CaseNote.body`;
- `EDDRecord.confidential_comment`;
- EDD `source_of_funds`;
- EDD `risk_rationale`;
- raw audit `diff_json`;
- credentials, token hashes, session material, owner IDs, checker-private markers, artificial flag fields, public attack data, or raw DB rows.

The repository tests inspect graph query text and fail if the default graph
profile selects from `case_notes`, selects confidential EDD fields, reads audit
diffs, or includes auth/session/checker-private markers. The secure related
graph baseline remains metadata-only in the default build.

W09-T02 HTTP graph tests plant high-entropy `CaseNote.body` and `EDDRecord.confidential_comment` sentinels on related cases and EDD records, then assert the graph entity, related-cases, and EDD-summary responses omit both sentinel values and forbidden private field names. Graph source guards also reject raw graph presenter exposure of private stores, raw audit diffs, credentials, session material, owner IDs, checker-private markers, artificial flag fields, trace IDs, and counterparty fingerprints.

W09-T03 adds the named Anti-AML-3 matrix:

- `TestAntiAML3RelatedGraphDoesNotExposePrivateStores` keeps owner note and owner EDD visibility intact, creates a second analyst sharing the same entity hint, and verifies all secure graph endpoints omit victim private sentinels for both users;
- `TestAntiAML3GraphProjectionContractsDenyPrivateFields` checks graph projection contracts for forbidden private, auth/session, checker, trace, and raw-row fields;
- `TestAntiAML3GraphRepositorySummariesStayMetadataOnly` source-checks graph repository summary structs and query methods so private note, confidential EDD, raw audit, credential, session, checker-private, and artificial flag markers do not enter graph repository outputs.

Wave 16 introduces AML-3 only under the `aml3_vulnerable` Go build tag. In that
tagged profile, only
`GET /api/graph/entities/{entity_hint}/edd-summaries` may add
`confidential_comment` to related EDD summary items after the requester passes
the normal owned-`entity_hint` graph access check. `docs/09_vulnerability_matrix.md`
is the source of truth for the AML-3 behavior and protected-field list.

The AML-3 profile does not change the default graph DTOs, the graph entity
summary endpoint, the related-case endpoint, owner note/EDD authorization, or
checker GET. It must not expose `CaseNote.body`, EDD `source_of_funds`, EDD
`risk_rationale`, raw audit diffs, export bundles, network-room dossiers,
credentials, sessions, checker-private state, public attack data, raw database
rows, debug/admin controls, or reference exploit/fix behavior.

Wave 16 is complete. The future reference exploit
`sploits/sentinel_aml/aml_related_graph.py` remains locked until Wave 21 when
the orchestrator opens that exploit wave, and the related graph fix remains
locked until Wave 26 after exploit evidence is captured.

## Wave 10 Export Redaction Visibility

Wave 10 moves export projection contracts from future planning into the current secure side-view allowlist. W10-T02 activates the secure owner-scoped export routes:

- `POST /api/cases/{case_id}/exports`
- `GET /api/exports/{export_id}`
- `POST /api/disputes`
- `POST /api/disputes/{dispute_id}/export`

Current export projection contracts are:

- `export_bundle`
- `export_case_shell`
- `export_audit_summary`
- `export_edd_summary`
- `export_item_metadata`

These contracts define recursive public/redacted export output for root cases, linked cases, audit summaries, EDD summaries, and export item metadata. The redaction policy is `public_redacted` by default for root and linked objects.

Export projections may show public case shells, public audit messages, redacted changed-field labels such as `sensitive_field`, EDD review status, risk tags, item metadata, and timestamps. They must not show private note bodies, EDD confidential comments, EDD `source_of_funds`, EDD `risk_rationale`, raw audit `diff_json`, audit value hashes, credentials, sessions, checker-private markers, public attack data, artificial flag fields, or raw DB rows.

Export route access does not broaden private investigation visibility. `GET /api/exports/{export_id}` is scoped through `exports.owner_user_id`; case and dispute export creation resolve through owned cases or owned disputes before any bundle is returned.

Wave 17 introduces AML-4 only under the `aml4_vulnerable` Go build tag. The
default build keeps the secure Wave 10 recursive export redaction behavior:
root and linked cases appear as public shells, audit and EDD entries appear as
safe summaries, and `CaseNote.body` plus `EDDRecord.confidential_comment`
remain absent from export bundles.

In the tagged AML-4 profile, only
`POST /api/disputes/{dispute_id}/export` may add `linked_private_notes[]` to
the export bundle. Those entries are limited to linked duplicate-case private
analyst notes with `case_id`, `note_id`, and `body`. Root private notes, EDD
confidential comments, EDD narrative fields, audit diffs, credentials,
sessions, checker-private state, graph data, network-room dossier data, raw
database rows, public attack data, debug/admin controls, reference exploit
behavior, and reference fix behavior remain forbidden.

`docs/09_vulnerability_matrix.md` is the source of truth for AML-4 vulnerable
behavior, exploit/fix sequencing, and protected-field boundaries.

## Wave 10 Network-Room Dossier Visibility

W10-T03 adds network-room persistence and safe dossier primitives. W10-T04 activates only the secure network-room HTTP routes:

- `GET /api/network/rooms`
- `GET /api/network/rooms/{room_id}`
- `POST /api/network/rooms/{room_id}/join`
- `GET /api/network/rooms/{room_id}/dossier`

Current network-room projection contracts are:

- `network_room_summary`
- `network_room_case`
- `network_room_dossier`

Network-room storage is references-first. Room records store deterministic entity/typology metadata, public risk tags, participant metadata, and case references. Safe dossiers may include room metadata, membership counts, public case shells, typology hints, public risk tags, and an explicit `private_data_omitted` marker.

Room participation is not private case, note, EDD, audit, export, or checker visibility. Network-room repositories and DTO contracts must not store or return private note bodies, EDD confidential comments, raw EDD narrative fields, raw audit diffs, value hashes, credentials, sessions, counterparty fingerprints, trace IDs, owner-only IDs beyond safe public references, checker-private markers, public attack data, artificial flag fields, or raw source case blobs.

W10-T04 HTTP regression tests plant private note and EDD sentinels in own and foreign cases, then verify those strings are absent from room list, room detail, join, dossier, cross-participant, unauthenticated, invalid-path, method-not-allowed, and absent route responses. Public case summaries may appear in dossiers for both own and foreign cases, with `owned_by_requester` and `private_data_omitted` making the redaction boundary explicit.

The default network-room profile remains the secure Wave 10 baseline. Room
participation normally grants access only to room metadata, participant
metadata, source-case references, public case shells, public risk tags, and
`private_data_omitted`; it does not grant default access to foreign private
case notes, EDD confidential comments, EDD narrative fields, audit diffs,
credentials, sessions, checker-private state, public attack data, or raw
database rows.

Wave 18 introduces AML-5 only under the `aml5_vulnerable` Go build tag. In
that tagged profile, `GET /api/network/rooms/{room_id}/dossier` may add
bounded `foreign_private_notes` and `foreign_edd_comments` after the normal
network-room clustering/materialization and participant path. The tagged
projection is intentionally local to the dossier response; owner note APIs,
owner EDD APIs, checker PUT/GET, graph, export, audit, public attack data, and
the default secure network-room profile are not broadened.

`docs/09_vulnerability_matrix.md` is the source of truth for AML-5 vulnerable
behavior, exploit/fix sequencing, and protected-field boundaries. The future
reference exploit `sploits/sentinel_aml/aml_network_room.py` remains locked
until Wave 23 is opened after Wave 18 acceptance.

## Operational Surface

`/healthz` and `/readyz` remain operational-only. They must not expose product data, checker state, configuration secrets, database details, flags, or debug metadata.

## Guardrails

No debug, admin, shell, direct database, broad export, or accidental all-field projection may be introduced as a shortcut.
