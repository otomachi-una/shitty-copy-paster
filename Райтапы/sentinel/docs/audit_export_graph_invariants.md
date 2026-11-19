# Sentinel AML — Audit Export and Graph Invariants

Wave 01 implements no audit export, graph view, or analytics API.

Future audit and graph features must use explicit projections, preserve visibility boundaries, and avoid direct database model serialization. Export behavior must not expose checker-private state, credentials, or hidden debug data.

## Wave 08 Secure Audit Baseline

Wave 08 adds redacted audit persistence and `GET /api/cases/{case_id}/timeline` for the owning analyst only. The timeline is an owner workflow view, not a public side view and not AML-2.

Audit HTTP responses use explicit DTOs and may show public event metadata plus redacted change records. They must not expose raw `audit_events.diff_json`, actor/owner database fields, `CaseNote.body`, `EDDRecord.confidential_comment`, value hashes, credentials, session data, checker-private fields, public attack data, debug/admin metadata, graph data, export data, or network-room data.

Customer activity and entity activity remain deferred until a later wave defines safe owner or projection semantics. Graph, export, network, checker, public attack-data, debug, and admin routes remain absent.

## Wave 15 AML-2 Vulnerable Audit Profile

Wave 15 adds the `aml2_vulnerable` Go build-tag profile. The default build
continues to use the secure Wave 08 redacted timeline. In the tagged vulnerable
profile, only the owner case timeline presenter may expose `CaseNote.body`
through a `case_note.body` change record for `case_note` audit events.

The AML-2 profile is deliberately local:

- audit persistence still stores redacted `audit_events.diff_json`;
- the vulnerable presenter recovers note content only through the owner-scoped
  case-note repository path after the case owner check has passed;
- cross-owner and unauthenticated timeline requests still fail closed;
- `EDDRecord.confidential_comment`, EDD narrative fields, hashes, credentials,
  session material, checker-private state, public attack data, graph data,
  export bundles, and network-room dossiers remain excluded.

Reference exploit and reference fix artifacts for AML-2 remain locked. The
source of truth for vulnerability behavior and sequencing is
`docs/09_vulnerability_matrix.md`.

## Wave 09 Secure Graph Baseline

Wave 09 adds `entity_graph_nodes` and `entity_graph_edges` persistence, `internal/graph` repository primitives, and secure graph HTTP endpoints under `/api/graph/entities/{entity_hint}`. It does not add the graph root, `/api/entities`, a public graph feed, checker path, export path, network-room path, or AML-3 vulnerable behavior.

Graph authorization is based on a narrow condition: the requesting analyst must own at least one customer with the requested normalized `entity_hint`. That condition permits safe related-entity metadata such as public case summaries, risk scores, typology hints, review statuses, counts, relation types, and timestamps. It does not expand private case-note or EDD permissions.

Graph repository queries must not select or join `CaseNote.body`, `EDDRecord.confidential_comment`, EDD source-of-funds details, EDD risk rationale, raw `audit_events.diff_json`, credentials, tokens, sessions, checker-private fields, public attack data, or artificial flag fields.

Graph HTTP responses use explicit DTOs only:

- `GraphEntityView`
- `GraphRelatedCaseView`
- `EDDGraphSummaryView`

Those DTOs may expose normalized entity hints, relation type, safe counts, public case summaries, risk tags, review status, and timestamps. They must not expose private note bodies, EDD confidential comments, EDD narrative fields, raw audit diffs, credentials, session material, owner IDs, checker-private markers, artificial flag fields, or raw DB rows.

## Wave 16 AML-3 Vulnerable Graph Profile

Wave 16 adds the `aml3_vulnerable` Go build-tag profile. The default build
continues to use the secure Wave 09 graph DTOs. In the tagged vulnerable
profile, only `GET /api/graph/entities/{entity_hint}/edd-summaries` may add the
`confidential_comment` field to related EDD summaries for a normalized
`entity_hint` cluster where the requester owns at least one customer.

The AML-3 profile is deliberately local:

- graph access still requires normal authentication and the owned-entity-hint
  condition;
- the vulnerable lookup selects only EDD `confidential_comment` for related EDD
  summaries;
- cross-owner direct note and EDD owner APIs remain fail closed;
- graph entity summaries, related-case summaries, export bundles, network-room
  dossiers, and audit timelines are not broadened;
- `CaseNote.body`, EDD `source_of_funds`, EDD `risk_rationale`, raw audit
  diffs, hashes, credentials, sessions, checker-private state, public attack
  data, raw DB rows, and debug/admin controls remain excluded.

Reference exploit and reference fix artifacts for AML-3 remain locked. The
source of truth for vulnerability behavior and sequencing is
`docs/09_vulnerability_matrix.md`.

## Wave 10 Secure Export Baseline

Wave 10 adds export/dispute persistence, redaction primitives, and secure owner-scoped export HTTP routes. It introduces `disputes`, `exports`, and `export_items` tables plus `internal/exporting`, then exposes only `POST /api/cases/{case_id}/exports`, `GET /api/exports/{export_id}`, `POST /api/disputes`, and `POST /api/disputes/{dispute_id}/export`. It does not register checker paths, public attack-data paths, network-room routes, exploit scripts, reference fixes, or AML-4 vulnerable behavior.

Export redaction is public/redacted by default and recursive across the root case, linked cases, audit summaries, EDD summaries, and export item metadata. Linked objects use the same redaction policy as the root export unless a later owner-authorization wave explicitly narrows or expands that rule.

Safe export bundles may include public case shells, safe audit event labels, EDD review/risk tags, deterministic item metadata, timestamps, and the `public_redacted` policy marker. They must not include `CaseNote.body`, `EDDRecord.confidential_comment`, EDD `source_of_funds`, EDD `risk_rationale`, raw `audit_events.diff_json`, audit value hashes, credentials, session material, checker-private fields, public attack data, artificial flag fields, or raw DB rows.

Export retrieval is owner-scoped through the stored export owner. Case export creation and dispute export creation must resolve the owned case or owned dispute before returning any bundle. Linked cases are included only as public/redacted shells.

## Wave 17 AML-4 Vulnerable Export Profile

Wave 17 adds the `aml4_vulnerable` Go build-tag profile. The default build
continues to use the secure Wave 10 recursive export redaction behavior. In the
tagged vulnerable profile, only
`POST /api/disputes/{dispute_id}/export` may add `linked_private_notes[]` to
the export bundle for linked duplicate cases. Each entry is limited to
`case_id`, `note_id`, and the linked case private note `body`.

The AML-4 profile is deliberately local:

- dispute export still requires normal authentication and owned-dispute access;
- linked note collection is limited to cases that are duplicate candidates for
  the requester-owned root case;
- ordinary case exports and default-build dispute exports remain recursively
  redacted;
- root private notes, `EDDRecord.confidential_comment`, EDD narrative fields,
  raw audit diffs, hashes, credentials, sessions, checker-private state, public
  attack data, graph data, and network-room dossiers remain excluded;
- cross-owner direct note and EDD owner APIs remain fail closed.

Reference exploit and reference fix artifacts for AML-4 remain locked. The
correct future fix is recursive export context serialization and redaction for
root cases, linked cases, evidence, notes, audit events, and EDD records. The
source of truth for vulnerability behavior and sequencing is
`docs/09_vulnerability_matrix.md`.

## Wave 10 Secure Network-Room Baseline

W10-T03 adds `network_rooms`, `network_room_cases`, `network_room_participants`, and `internal/networkroom` repository primitives. It does not expose network-room HTTP routes, add workers, register checker paths, publish public attack data, create exploit/reference-fix scripts, or implement AML-5 vulnerable dossier behavior.

Network-room storage is references-first. Room records may store deterministic `room_key`, `entity_hint`, `typology_hint`, status, public summary, public risk tags, creator, timestamps, case IDs, participant IDs, and participant roles. They must not copy private note bodies, EDD confidential comments, EDD narrative fields, raw audit diffs, value hashes, raw source case blobs, credentials, sessions, checker-private fields, public attack data, or artificial flag fields.

Safe dossiers may include room metadata, membership counts, public case shells, typology hints, public risk tags, and `private_data_omitted`. Room participation does not grant private source-case, note, EDD, audit, export, checker, debug, or admin visibility.

AML-5 remains future-only. Later route work must keep this secure baseline unless a scoped vulnerability wave intentionally changes it.
