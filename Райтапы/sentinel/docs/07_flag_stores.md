# Sentinel AML - Flag Stores

Wave 12 preserves the Wave 11 place 1 checker lifecycle and activates the
place 2 checker state contract and dispatch for `EDDRecord.confidential_comment`.
AD-C0 formally accepts both stores as active checker places.

## Places

- Place 1 maps to `CaseNote.body`, a normal private analyst note field
  reachable through owner-authenticated case-note APIs.
- Place 2 maps to `EDDRecord.confidential_comment`, a normal private EDD
  review field in owner-scoped persistence and owner-only EDD HTTP DTOs.

`CaseNote.body` is now the active Wave 11 place 1 store, but it remains normal
private business data. The checker writes it only through
`POST /api/cases/{case_id}/notes` and reads it only through
`GET /api/cases/{case_id}/notes` with the owner credentials stored in private
checker state.

Place 1 PUT creates the surrounding investigation through ordinary APIs:
register analyst, login, create customer, create account, create suspicious
transaction, read and claim the generated alert, create case, and then add the
private case note. The raw flag is present only in the private note creation
request body and never in public attack data or non-note setup requests.

Place 1 GET verifies flags only through the owner case-note list endpoint:
`GET /api/cases/{case_id}/notes`. It may use the private-state bearer token or
re-authenticate with private-state owner credentials, but it must not use public
attack data as credentials and must not read flag material from dedup, audit,
graph, export, network-room, merge-preview, or other side-view endpoints.

Historical Wave 11 marker: Checker place 2 remains deferred in Wave 11 only,
where `EDDRecord.confidential_comment` was fail-closed. Wave 12 removes that
deferral: place 2 maps to the owner-scoped EDD confidential comment store; the
checker writes it through `POST /api/customers/{customer_id}/edd` and reads it
through `GET /api/customers/{customer_id}/edd` with the owner credentials
stored in private checker state.

Place 2 PUT creates a checker-owned analyst, logs in, creates a deterministic
customer, and creates an owner EDD record with the raw flag only in the
`confidential_comment` field. Place 2 GET verifies the owner EDD response by
matching `id`, `customer_id`, and `confidential_comment == flag`, with
re-authentication on stale bearer tokens.

## State Split

Private checker state may contain checker-owned owner credentials, a bearer
token, place-specific owner object IDs, public hints, and the idempotency key.
It is MACed with HMAC-SHA256 using the checker secret.

Public attack data contains only `service`, `store`, `case_id`, `customer_id`,
`dedup_hint`, and `typology_hint`. It must not contain usernames, passwords,
tokens, sessions, raw flags, checker secrets, password hashes, session hashes,
or the private state envelope.

Place 1 public attack data contains only `service`, `store`, `case_id`,
`customer_id`, `dedup_hint`, and `typology_hint`.

Place 2 private checker state contains service/store/place identifiers, owner
username/password/token recovery data, `customer_id`, `edd_record_id`,
`entity_hint`, `typology_hint`, and the idempotency key. Place 2 public attack
data contains only `service`, `store`, `customer_id`, `entity_hint`, and
`typology_hint`. Its public `store` value is `EDDRecord`, while the exact
`EDDRecord.confidential_comment` field name stays in private state and docs; it
must not appear in public attack data.

## Invariants

Flags must be embedded only through normal business workflows. There must be no
synthetic flag endpoint, direct database checker path, debug API, admin
shortcut, hidden helper route, or public credential leakage.

For place 2, `EDDRecord.confidential_comment` remains private owner data. GET
must not use dedup, audit, graph, export, network-room, or any other side-view
projection to retrieve the flag.
