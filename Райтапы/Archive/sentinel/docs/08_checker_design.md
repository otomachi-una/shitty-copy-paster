# Sentinel AML - Checker Design

Wave 13 starts from the accepted two-place checker and adds the CHECK/HAVOC
framework. The checker remains a normal HTTP client of the product APIs and
does not receive any repository, database, debug, admin, or hidden helper path.
AD-C0 accepts the two-place checker contract; Wave 13 may start without
flag-store ambiguity.

## Files

- `checkers/sentinel_aml/checker.py`
- `checkers/sentinel_aml/checker_lib.py`
- `checkers/sentinel_aml/requirements.txt`

The checker uses only the Python standard library.

## Actions

- `check <host>` runs the named CHECK subcheck dispatcher.
- `havoc <host>` runs the same safe dispatcher framework for pre-noise coverage.
- `put <host> [external_flag_id] <flag> <place>` dispatches place 1 and place 2.
- `get <host> <private_flag_id> <flag> <place>` dispatches place 1 and place 2.
- `putnoise <host> [seed]` creates deterministic non-secret noise objects and
  returns a MAC-protected `noise_id` plus credential-free public noise locators.
- `getnoise <host> <noise_id>` restores private noise state and verifies the
  noise objects remain reachable through normal owner/public-redacted APIs.

Unsupported actions, malformed arguments, and unsupported place values fail
closed with a non-zero checker result. Historical Wave 11 behavior kept place
2 deferred until Wave 12; Wave 12 now makes place 2 an explicit checker
contract.

## Final Scenario Matrix

The final checker scenario inventory is implemented by
`checker_lib.checker_scenario_inventory()` and covered by
`tests/test_checker_scenario_inventory.py`. `make ad-stability-gate` includes
all `test_checker_*.py` tests, so this matrix is part of the archive-free
stability gate.

| Scenario | Action | Store / Surface | Normal API evidence |
| --- | --- | --- | --- |
| `place1_put` | `put` place 1 | `CaseNote.body` | Register/login owner, create customer/account/transaction/alert/case, then write the flag with `POST /api/cases/{case_id}/notes`. |
| `place1_get` | `get` place 1 | `CaseNote.body` | Decode MAC state, use owner token or owner re-login, then read only `GET /api/cases/{case_id}/notes`. |
| `place2_put` | `put` place 2 | `EDDRecord.confidential_comment` | Register/login owner, create customer, then write the flag with `POST /api/customers/{customer_id}/edd`. |
| `place2_get` | `get` place 2 | `EDDRecord.confidential_comment` | Decode MAC state, use owner token or owner re-login, then read only `GET /api/customers/{customer_id}/edd`. |
| `health` | `check` / `havoc` | Liveness | `GET /healthz`. |
| `check_basic` | `check` / `havoc` | Core business flow | Auth, customer, account, transaction, alert queue, and readback APIs. |
| `check_case_notes` | `check` / `havoc` | Owner case notes | `POST` and `GET /api/cases/{case_id}/notes` with non-flag note content. |
| `check_edd` | `check` / `havoc` | Owner EDD | `POST` and `GET /api/customers/{customer_id}/edd` with non-flag confidential-comment content. |
| `check_dedup` | `check` / `havoc` | Secure dedup projection | Duplicate candidate and merge-preview APIs, verified as public-only. |
| `check_audit` | `check` / `havoc` | Secure audit projection | Owner timeline API, verified redacted for sensitive note changes. |
| `check_graph` | `check` / `havoc` | Secure graph projection | Graph entity and related-case APIs, verified public-only. |
| `check_export` | `check` / `havoc` | Secure export projection | Case export create/read APIs, verified `public_redacted`. |
| `check_network_room` | `check` / `havoc` | Secure network-room projection | Room list and dossier APIs, verified references-only. |
| `check_retention` | `check` / `havoc` | Flag-store retention | Source scan rejects physical delete/truncate/drop paths for `case_notes` and `edd_records`. |
| `putnoise` | `putnoise` | Non-flag business noise | Creates deterministic customer/account/transaction/case/note/EDD/export/graph/network locator data. |
| `getnoise` | `getnoise` | Non-flag business noise | Reauthenticates from MAC state and verifies stored non-flag locators. |

Public attack data is locator-only. Place 1 exposes only service,
case/customer locators, an entity/party reference, and the product matching
reference needed by reference exploits. Place 2 exposes only service,
customer and entity/party locators. Public data and public noise data must not
contain usernames, passwords, bearer tokens, sessions, raw flags, checker
secrets, private state, store labels, direct `dedup_hint` / `typology_hint`
keys, or `confidential_comment`.

## Wave 13 CHECK/HAVOC Framework

`check <host>` and `havoc <host>` use `run_check` / `run_havoc`, which execute
`DEFAULT_CHECK_SUBCHECKS` through `run_check_subchecks`. Each subcheck has a
stable name, description, and runner. W13-T02 enabled basic, notes, and dedup
business checks. W13-T03 added audit and graph safety checks. W13-T04 added
export and network-room anti-coarse-fix checks. W13-T05 adds noise and retention
guards. The default set is:

- `health`: verifies `GET /healthz`.
- `check_basic`: registers/logs in, creates a customer, creates an account,
  creates a transaction, then reads the customer, account list, transaction,
  and customer transaction list back through normal APIs.
- `check_case_notes`: creates an owned alert/case workflow, writes a non-secret
  private note through `POST /api/cases/{case_id}/notes`, and reads it through
  `GET /api/cases/{case_id}/notes` as the owner.
- `check_edd`: creates an owned customer, writes a non-secret EDD record
  through `POST /api/customers/{customer_id}/edd`, and reads it through
  `GET /api/customers/{customer_id}/edd` as the owner.
- `check_dedup`: creates two owned cases with the same `dedup_hint`, verifies
  `GET /api/cases/{case_id}/duplicates`, and verifies
  `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`
  returns only secure public preview fields.
- `check_audit`: creates an owned alert/case workflow, writes a non-secret
  private note, reads `GET /api/cases/{case_id}/timeline`, verifies a
  case-note event exists, and requires the sensitive change to be redacted.
- `check_graph`: creates two owned investigation cases for customers sharing
  the same `entity_hint`, reads `GET /api/graph/entities/{entity_hint}` and
  `GET /api/graph/entities/{entity_hint}/related-cases`, then verifies public
  graph DTO fields and relation counts.
- `check_export`: creates an owned case, non-secret private note, and EDD
  context, requests `POST /api/cases/{case_id}/exports`, retrieves
  `GET /api/exports/{export_id}`, and verifies the export bundle uses the
  public redaction shape.
- `check_network_room`: creates deterministic same-entity cases, reads
  `GET /api/network/rooms` until a bounded deterministic worker window expires,
  finds the materialized matching room, retrieves
  `GET /api/network/rooms/{room_id}/dossier`, and verifies references-only
  public room/case DTOs.
- `check_retention`: scans the packaged source tree for physical delete/truncate
  paths against retention-sensitive flag-store tables.

The framework aggregates independent subcheck failures and maps them to
Hackerdom-compatible non-OK exit codes. Service connection failures and
timeouts map to down; malformed responses, bad statuses, unsupported subchecks,
or framework contract errors map to mumble.

`safe_error_message` and `redact_sensitive` sanitize CHECK/HAVOC and top-level
checker errors before printing them. Error output must not include raw flags,
private state, credentials, bearer/session tokens, checker secrets, or
server-provided secret-bearing text.

CHECK/HAVOC remains a normal API client. It must not use hidden checker-only
routes, debug/admin routes, direct DB access, or public attack-data routes. It
must not use any side-view endpoint to recover flags. The dedup, audit, graph,
export, and network-room subchecks may use their secure public/redacted
side-view APIs only to validate projection behavior and guard against coarse
module disabling. They must reject private fields such as note bodies, EDD
confidential comments, private-note markers, raw audit diffs, credentials,
tokens, sessions, owner IDs, or checker private-state markers.

Wave 14 introduces AML-1 only in the `aml1_vulnerable` product profile, where
dedup merge-preview can expose duplicate `private_notes[].body`. That behavior
does not change checker PUT/GET. Place 1 GET continues to read only owner
notes, place 2 GET continues to read only owner EDD, and public attack data
remains locator-only. The vulnerability behavior and exploit/fix schedule are
governed by `docs/09_vulnerability_matrix.md`.

Wave 15 introduces AML-2 only in the `aml2_vulnerable` product profile, where
the owner audit timeline can expose `CaseNote.body` as a `case_note.body`
change record. That behavior is not a checker retrieval path. Place 1 GET must
continue to use only `GET /api/cases/{case_id}/notes`, place 2 GET must
continue to use only `GET /api/customers/{customer_id}/edd`, and CHECK/HAVOC
must continue to reject broad audit, graph, export, network-room, credential,
or private-state leakage according to `docs/09_vulnerability_matrix.md`.

`check_network_room` does not create rooms through a hidden checker endpoint.
Current product HTTP support exposes list/detail/join/dossier routes, while room
creation/materialization remains product-side/internal. The checker therefore
creates deterministic same-entity case inputs and fails closed if no matching
participant-visible room is materialized within the bounded wait. Owner
timeline and direct note/EDD GET paths remain owner-only and are not replaced by
network-room, graph, export, audit, or dedup side views.

## Wave 34 Clean-Deploy CHECK/HAVOC Evidence

W34-T05 adds `scripts/check_live_checker_clean_deploy.py` as the focused
clean-deploy proof for CHECK/HAVOC. Static mode verifies the checker registry
contains every default subcheck and that `check_network_room` has a bounded
materialization wait. Live mode starts a clean PostgreSQL database, applies
migrations, starts the competition-tagged Go API and worker, then runs:

```powershell
python -B scripts\check_live_checker_clean_deploy.py --run --python python --go go --docker docker --json-output tmp\live-checker-clean-deploy.json
```

Recorded W34-T05 evidence on the local target environment:

- exit code: `0`;
- elapsed: `18.094s`;
- build tags: `case_match_preview audit_detail_view entity_review_summary linked_case_export_detail network_room_detail`;
- `clean:checker-check`: exit `101`, classification `OK`;
- `clean:checker-havoc`: exit `101`, classification `OK`.

CHECK/HAVOC subchecks and the coarse fix they catch:

| Subcheck | Coarse fix or regression caught |
| --- | --- |
| `health` | API process unavailable or health route removed. |
| `check_basic` | Auth, customer, account, transaction, alert creation, or core readback disabled. |
| `check_case_notes` | Owner case-note create/list disabled or note body persistence broken. |
| `check_edd` | Owner EDD create/read disabled or confidential-comment persistence broken. |
| `check_dedup` | Duplicate candidate or merge-preview module removed, malformed, or leaking private fields. |
| `check_audit` | Owner timeline disabled, case-note events missing, or audit redaction broken. |
| `check_graph` | Entity graph or related-case module disabled, malformed, or leaking private fields. |
| `check_export` | Export creation/read disabled, malformed, or no longer `public_redacted`. |
| `check_network_room` | Worker lifecycle/room route disabled, matching rooms not materialized, dossier malformed, or dossier leaking broader private data outside the selected competition projection. |
| `check_retention` | Physical delete/truncate/drop paths added against checker flag-store tables. |

Checker exit evidence is classified explicitly as Hackerdom-compatible `OK`
(`101`), `CORRUPT` (`102`), `MUMBLE` (`103`), `DOWN` (`104`), or
`CHECKER_ERROR` (`110`). The live harness still talks to the checker CLI and
normal HTTP APIs only; it does not read the database or use debug/admin routes.

## Noise Actions

`putnoise <host> [seed]` creates ordinary, non-flag business objects through the
same HTTP client helpers used by CHECK:

1. Register/login a deterministic checker noise analyst.
2. Create two customers sharing a graph `entity_hint`.
3. Create accounts, suspicious transactions, alerts, and cases for those
   customers.
4. Add a non-secret private case note.
5. Add a non-secret EDD record.
6. Create and retrieve a redacted case export.
7. Read graph/network-room locators where those public side views are safely
   materialized.

The returned public noise data contains only service/kind, customer IDs, case
IDs, transaction IDs, EDD record ID, export ID, graph hint, and optional network
room ID. It must not contain usernames, passwords, bearer tokens, sessions, raw
flags, `CaseNote.body`, `EDDRecord.confidential_comment`, checker secrets, or
private state. `getnoise` uses the MAC-protected private `noise_id` to
reauthenticate and verify the stored noise locators.

## Retention Smoke

The checker retention smoke identifies `case_notes` and `edd_records` as
retention-sensitive because they back place 1 and place 2 flag stores. It scans
packaged migrations, product source, and scripts for physical `DELETE`,
`TRUNCATE`, or `DROP TABLE` paths targeting those tables. This is a smoke guard,
not a substitute for future live flag-lifetime testing.

## Place 1 PUT Flow

Place 1 maps to `CaseNote.body`. PUT uses normal owner-authenticated business
APIs:

1. Register a deterministic checker-owned analyst with `POST /api/auth/register`.
2. Login with `POST /api/auth/login` and use that bearer token for the business workflow.
3. Create a deterministic customer with `POST /api/customers`.
4. Create an account with `POST /api/customers/{customer_id}/accounts`.
5. Create a suspicious high-value transaction with `POST /api/transactions`.
6. Read the deterministic alert from `GET /api/alerts/queue`.
7. Claim the alert with `POST /api/alerts/{alert_id}/claim`.
8. Create a case with `POST /api/alerts/{alert_id}/case`.
9. Store the flag as private analyst note content with `POST /api/cases/{case_id}/notes`.

The raw flag is sent only in the JSON body of the private case-note creation
request as `{"visibility":"private","body":flag}`. It is not sent in auth,
customer, account, transaction, alert, case, public attack-data, logs, or error
messages.

## Place 1 GET Flow

GET decodes and verifies the private state, compares the requested flag to the
state idempotency key, then authenticates as the original checker-created owner.
It first tries the stored bearer token. If the owner note endpoint returns
`401` or `403`, GET logs in with the private-state username/password and retries
with the fresh owner token.

GET reads flags only through:

```text
GET /api/cases/{case_id}/notes
```

It does not use public attack data as credential state and does not read flags
from dedup, audit timeline, graph, export, network-room, merge-preview, or other
side-view endpoints. Verification is exact: the expected note must have the
private-state `note_id`, the private-state `case_id`, and `body == flag`.

## Failure Mapping

- Valid flag found in owner notes: `OK`.
- Wrong flag for private state or tampered private state: corrupt.
- Missing case/note owner view or missing expected note body: corrupt.
- Unsupported place values: mumble/fail-closed.
- Malformed arguments or unexpected response shape: mumble.
- Service connection failure or timeout: down.
- Authentication failure after token retry and login: mumble.

Checker error messages must not include raw flags, private state envelopes,
credentials, tokens, or server-provided error text.

## Place 2 Contract

Place 2 maps to `EDDRecord.confidential_comment`. The Wave 12 state contract
uses the normal owner EDD API family:

```text
POST /api/customers/{customer_id}/edd
GET /api/customers/{customer_id}/edd
PATCH /api/customers/{customer_id}/edd
```

W12-T01 defines the tamper-detecting state and public attack-data schemas plus
explicit CLI dispatch. W12-T02 implements PUT with this route sequence:

1. Register a deterministic checker-owned analyst with `POST /api/auth/register`.
2. Login with `POST /api/auth/login`.
3. Create a deterministic customer with `POST /api/customers`.
4. Store the flag as `confidential_comment` with `POST /api/customers/{customer_id}/edd`.

The raw flag is sent only as the `confidential_comment` value in the owner EDD
create request. It is not sent in auth, customer, public attack-data, logs, or
error messages.

W12-T03 implements GET by decoding private state, checking the idempotency key,
trying the stored bearer token, and re-authenticating on `401` or `403`.

GET reads place 2 flags only through:

```text
GET /api/customers/{customer_id}/edd
```

Verification is exact: the owner EDD response must have the private-state
`edd_record_id`, the private-state `customer_id`, and
`confidential_comment == flag`. Missing EDD owner view, missing
`confidential_comment`, identity mismatch, or bad comment value is corrupt. GET
must not read or recover flag material from dedup, audit, graph, export,
network-room, merge-preview, or other side-view endpoints.

## Private State

The private `flag_id` is a base64url-encoded JSON envelope:

```json
{
  "payload": {
    "schema_version": 1,
    "service": "sentinel_aml",
    "store": "CaseNote.body",
    "place": 1,
    "username": "...",
    "password": "...",
    "token": "...",
    "customer_id": 1,
    "case_id": 1,
    "note_id": 1,
    "dedup_hint": "...",
    "typology_hint": "...",
    "idempotency_key": "..."
  },
  "mac": "hex-encoded HMAC-SHA256 over canonical payload JSON"
}
```

The MAC key is the checker secret from `SENTINEL_AML_CHECKER_SECRET`, falling
back to a deterministic development secret for local tests. GET rejects missing
fields, schema drift, service/store/place mismatches, and MAC tampering before
using the state.

Place 2 uses the same envelope and MAC contract with this payload:

```json
{
  "payload": {
    "schema_version": 1,
    "service": "sentinel_aml",
    "store": "EDDRecord.confidential_comment",
    "place": 2,
    "username": "...",
    "password": "...",
    "token": "...",
    "customer_id": 1,
    "edd_record_id": 1,
    "entity_hint": "...",
    "typology_hint": "...",
    "idempotency_key": "..."
  },
  "mac": "hex-encoded HMAC-SHA256 over canonical payload JSON"
}
```

Place-aware decoding rejects a place 1 state supplied to a place 2 request and
rejects a place 2 state supplied to a place 1 request. Store mismatches, missing
fields, malformed envelopes, and MAC tampering fail before HTTP work.

## Public Attack Data

Place 1 public attack data contains only:

```json
{
  "service": "sentinel_aml",
  "case_ref": "case-1",
  "case_id": 1,
  "customer_ref": "customer-1",
  "customer_id": 1,
  "entity_ref": "...",
  "party_ref": "...",
  "matching_reference": "..."
}
```

It must not include usernames, passwords, tokens, sessions, raw flags, checker
secrets, password hashes, session hashes, store labels, direct
`dedup_hint` / `typology_hint` keys, or the private state envelope.

Place 2 public attack data contains only:

```json
{
  "service": "sentinel_aml",
  "customer_ref": "customer-1",
  "customer_id": 1,
  "entity_ref": "...",
  "party_ref": "..."
}
```

The shared public-data safety assertion applies to both places and rejects
credential, token, session, raw flag, checker-secret, or private-state markers.
It also rejects public `store`, `dedup_hint`, `typology_hint`, `entity_hint`,
literal owner-storage labels, and the literal `confidential_comment` field name
in public attack data.

## Idempotency

The deterministic idempotency key is:

```text
HMAC_SHA256(checker_secret, flag + "\x00" + place + "\x00" + "sentinel_aml")
```

The checker uses derived names and hints from this key to avoid randomness in
PUT setup. The raw flag is never included in public attack data.
