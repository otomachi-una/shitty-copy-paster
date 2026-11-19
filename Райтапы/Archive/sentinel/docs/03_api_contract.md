# Sentinel AML — API Contract

Wave 10 keeps the authenticated owner workflows for customers, accounts, transactions, alerts, cases, private case notes, owner-only EDD records, secure dedup, secure audit timeline, and secure graph metadata. W10-T02 adds secure owner-scoped export and dispute routes. W10-T04 adds secure network-room collaboration routes for room list/detail/join/dossier only. Checker-only APIs, planned vulnerabilities, debug, and admin endpoints remain out of scope.

## Current Operational Endpoints

The API process exposes operational health metadata only:

- `GET /healthz`
- `GET /readyz`

These endpoints are liveness/readiness checks. They must not expose product data, checker state, configuration secrets, database details, flags, or debug metadata.

## Authentication Endpoints

### `POST /api/auth/register`

Registers a normal analyst user and creates a session.

Request:

```json
{
  "username": "analyst-a",
  "password": "correct horse"
}
```

Success response, `201 Created`:

```json
{
  "user": {
    "id": 1,
    "username": "analyst-a",
    "role": "analyst",
    "status": "active",
    "created_at": "2026-08-30T00:00:00Z"
  },
  "session": {
    "token": "returned-once-raw-session-token",
    "expires_at": "2026-08-30T12:00:00Z"
  }
}
```

Errors:

- `400 {"error":"invalid_request"}` for missing username or password.
- `400 {"error":"invalid_json"}` for malformed JSON or unknown fields.
- `409 {"error":"duplicate_username"}` when the username already exists.

### `POST /api/auth/login`

Authenticates an existing active user and creates a new session.

Request:

```json
{
  "username": "analyst-a",
  "password": "correct horse"
}
```

Success response, `200 OK`, uses the same response schema as register.

Errors:

- `400 {"error":"invalid_request"}` for missing username or password.
- `400 {"error":"invalid_json"}` for malformed JSON or unknown fields.
- `401 {"error":"invalid_credentials"}` for unknown username or wrong password.
- `403 {"error":"user_disabled"}` for disabled users.

### `GET /api/auth/me`

Returns the current user for a valid bearer session token.

Request header:

```text
Authorization: Bearer <session-token>
```

Success response, `200 OK`:

```json
{
  "user": {
    "id": 1,
    "username": "analyst-a",
    "role": "analyst",
    "status": "active",
    "created_at": "2026-08-30T00:00:00Z"
  }
}
```

Errors:

- `401 {"error":"unauthenticated"}` for missing, malformed, expired, revoked, or unknown bearer tokens.
- `403 {"error":"user_disabled"}` for disabled users.

## Owner Product Endpoints

All Wave 03 product endpoints require:

```text
Authorization: Bearer <session-token>
```

Common errors:

- `400 {"error":"invalid_json"}` for malformed JSON or unknown fields.
- `400 {"error":"invalid_request"}` for invalid required fields.
- `400 {"error":"invalid_path"}` for malformed or non-positive path IDs.
- `401 {"error":"unauthenticated"}` for missing, malformed, expired, revoked, or unknown bearer tokens.
- `404 {"error":"not_found"}` when the target object does not exist or is outside the authenticated owner boundary.
- `409` conflict responses for duplicate owner-scoped natural keys.
- `405 {"error":"method_not_allowed"}` for unsupported methods on a registered path.

### `POST /api/customers`

Creates a customer owned by the authenticated analyst.

Request:

```json
{
  "display_name": "Acme Ltd",
  "customer_type": "organization",
  "country": "US",
  "registration_number": "US-001",
  "risk_level": "medium",
  "entity_hint": "onboarded",
  "status": "active"
}
```

Success response, `201 Created`:

```json
{
  "id": 1,
  "display_name": "Acme Ltd",
  "customer_type": "organization",
  "country": "US",
  "registration_number": "US-001",
  "risk_level": "medium",
  "entity_hint": "onboarded",
  "created_at": "2026-08-30T00:00:00Z",
  "status": "active"
}
```

The response does not expose `owner_user_id`.

Duplicate registration number for the same owner returns `409 {"error":"duplicate_customer_registration"}`.

### `GET /api/customers/{customer_id}`

Returns one customer only when it belongs to the authenticated owner.

Success response, `200 OK`, uses the customer response schema above.

### `POST /api/customers/{customer_id}/accounts`

Creates an account under an owned customer.

Request:

```json
{
  "iban_like": "SAMLACCT001",
  "currency": "USD",
  "status": "active"
}
```

Success response, `201 Created`:

```json
{
  "id": 1,
  "customer_id": 1,
  "iban_like": "SAMLACCT001",
  "currency": "USD",
  "status": "active",
  "created_at": "2026-08-30T00:00:00Z"
}
```

Duplicate `iban_like` under the same customer returns `409 {"error":"duplicate_account_iban"}`.

### `GET /api/accounts/{account_id}`

Returns one account only when its customer belongs to the authenticated owner.

Success response, `200 OK`, uses the account response schema above.

### `GET /api/customers/{customer_id}/accounts`

Lists accounts for an owned customer.

Success response, `200 OK`:

```json
{
  "accounts": [
    {
      "id": 1,
      "customer_id": 1,
      "iban_like": "SAMLACCT001",
      "currency": "USD",
      "status": "active",
      "created_at": "2026-08-30T00:00:00Z"
    }
  ]
}
```

### `POST /api/transactions`

Creates a transaction under an account owned by the authenticated analyst.

Request:

```json
{
  "account_id": 1,
  "counterparty_name": "Globex",
  "counterparty_country": "GB",
  "counterparty_fingerprint": "globex-fp",
  "amount": "42.50",
  "currency": "USD",
  "direction": "outbound",
  "purpose": "invoice",
  "trace_id": "trace-001"
}
```

Success response, `201 Created`:

```json
{
  "id": 1,
  "account_id": 1,
  "counterparty_name": "Globex",
  "counterparty_country": "GB",
  "counterparty_fingerprint": "globex-fp",
  "amount": "42.50",
  "currency": "USD",
  "direction": "outbound",
  "purpose": "invoice",
  "trace_id": "trace-001",
  "created_at": "2026-08-30T00:00:00Z",
  "risk_score": 0
}
```

`amount` must be a positive decimal compatible with `numeric(18,2)`: up to 16 integer digits, optional one or two fractional digits, no sign, no exponent, and no zero value.

`risk_score` is server-owned. Transaction create requests that include `risk_score` are rejected as unknown-field JSON with `400 {"error":"invalid_json"}`. In Wave 04, the API may return a deterministic server-computed score after synchronous in-process risk scoring; clients still cannot set or override it.

Duplicate `trace_id` under the same account returns `409 {"error":"duplicate_transaction_trace"}`.

### `GET /api/transactions/{transaction_id}`

Returns one transaction only when its account and customer belong to the authenticated owner.

Success response, `200 OK`, uses the transaction response schema above.

### `GET /api/customers/{customer_id}/transactions`

Lists transactions for accounts under an owned customer.

Success response, `200 OK`:

```json
{
  "transactions": [
    {
      "id": 1,
      "account_id": 1,
      "counterparty_name": "Globex",
      "counterparty_country": "GB",
      "counterparty_fingerprint": "globex-fp",
      "amount": "42.50",
      "currency": "USD",
      "direction": "outbound",
      "purpose": "invoice",
      "trace_id": "trace-001",
      "created_at": "2026-08-30T00:00:00Z",
      "risk_score": 0
    }
  ]
}
```

## Wave 04 Investigation Endpoints

All Wave 04 investigation endpoints require:

```text
Authorization: Bearer <session-token>
```

They use the same common JSON errors as the owner product endpoints. Cross-owner alert, case, and note access fails closed with `404 {"error":"not_found"}`.

### `GET /api/alerts/queue`

Lists alerts linked to customers owned by the authenticated analyst.

Success response, `200 OK`:

```json
{
  "alerts": [
    {
      "id": 1,
      "transaction_id": 1,
      "customer_id": 1,
      "rule_code": "DETERMINISTIC_RISK_THRESHOLD",
      "risk_score": 80,
      "status": "NEW",
      "typology_hint": "large-value-transfer",
      "created_at": "2026-08-30T00:00:00Z",
      "updated_at": "2026-08-30T00:00:00Z"
    }
  ]
}
```

### `GET /api/alerts/{alert_id}`

Returns one owned alert. The response uses the alert schema above. Claimed alerts include `assigned_user_id`.

### `POST /api/alerts/{alert_id}/claim`

Claims an owned alert for the authenticated analyst.

Success response, `200 OK`, uses the alert response schema and includes `assigned_user_id`.

### `POST /api/alerts/{alert_id}/triage`

Updates an owned alert status through safe state transitions.

Request:

```json
{
  "status": "TRIAGED"
}
```

Success response, `200 OK`, uses the alert response schema.

Invalid transitions return `409 {"error":"invalid_transition"}`. Invalid status values return `400 {"error":"invalid_request"}`.

### `POST /api/alerts/{alert_id}/case`

Creates an investigation case from an owned alert.

Request:

```json
{
  "public_summary": "Review deterministic alert",
  "dedup_hint": "entity-acme-shared"
}
```

`dedup_hint` is optional non-secret matching metadata. It is normalized by the casework boundary and is not returned in the case shell response.

Success response, `201 Created`:

```json
{
  "id": 1,
  "customer_id": 1,
  "alert_id": 1,
  "status": "OPEN",
  "public_summary": "Review deterministic alert",
  "risk_score": 80,
  "typology_hint": "large-value-transfer",
  "created_at": "2026-08-30T00:00:00Z",
  "updated_at": "2026-08-30T00:00:00Z"
}
```

Duplicate case creation for the same alert returns `409 {"error":"duplicate_case"}`.

### `GET /api/cases/{case_id}`

Returns one case only when it belongs to the authenticated owner. The response uses the case schema above and does not expose `owner_user_id`.

### `PATCH /api/cases/{case_id}/status`

Updates an owned case through safe state transitions.

Request:

```json
{
  "status": "UNDER_REVIEW"
}
```

Success response, `200 OK`, uses the case response schema.

Invalid transitions return `409 {"error":"invalid_transition"}`. Invalid status values return `400 {"error":"invalid_request"}`.

### `POST /api/cases/{case_id}/notes`

Creates a private business note on an owned case.

Request:

```json
{
  "visibility": "private",
  "body": "Private owner-only note"
}
```

Success response, `201 Created`:

```json
{
  "id": 1,
  "case_id": 1,
  "author_user_id": 1,
  "visibility": "private",
  "body": "Private owner-only note",
  "created_at": "2026-08-30T00:00:00Z",
  "updated_at": "2026-08-30T00:00:00Z"
}
```

`body` is normal private analyst data in Wave 04. It is not checker storage, public attack data, or an artificial flag field.

### `GET /api/cases/{case_id}/notes`

Lists private notes for an owned case.

Success response, `200 OK`:

```json
{
  "notes": [
    {
      "id": 1,
      "case_id": 1,
      "author_user_id": 1,
      "visibility": "private",
      "body": "Private owner-only note",
      "created_at": "2026-08-30T00:00:00Z",
      "updated_at": "2026-08-30T00:00:00Z"
    }
  ]
}
```

Private note bodies are returned only through owner-authorized case-note paths. There is no public or side-view note projection in Wave 04.

## Wave 07 Secure Dedup Endpoints

All Wave 07 dedup endpoints require:

```text
Authorization: Bearer <session-token>
```

Source cases must belong to the authenticated analyst. Duplicate candidates are selected by shared `cases.dedup_hint`. Candidate status does not grant access to private notes, EDD comments, internal evidence, audit diffs, credentials, or checker-private data.

Secure `CaseDuplicatePreviewView` fields:

- `case_id`
- `public_summary`
- `risk_tags`
- `overlap_score`
- `match_explanation`

### `GET /api/cases/{case_id}/duplicates`

Lists secure duplicate candidates for an owned source case.

Success response, `200 OK`:

```json
{
  "candidates": [
    {
      "case_id": 2,
      "public_summary": "Candidate public overlap",
      "risk_tags": ["risk_level:high", "typology:layering", "risk_score:high"],
      "overlap_score": 95,
      "match_explanation": "shared_dedup_hint"
    }
  ]
}
```

Blank source `dedup_hint` values return an empty candidate list. Unknown or cross-owner source cases return `404 {"error":"not_found"}`.

### `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`

Returns a secure merge preview for a candidate that shares the owned source case's dedup hint.

Success response, `200 OK`:

```json
{
  "source_case_id": 1,
  "candidate": {
    "case_id": 2,
    "public_summary": "Candidate public overlap",
    "risk_tags": ["risk_level:high", "typology:layering", "risk_score:high"],
    "overlap_score": 95,
    "match_explanation": "shared_dedup_hint"
  }
}
```

Non-candidates, unknown candidates, and cross-owner source cases fail closed with `404 {"error":"not_found"}`. Malformed IDs return `400 {"error":"invalid_path"}`.

Dedup responses must not include `body`, `confidential_comment`, `private_notes`, audit fields, diffs, password hashes, session material, checker-private markers, or raw database rows. Anti-AML-1 tests plant victim note and EDD sentinels and require these endpoints to remain public-only until the planned Wave 14 vulnerability.

## Wave 05 EDD Endpoints

All Wave 05 EDD endpoints require:

```text
Authorization: Bearer <session-token>
```

They use the same common JSON errors as the owner product endpoints. Cross-owner EDD access fails closed with `404 {"error":"not_found"}` and does not reveal whether the customer or EDD record exists.

### `POST /api/customers/{customer_id}/edd`

Creates the current EDD record for an owned customer.

Request:

```json
{
  "source_of_funds": "verified payroll and retained earnings",
  "risk_rationale": "enhanced diligence required for high-risk jurisdiction exposure",
  "confidential_comment": "Owner-only EDD analyst comment",
  "review_status": "DRAFT"
}
```

`review_status` is optional on create and defaults to `DRAFT`. Valid statuses are `DRAFT`, `IN_REVIEW`, `APPROVED`, and `REJECTED`.

Success response, `201 Created`:

```json
{
  "id": 1,
  "customer_id": 1,
  "analyst_user_id": 1,
  "source_of_funds": "verified payroll and retained earnings",
  "risk_rationale": "enhanced diligence required for high-risk jurisdiction exposure",
  "confidential_comment": "Owner-only EDD analyst comment",
  "review_status": "DRAFT",
  "created_at": "2026-08-30T00:00:00Z",
  "updated_at": "2026-08-30T00:00:00Z"
}
```

Duplicate current EDD creation for the same customer returns `409 {"error":"duplicate_edd_record"}`.

### `GET /api/customers/{customer_id}/edd`

Returns the current EDD record only when the customer belongs to the authenticated owner.

Success response, `200 OK`, uses the EDD owner view schema above.

### `PATCH /api/customers/{customer_id}/edd`

Updates the current EDD record for an owned customer.

Request:

```json
{
  "source_of_funds": "verified payroll",
  "risk_rationale": "review complete",
  "confidential_comment": "Updated owner-only EDD analyst comment",
  "review_status": "IN_REVIEW"
}
```

Success response, `200 OK`, uses the EDD owner view schema above.

`confidential_comment` is normal private owner-only business data. It appears only in EDD owner responses and must not appear in customer, account, transaction, alert, case, case-note shell, public, checker, graph, export, or network projections.

## Endpoints Not Implemented In Wave 09

Wave 09 still does not register these surfaces; W10-T02 later activates only the secure export routes documented below:

- `/api/customers/{customer_id}/profile`
- `/api/customers/{customer_id}/risk`
- `/api/graph`
- `/api/entities`
- network-room, public attack-data, checker-only, debug, or admin endpoints.

## Wave 06 Projection Contract Boundary

`internal/projection` defines named allowlisted contracts for current owner views and future safe placeholder views. Those contracts do not create routes or change response behavior. They document and test that:

- current owner note views are the only DTO contract that may include `body`;
- current owner EDD views are the only DTO contract that may include `confidential_comment`;
- future public case shell, duplicate-preview, audit, export, and network summary contracts omit private note, EDD, auth/session, checker-private, and raw DB model-only fields;
- HTTP handlers continue to project repository models into explicit response DTOs before JSON encoding.

Wave 06 HTTP visibility regression plants high-entropy private note and EDD sentinels and verifies they appear only in owner `GET /api/cases/{case_id}/notes` and owner `GET /api/customers/{customer_id}/edd` responses. Auth, customer, account, transaction, alert, case shell, unsupported profile/risk, secure dedup, secure graph, absent side-view/checker routes, and JSON error responses must not contain either sentinel.

`scripts/check_wave06_gate.py` was the Wave 06 API-surface guard before secure dedup routes were introduced. `scripts/check_wave07_gate.py` is the historical Wave 07 API-surface guard before Wave 08 audit timeline activation. `scripts/check_wave08_gate.py` is the historical Wave 08 API-surface guard before Wave 09 graph route activation. Wave 10 activates secure export routes and the secure network-room room list/detail/join/dossier routes. Checker/debug/admin routes remain absent, and `CaseNote.body` plus `EDDRecord.confidential_comment` remain limited to their owner-only DTO contexts.

## Wave 08 Owner Audit Timeline

Wave 08 instruments successful owner workflows with redacted audit events and exposes only the secure owner case timeline:

```text
GET /api/cases/{case_id}/timeline
```

The route requires bearer authentication and case ownership. Cross-owner and missing cases fail closed with `404 {"error":"not_found"}`. Malformed case IDs return `400 {"error":"invalid_path"}`. Unsupported methods return `405 {"error":"method_not_allowed"}`.

Success response, `200 OK`:

```json
{
  "events": [
    {
      "id": 1,
      "object_type": "case_note",
      "object_id": 7,
      "event_type": "created",
      "public_message": "case note created",
      "changes": [
        {
          "field": "sensitive_field",
          "old": "[redacted]",
          "new": "[redacted]",
          "redacted": true
        }
      ],
      "created_at": "2026-08-31T00:00:00Z",
      "visibility_scope": "owner"
    }
  ]
}
```

Timeline DTOs never expose `actor_user_id`, raw `diff_json`, raw `CaseNote.body`, raw `EDDRecord.confidential_comment`, value hashes, credential fields, session material, owner-only database fields, checker-private state, or artificial flag fields. Sensitive field labels are collapsed to `sensitive_field` in HTTP responses.

Wave 08 records redacted events for case creation, case status changes, private note creation, and EDD create/update. EDD events are persisted for future owner/customer activity work but are not exposed by the case timeline unless a later safe customer activity contract is added.

Deferred in Wave 08:

- `GET /api/customers/{customer_id}/activity`
- `GET /api/entities/{entity_hint}/activity`
- raw audit/diff endpoints
- graph, export, network, checker, public attack-data, debug, and admin endpoints

AML-2 remains future-only. This wave is the secure baseline and does not introduce the vulnerable audit timeline behavior.

## Wave 09 Secure Graph Endpoints

Wave 09 exposes only normalized entity-hint graph metadata. All graph endpoints require bearer authentication. The requesting analyst must own at least one customer whose normalized `entity_hint` matches the requested `{entity_hint}`. Missing, invalid, or unauthorized hints fail closed with stable JSON errors.

Graph access does not grant private case-note, EDD narrative, audit diff, credential, session, checker-private, or raw database visibility.

### `GET /api/graph/entities/{entity_hint}`

Returns a safe graph entity summary.

Success response, `200 OK`:

```json
{
  "entity_hint": "acme-shared",
  "relation_type": "shared_entity_hint",
  "customer_count": 2,
  "case_count": 2,
  "highest_risk": 80,
  "risk_tags": ["typology:large-value-transfer"],
  "updated_at": "2026-08-31T00:00:00Z"
}
```

### `GET /api/graph/entities/{entity_hint}/related-cases`

Returns public case/customer metadata for cases linked to the requested entity hint.

Success response, `200 OK`:

```json
{
  "cases": [
    {
      "case_id": 2,
      "customer_id": 2,
      "entity_hint": "acme-shared",
      "display_name": "Acme Ltd",
      "country": "US",
      "status": "OPEN",
      "public_summary": "Public case summary",
      "risk_score": 80,
      "typology_hint": "large-value-transfer",
      "created_at": "2026-08-31T00:00:00Z",
      "updated_at": "2026-08-31T00:00:00Z"
    }
  ]
}
```

### `GET /api/graph/entities/{entity_hint}/edd-summaries`

Returns only EDD review status and public risk tags for customers linked to the requested entity hint.

Success response, `200 OK`:

```json
{
  "summaries": [
    {
      "customer_id": 2,
      "entity_hint": "acme-shared",
      "review_status": "DRAFT",
      "risk_tags": ["risk_level:medium"],
      "created_at": "2026-08-31T00:00:00Z",
      "updated_at": "2026-08-31T00:00:00Z"
    }
  ]
}
```

Graph DTOs must not include `body`, `confidential_comment`, `source_of_funds`, `risk_rationale`, raw `diff_json`, value hashes, password hashes, token hashes, session material, owner IDs, analyst/author/assignee IDs, counterparty fingerprints, trace IDs, checker-private markers, artificial flag fields, public attack data, or raw DB rows.

## Wave 10 Secure Export APIs

W10-T02 exposes secure export and dispute routes using explicit DTOs and `internal/exporting` redaction primitives. All routes require bearer authentication and owner authorization.

### `POST /api/cases/{case_id}/exports`

Creates a redacted export bundle for an owned case.

Request:

```json
{
  "purpose": "case_review",
  "allowed_scopes": ["root_case", "linked_cases", "audit_summary", "edd_summary", "item_metadata"]
}
```

`purpose` must be one of `case_review`, `regulatory_report`, or `dispute_review`. When `allowed_scopes` is omitted, the server uses the full secure export scope shown above. Scope values outside the allowlist fail with `400 {"error":"invalid_request"}`.

### `GET /api/exports/{export_id}`

Returns a previously generated export only to its owning analyst. Cross-owner reads fail closed with `404 {"error":"not_found"}`.

### `POST /api/disputes`

Creates a dispute tied to an owned case.

Request:

```json
{
  "case_id": 50,
  "reason": "request a redacted case export",
  "status": "OPEN"
}
```

`status` is optional and defaults to `OPEN`.

### `POST /api/disputes/{dispute_id}/export`

Creates a redacted export bundle for an owned dispute's case. The response is the same `ExportResponse` shape as direct case export creation.

### Export DTOs

Secure export DTOs are represented by HTTP response types, projection contracts, and `internal/exporting` output structs:

- `ExportBundleView`: `purpose`, `redaction_policy`, `generated_at`, `root_case`, `linked_cases`, `audit_summaries`, `edd_summaries`, `items`.
- `ExportCaseShellView`: `case_id`, `customer_id`, `status`, `public_summary`, `risk_score`, `typology_hint`, `created_at`, `updated_at`.
- `ExportAuditSummaryView`: `event_id`, `object_type`, `object_id`, `event_type`, `public_message`, `changed_fields`, `created_at`.
- `ExportEDDSummaryView`: `record_id`, `customer_id`, `review_status`, `risk_tags`, `created_at`, `updated_at`.
- `ExportItemMetadataView`: `item_type`, `object_type`, `object_id`, `relation`, `redaction_policy`.

Secure export DTOs must not expose `CaseNote.body`, `EDDRecord.confidential_comment`, EDD `source_of_funds`, EDD `risk_rationale`, raw `diff_json`, value hashes, credentials, session material, owner/analyst/author/assignee IDs, checker-private fields, public attack data, artificial flag fields, or raw DB rows. AML-4 remains future-only.

## Wave 10 Secure Network-Room APIs

W10-T04 exposes secure network-room collaboration routes using explicit HTTP DTOs backed by the `internal/networkroom` references-first repository and projection contracts. All routes require bearer authentication.

### `GET /api/network/rooms`

Lists rooms where the authenticated analyst is already a participant.

Success response, `200 OK`:

```json
{
  "rooms": [
    {
      "id": 90,
      "room_key": "shared_entity:large_value_transfer",
      "entity_hint": "shared_entity",
      "typology_hint": "large_value_transfer",
      "status": "OPEN",
      "public_summary": "Shared public risk workspace",
      "public_risk_tags": ["large-value-transfer"],
      "case_count": 2,
      "participant_count": 2,
      "created_at": "2026-08-31T00:00:00Z",
      "updated_at": "2026-08-31T00:00:00Z"
    }
  ]
}
```

### `GET /api/network/rooms/{room_id}`

Returns room summary metadata and participant metadata for an authenticated participant. Non-participants and unknown rooms fail closed with `404 {"error":"not_found"}`.

### `POST /api/network/rooms/{room_id}/join`

Joins an existing room as the authenticated analyst. Duplicate joins return `409 {"error":"duplicate_network_room_object"}`.

### `GET /api/network/rooms/{room_id}/dossier`

Returns a safe references-only dossier for an authenticated participant. The response includes room metadata, public case shells, requester ownership markers, the redaction policy, and the private-data policy. Own and foreign cases use the same public/redacted dossier policy.

### Network-Room DTOs

Secure network-room DTOs are:

- `NetworkRoomSummaryView`: `id`, `room_key`, `entity_hint`, `typology_hint`, `status`, `public_summary`, `public_risk_tags`, `case_count`, `participant_count`, `created_at`, `updated_at`.
- `NetworkRoomParticipantView`: `id`, `room_id`, `user_id`, `participant_role`, `joined_at`.
- `NetworkRoomCaseView`: `case_id`, `customer_id`, `owned_by_requester`, `status`, `public_summary`, `risk_score`, `typology_hint`, `public_risk_tags`, `private_data_omitted`, `created_at`, `updated_at`.
- `NetworkRoomDossierView`: `room`, `cases`, `redaction_policy`, `private_data_policy`.

Network-room DTOs must not expose private note bodies, EDD confidential comments, EDD narrative fields, raw audit diffs, value hashes, credential material, session material, counterparty fingerprints, trace IDs, checker-private fields, public attack data, artificial flag fields, raw source case blobs, or raw DB rows. AML-5 remains future-only.

## API Rules

Product endpoints must:

- use normal authenticated business flows;
- keep authorization behind `internal/authz`;
- avoid direct database model serialization;
- accept request contexts and honor timeouts;
- avoid hidden checker, debug, admin, shell, or direct database helper paths.

Auth responses must not include `password_hash`, stored session token hashes, internal database rows, or checker-private data.

## Frontend consumption note

The Sentinel AML frontend consumes these contracts through `frontend/src/shared/api/sentinel.ts` and allowlisted adapter modules under `frontend/src/shared/api/adapters/`. The frontend may ignore unknown server fields, but it must not widen a rendered view without a named adapter change, visibility review, and matching tests. Frontend work does not own backend contract changes; missing UI capabilities are tracked in `docs/ui/backend_contract_change_requests.md`.
