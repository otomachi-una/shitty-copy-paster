# Sentinel AML — Authentication and Authorization

Wave 09 uses the Wave 02 bearer-session foundation for auth endpoints, owner-scoped product APIs, secure owner investigation workflows, owner-only EDD APIs, secure dedup, secure audit timeline, and secure graph side-view metadata. Projection contracts remain explicit so authorization decisions are paired with allowlisted response shapes.

## Boundary

Authorization logic lives behind `internal/authz`. Authenticated HTTP handlers place a request principal in that boundary after a bearer token is validated.

Wave 06 records current owner-scope contracts in `internal/authz`. These contracts are documentation/test anchors for resource ownership and expected cross-owner behavior; they do not introduce new roles or privilege escalation paths.

## Session Model

- Passwords are hashed with `golang.org/x/crypto/bcrypt` before storage.
- Session tokens are generated with `crypto/rand`.
- Only the raw token returned to the client at register/login time can be used as the bearer credential.
- The database stores a SHA-256 hash of the raw token in `sessions.token_hash`.
- Sessions use `expires_at`; revoked or expired sessions fail closed.
- The default user role for registration is `analyst`.

## Request Authentication

Protected requests use:

```text
Authorization: Bearer <session-token>
```

The middleware rejects missing, malformed, expired, revoked, unknown, or disabled-user sessions. Protected unauthenticated requests return a stable `401 {"error":"unauthenticated"}` response.

## Current Product Scope

Auth routes are:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`

Wave 03 owner product routes are:

- `POST /api/customers`
- `GET /api/customers/{customer_id}`
- `POST /api/customers/{customer_id}/accounts`
- `GET /api/accounts/{account_id}`
- `GET /api/customers/{customer_id}/accounts`
- `POST /api/transactions`
- `GET /api/transactions/{transaction_id}`
- `GET /api/customers/{customer_id}/transactions`

Wave 04 owner investigation routes are:

- `GET /api/alerts/queue`
- `GET /api/alerts/{alert_id}`
- `POST /api/alerts/{alert_id}/claim`
- `POST /api/alerts/{alert_id}/triage`
- `POST /api/alerts/{alert_id}/case`
- `GET /api/cases/{case_id}`
- `PATCH /api/cases/{case_id}/status`
- `GET /api/cases/{case_id}/notes`
- `POST /api/cases/{case_id}/notes`
- `GET /api/cases/{case_id}/duplicates`
- `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`
- `POST /api/customers/{customer_id}/edd`
- `GET /api/customers/{customer_id}/edd`
- `PATCH /api/customers/{customer_id}/edd`

Wave 09 secure graph routes are:

- `GET /api/graph/entities/{entity_hint}`
- `GET /api/graph/entities/{entity_hint}/related-cases`
- `GET /api/graph/entities/{entity_hint}/edd-summaries`

## Owner Authorization Rules

- Customers are owned directly by `owner_user_id`.
- Account reads, account lists, and account creates must resolve through a customer owned by the authenticated principal.
- Transaction reads, transaction lists, and transaction creates must resolve through an account and customer owned by the authenticated principal.
- Transaction create requests cannot set `risk_score`; it is server-owned and may be updated by the deterministic Wave 04 risk workflow.
- Alert reads, lists, claims, and triage updates must resolve through the linked customer owner. In Wave 04, alert assignment must target the owning analyst because collaborator assignment is not implemented yet.
- Case creation must resolve through an owned alert; case reads and status updates are scoped by `cases.owner_user_id`.
- Case note creation and listing must resolve through an owned case. In Wave 04, note authors must match the owning analyst because collaborator authorization is not implemented yet.
- Private note bodies are visible only through owner-authorized case-note endpoints. There is no public note, side-view, checker-only, or collaborator projection in Wave 04.
- Dedup candidate and merge-preview routes require the source case to belong to the authenticated analyst. Candidate data is selected by shared non-secret `cases.dedup_hint` and is limited to public overlap metadata.
- EDD record create, read, and update paths must resolve through `customers.owner_user_id`. In Wave 05, `analyst_user_id` is set to the authenticated owner because collaborator authorization is not implemented yet.
- EDD confidential comments are private business data in Wave 05 and are exposed only through `POST /api/customers/{customer_id}/edd`, `GET /api/customers/{customer_id}/edd`, and `PATCH /api/customers/{customer_id}/edd` for the owning analyst. They have no public view, side view, or checker-only path.
- Wave 06 projection contracts keep owner views separate from future public/side-view DTOs. Public case shell, duplicate-preview, audit, export, graph, and network summary contracts must not include private note bodies, EDD confidential comments, auth/session hashes, checker-private fields, or raw DB model-only owner fields.
- Case timeline reads must resolve through `cases.owner_user_id` before audit events are listed. Right to see a case timeline does not grant access to raw audit `diff_json`, private note bodies, EDD confidential comments, credential material, or checker-private state.
- Graph entity reads require the authenticated analyst to own at least one customer whose normalized `entity_hint` matches the requested hint. That access grants only safe graph DTO metadata and never grants private case-note bodies, EDD confidential comments, raw audit diffs, credentials, session material, owner IDs, or checker-private state.
- Case export creation resolves through an owned case before a redacted bundle is generated. Export retrieval resolves through `exports.owner_user_id`; dispute creation and dispute export resolve through the owned case or owned dispute. Export authorization grants only public/redacted bundle DTOs and never grants raw notes, EDD confidential comments, EDD narrative fields, raw audit diffs, value hashes, credential material, or checker-private state.
- Network-room list/detail/dossier reads require room participation. Joining a room requires authentication and an existing room, but participation grants only room metadata, participant metadata, and references-first public dossier content. It never grants private note bodies, EDD confidential comments, EDD narrative fields, raw audit diffs, value hashes, credential material, counterparty fingerprints, trace IDs, checker-private state, or raw source case blobs.
- Cross-owner access fails closed as `404 {"error":"not_found"}` so responses do not reveal whether another analyst's object exists.
- Missing or invalid bearer credentials fail before product handler execution with `401 {"error":"unauthenticated"}`.
- Path IDs must be positive integers; malformed path IDs fail with `400 {"error":"invalid_path"}`.

## Wave 06 Cross-Owner Authorization Matrix

Current object-scoped owner operations fail closed as `404 {"error":"not_found"}` when attempted by another analyst. Queue-style operations remain available but are owner-filtered.

| Resource | Covered operations | Cross-owner behavior |
| --- | --- | --- |
| Customer | `GET /api/customers/{customer_id}` | `404 not_found`, no existence detail |
| Account | `GET /api/accounts/{account_id}`, `GET /api/customers/{customer_id}/accounts`, `POST /api/customers/{customer_id}/accounts` | `404 not_found`, scoped through customer owner |
| Transaction | `GET /api/transactions/{transaction_id}`, `GET /api/customers/{customer_id}/transactions`, `POST /api/transactions` | `404 not_found`, scoped through account and customer owner |
| Alert | `GET /api/alerts/{alert_id}`, `POST /api/alerts/{alert_id}/claim`, `POST /api/alerts/{alert_id}/triage` | `404 not_found`, scoped through customer owner |
| Alert queue | `GET /api/alerts/queue` | `200 OK` with only the authenticated owner's alerts |
| Case | `GET /api/cases/{case_id}`, `PATCH /api/cases/{case_id}/status` | `404 not_found`, scoped by case owner |
| Case note | `GET /api/cases/{case_id}/notes`, `POST /api/cases/{case_id}/notes` | `404 not_found`, scoped through owned case |
| Case audit timeline | `GET /api/cases/{case_id}/timeline` | `404 not_found`, scoped through owned case; response contains redacted event DTOs only |
| Case dedup | `GET /api/cases/{case_id}/duplicates`, `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview` | `404 not_found` for foreign source cases; candidate previews contain public overlap fields only |
| EDD record | `GET /api/customers/{customer_id}/edd`, `POST /api/customers/{customer_id}/edd`, `PATCH /api/customers/{customer_id}/edd` | `404 not_found`, scoped through customer owner |
| Entity graph | `GET /api/graph/entities/{entity_hint}`, `GET /api/graph/entities/{entity_hint}/related-cases`, `GET /api/graph/entities/{entity_hint}/edd-summaries` | `404 not_found` when the user owns no customer for the normalized hint; response contains safe metadata only |
| Export and dispute | `POST /api/cases/{case_id}/exports`, `GET /api/exports/{export_id}`, `POST /api/disputes`, `POST /api/disputes/{dispute_id}/export` | `404 not_found` for foreign cases, exports, or disputes; responses contain redacted export DTOs only |
| Network room | `GET /api/network/rooms`, `GET /api/network/rooms/{room_id}`, `POST /api/network/rooms/{room_id}/join`, `GET /api/network/rooms/{room_id}/dossier` | list is participant-filtered; detail and dossier return `404 not_found` for non-participants; dossier responses contain public references-only case summaries |

Malformed IDs fail before object lookup as `400 {"error":"invalid_path"}`. Missing or malformed bearer credentials fail before ownership checks as `401 {"error":"unauthenticated"}`. No current role name grants supervisor, auditor, admin, or checker bypass behavior.

The current branch gate, `scripts/check_wave06_gate.py`, requires this Cross-Owner Authorization Matrix and its HTTP regression tests before Wave 06 can close.

## Constraints

Auth work must not introduce:

- debug impersonation;
- admin bypasses;
- hidden checker-only authorization paths;
- credentials in public attack data;
- direct database shortcuts for checker behavior.

Future checker traffic must authenticate through the same normal API flow rather than a hidden checker path.
