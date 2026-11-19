# Sentinel AML — Database Model

PostgreSQL is the authoritative database for Sentinel AML.

## Wave 02 Foundation

Wave 02 adds the initial migration foundation for authentication persistence only:

- `users`
- `sessions`
- `schema_migrations`

Migration decision: `docs/decisions/0001_database_migration_foundation.md`.

## Users

The initial `users` table contains:

- `id`
- `username`
- `password_hash`
- `role`
- `status`
- `created_at`

Constraints:

- usernames are unique;
- roles are constrained to `analyst`, `senior_analyst`, `supervisor`, `auditor`, and `system_worker`;
- status is constrained to `active` or `disabled`;
- password hashes are stored internally and must not appear in DTOs or logs.

## Sessions

The initial `sessions` table contains:

- `id`
- `user_id`
- `token_hash`
- `created_at`
- `expires_at`
- `revoked_at`

Only session token hashes are stored. Raw session tokens must not be persisted.

## Wave 03 Domain Persistence

Wave 03 adds `migrations/000002_create_customers_accounts_transactions.sql` after the Wave 02 authentication migration.

### Customers

The `customers` table contains:

- `id`
- `owner_user_id`
- `display_name`
- `customer_type`
- `country`
- `registration_number`
- `risk_level`
- `entity_hint`
- `created_at`
- `status`

Constraints and indexes:

- `owner_user_id` references `users(id)` with cascade delete.
- `registration_number` is unique per owner.
- `customer_type` is constrained to `individual` or `organization`.
- `risk_level` is constrained to `low`, `medium`, or `high`.
- `status` is constrained to `active` or `inactive`.
- owner, owner/status, and risk-level indexes support owner-scoped product reads and future worker inputs.

### Accounts

The `accounts` table contains:

- `id`
- `customer_id`
- `iban_like`
- `currency`
- `status`
- `created_at`

Constraints and indexes:

- `customer_id` references `customers(id)` with cascade delete.
- `iban_like` is unique per customer.
- `currency` is constrained to three uppercase letters.
- `status` is constrained to `active` or `closed`.
- customer and status indexes support customer-bound reads and later workflow inputs.

### Transactions

The `transactions` table contains:

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

Constraints and indexes:

- `account_id` references `accounts(id)` with cascade delete.
- `trace_id` is unique per account.
- `amount` must be a positive decimal compatible with `numeric(18,2)`.
- `currency` is constrained to three uppercase letters.
- `direction` is constrained to `inbound` or `outbound`.
- `risk_score` is constrained to 0 through 100, defaults to 0, and is not client-controlled.
- account, trace, counterparty fingerprint, created-at, and risk-score indexes support owner-scoped reads and future deterministic worker inputs.

Wave 03 does not add a risk engine. `risk_score` is stored as a deterministic server-owned placeholder/default for later secure workflow waves. Transaction create repository paths omit `risk_score` from inserts so PostgreSQL supplies the default.

## Wave 04 Investigation Persistence

Wave 04 adds `migrations/000003_create_alerts_cases_notes.sql` after the Wave 03 customer/account/transaction migration.

### Alerts

The `alerts` table contains:

- `id`
- `transaction_id`
- `customer_id`
- `rule_code`
- `risk_score`
- `status`
- `assigned_user_id`
- `typology_hint`
- `created_at`
- `updated_at`

Constraints and indexes:

- `transaction_id` references `transactions(id)` with cascade delete.
- `customer_id` references `customers(id)` with cascade delete.
- `assigned_user_id` references `users(id)` with set-null delete behavior.
- `rule_code` is unique per transaction.
- `risk_score` is constrained to 0 through 100.
- `status` is constrained to `NEW`, `TRIAGED`, `CASE_OPENED`, `ESCALATED`, or `CLOSED`.
- transaction, customer, customer/status, assigned-user, status, and updated-at indexes support owner-scoped alert queues and status transitions.

### Cases

The `cases` table contains:

- `id`
- `customer_id`
- `alert_id`
- `owner_user_id`
- `status`
- `public_summary`
- `risk_score`
- `typology_hint`
- `dedup_hint`
- `created_at`
- `updated_at`

Constraints and indexes:

- `customer_id` references `customers(id)` with cascade delete.
- `alert_id` references `alerts(id)` and is unique so each alert opens at most one case.
- `owner_user_id` references `users(id)` with cascade delete.
- `risk_score` is constrained to 0 through 100.
- `status` is constrained to `OPEN`, `UNDER_REVIEW`, `ESCALATED`, `REPORTED`, or `CLOSED`.
- `dedup_hint` is non-secret matching metadata used to discover potential duplicate case candidates.
- customer, alert, owner, owner/status, dedup-hint, owner/dedup-hint, and updated-at indexes support owner case work queues and deterministic duplicate candidate discovery.

### Case Notes

The `case_notes` table contains:

- `id`
- `case_id`
- `author_user_id`
- `visibility`
- `body`
- `created_at`
- `updated_at`

Constraints and indexes:

- `case_id` references `cases(id)` with cascade delete.
- `author_user_id` references `users(id)` with restrict delete behavior.
- `visibility` is constrained to `private` or `internal`.
- case, author, visibility, and updated-at indexes support owner-authorized note reads.

`CaseNote.body` is normal private business data in Wave 04. It is not an artificial flag field, checker storage API, public attack-data field, or vulnerability surface in this wave.

## Wave 05 EDD Persistence

Wave 05 adds `migrations/000004_create_edd_records.sql` after the Wave 04 alert/case/note migration.

### EDD Records

The `edd_records` table contains:

- `id`
- `customer_id`
- `analyst_user_id`
- `source_of_funds`
- `risk_rationale`
- `confidential_comment`
- `review_status`
- `created_at`
- `updated_at`

Constraints and indexes:

- `customer_id` references `customers(id)` with restrict delete behavior to avoid deleting future flag-bearing EDD records through parent cleanup.
- `analyst_user_id` references `users(id)` with restrict delete behavior.
- `customer_id` is unique so each customer has at most one current EDD record in Wave 05.
- `review_status` is constrained to `DRAFT`, `IN_REVIEW`, `APPROVED`, or `REJECTED`.
- customer, analyst, review-status, and updated-at indexes support owner-scoped EDD review paths.

`EDDRecord.confidential_comment` is normal private business data in Wave 05. It is not an artificial flag field, checker storage API, public attack-data field, or vulnerability surface in this wave.

Wave 05 does not add cleanup or retention deletes for EDD records.

## Wave 07 Dedup Metadata

Wave 07 adds `migrations/000005_add_case_dedup_hint.sql` after the Wave 05 EDD migration.

The migration adds `cases.dedup_hint` as a `text NOT NULL DEFAULT ''` column. The canonical placement is `cases.dedup_hint` because duplicate review operates on case shells and must not read private note bodies or EDD confidential comments.

Constraints and indexes:

- `cases_dedup_hint_not_blank_when_set` allows the empty default and rejects whitespace-only populated hints.
- `cases_dedup_hint_idx` supports same-hint candidate lookup.
- `cases_owner_dedup_hint_idx` supports owner-scoped source/candidate workflows.

`dedup_hint` is public matching metadata, not a secret, credential, checker-private field, flag value, or private investigation narrative. It must not be confused with `CaseNote.body` or `EDDRecord.confidential_comment`.

## Wave 08 Audit Persistence

Wave 08 adds `migrations/000006_create_audit_events.sql` after the Wave 07 dedup metadata migration.

### Audit Events

The `audit_events` table contains:

- `id`
- `actor_user_id`
- `object_type`
- `object_id`
- `event_type`
- `public_message`
- `diff_json`
- `created_at`
- `visibility_scope`

Constraints and indexes:

- `actor_user_id` references `users(id)` with restrict delete behavior.
- `object_id` must be positive.
- `object_type` is constrained to `customer`, `account`, `transaction`, `alert`, `case`, `case_note`, or `edd_record`.
- `event_type` is constrained to `created`, `updated`, `status_changed`, `claimed`, `triaged`, or `reviewed`.
- `visibility_scope` is constrained to `owner`, `internal`, or `system`.
- `diff_json` must be a JSON array.
- actor, object, event-type, visibility/created-at, and created-at indexes support owner timeline access patterns planned for W08-T02.

Audit diffs are generated by `internal/audit` redaction helpers before insertion. Sensitive fields such as `CaseNote.body`, `EDDRecord.confidential_comment`, passwords, token hashes, session material, checker-private markers, and artificial flag fields must be represented as `[redacted]` plus deterministic `sha256:` value hashes rather than raw values.

Wave 08 audit persistence is secure baseline behavior only. It is not AML-2. The only Wave 08 audit HTTP surface is owner-scoped `GET /api/cases/{case_id}/timeline`, and neither storage nor DTOs may duplicate private note bodies or EDD confidential comments.

## Serialization Boundary

Database records are internal persistence models. HTTP responses must use explicit API projections and authorization checks instead of direct database model serialization. Wave 05 EDD HTTP responses use an owner DTO rather than exposing a raw `edd_records` row shape. Wave 07 dedup candidate repository results are internal safe metadata only, and Wave 07 HTTP dedup endpoints expose only `CaseDuplicatePreviewView` public overlap fields.

## Exclusions

Wave 08 does not add graph/export/network persistence, cleanup/retention deletion behavior, checker DB access, checker PUT/GET behavior, public attack data, planned vulnerabilities, exploits, reference fixes, raw audit endpoints, customer/entity activity endpoints, or EDD side-view endpoints.

## Wave 09 Entity Graph Persistence

Wave 09 adds `migrations/000007_create_entity_graph.sql` after the Wave 08 audit migration. This is the secure related-entity graph persistence baseline and is not AML-3.

### Entity Graph Nodes

The `entity_graph_nodes` table contains:

- `id`
- `entity_hint`
- `node_type`
- `display_label`
- `public_risk_tags`
- `created_at`
- `updated_at`

Constraints:

- `entity_hint` must be nonblank.
- `node_type` is limited to `customer_entity`, `counterparty`, `case_cluster`, or `edd_status`.
- `(entity_hint, node_type)` is unique.

Indexes:

- `entity_graph_nodes_entity_hint_idx` supports entity-hint lookups.
- `entity_graph_nodes_node_type_idx` supports future graph maintenance and validation.

### Entity Graph Edges

The `entity_graph_edges` table contains:

- `id`
- `source_node_id`
- `target_node_id`
- `relation_type`
- `strength`
- `public_summary`
- `created_at`
- `updated_at`

Constraints:

- source and target nodes reference `entity_graph_nodes`.
- self-edges are rejected.
- `relation_type` is limited to `shared_entity_hint`, `shared_counterparty`, `same_case_cluster`, or `edd_status_overlap`.
- `strength` must be between `0` and `100`.
- `(source_node_id, target_node_id, relation_type)` is unique.

Indexes:

- source-node, target-node, and relation-type indexes support future graph traversal and validation.

Wave 09 repository primitives use query-time discovery from `customers.entity_hint`, cases, and EDD review metadata for safe summaries. The materialized graph node/edge tables are present as the architecture-aligned persistence foundation, but no worker populates them and no HTTP graph route exposes them in W09-T01.

The graph migration and repository must not store or select `CaseNote.body`, `EDDRecord.confidential_comment`, raw EDD `source_of_funds`, EDD `risk_rationale`, audit `diff_json`, credentials, token/session material, checker-private markers, public attack data, or artificial flag fields.

## Wave 10 Export And Dispute Persistence

Wave 10 adds `migrations/000008_create_exports_disputes.sql` after the Wave 09 graph migration. This is the secure export persistence and redaction baseline, not AML-4.

Tables:

- `disputes`: owner-scoped case dispute records with `id`, `owner_user_id`, `case_id`, `status`, `reason`, `resolution_summary`, `created_at`, and `updated_at`.
- `exports`: owner-scoped export jobs with `id`, `owner_user_id`, `root_case_id`, optional `dispute_id`, `purpose`, `status`, `bundle_json`, `redaction_policy`, `created_at`, `updated_at`, and `expires_at`.
- `export_items`: deterministic export item metadata with `id`, `export_id`, `item_type`, `object_type`, `object_id`, `relation`, `redaction_policy`, `payload_json`, and `created_at`.

Constraints:

- dispute statuses are `OPEN`, `UNDER_REVIEW`, `RESOLVED`, and `REJECTED`;
- export statuses are `PENDING`, `GENERATED`, `FAILED`, and `EXPIRED`;
- export item types are `root_case`, `linked_case`, `audit_summary`, `edd_summary`, and `metadata`;
- export object types are `case`, `audit_event`, `edd_record`, and `export`;
- all stored export payloads use the `public_redacted` redaction policy and JSON object payloads.

Indexes cover dispute owner/status lookups, dispute case lookups, export owner/status lookups, export root-case/dispute/expiry lookups, and export item object metadata lookups.

The export migration intentionally does not store raw private note bodies, EDD confidential comments, raw EDD narrative fields, raw audit diffs, value hashes, checker-private state, public attack data, artificial flag fields, or debug/admin state.

## Wave 10 Network-Room Persistence

W10-T03 adds `migrations/000009_create_network_rooms.sql` after the export/dispute migration. This is the secure references-first network-room persistence baseline and is not AML-5.

Tables:

- `network_rooms`: deterministic room metadata with `id`, `room_key`, `entity_hint`, `typology_hint`, `status`, `public_summary`, `public_risk_tags`, `created_by_user_id`, `created_at`, and `updated_at`.
- `network_room_cases`: room-to-case references with `id`, `room_id`, `case_id`, `relation_type`, `added_by_user_id`, and `created_at`.
- `network_room_participants`: room participation metadata with `id`, `room_id`, `user_id`, `participant_role`, and `joined_at`.

Constraints:

- room status is limited to `OPEN`, `MONITORING`, or `CLOSED`;
- `(room_key)` is unique so same entity/typology grouping is deterministic;
- `(room_id, case_id)` is unique so case references are not duplicated in a room;
- room-case relation type is limited to `root_case`, `related_case`, `typology_match`, or `entity_match`;
- participant role is limited to `analyst` or `observer`;
- `(room_id, user_id)` is unique.

Indexes cover entity-hint, typology, status, creator, room-case, case, relation, room participant, and user participant lookups.

Network-room storage is references-first. It must not copy private note bodies, EDD confidential comments, raw EDD narrative fields, raw audit diffs, value hashes, raw case blobs, checker-private state, public attack data, artificial flag fields, or debug/admin state.
