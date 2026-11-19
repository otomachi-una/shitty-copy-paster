# Sentinel AML — Domain Model

The Sentinel AML domain models AML investigation workflows. Wave 05 adds secure normal EDD persistence and owner HTTP views while keeping checker flows, vulnerabilities, public attack data, and later graph/export/network workflows out of scope.

## Wave 03 Entities

### Customer

Implemented fields:

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

Rules:

- `owner_user_id` links each customer to a user.
- `customer_type` is limited to `individual` or `organization`.
- `risk_level` is limited to `low`, `medium`, or `high` and defaults to `medium`.
- `status` is limited to `active` or `inactive` and defaults to `active`.
- `registration_number` is unique per owner.

### Account

Implemented fields:

- `id`
- `customer_id`
- `iban_like`
- `currency`
- `status`
- `created_at`

Rules:

- `customer_id` links each account to a customer.
- repository methods that return accounts require an owner boundary and join through customers.
- `currency` is a three-letter uppercase code.
- `status` is limited to `active` or `closed` and defaults to `active`.
- `iban_like` is unique per customer.

### Transaction

Implemented fields:

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

Rules:

- `account_id` links each transaction to an account.
- repository methods that return transactions require an owner boundary and join through accounts and customers.
- `amount` must be positive.
- `currency` is a three-letter uppercase code.
- `direction` is limited to `inbound` or `outbound`.
- `trace_id` is unique per account.
- `risk_score` is a deterministic placeholder field only, constrained to 0 through 100 and defaulting to 0. Wave 03 does not implement a risk engine.

## Wave 04 Investigation Entities

### Alert

Implemented fields:

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

Rules:

- Alerts are scoped to owners through `customer_id` and the linked customer owner.
- `transaction_id` links alerts to the transaction that triggered normal review.
- `rule_code` is unique per transaction.
- `status` is limited to `NEW`, `TRIAGED`, `CASE_OPENED`, `ESCALATED`, or `CLOSED`.
- `risk_score` is constrained to 0 through 100 and remains server-side investigation state.
- Claiming an alert updates only owner-authorized alerts.

### Case

Implemented fields:

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

Rules:

- Cases are created from owner-authorized alerts.
- `owner_user_id` is stored on the case and all case reads/updates require that owner boundary.
- One case may be created for each alert.
- `status` is limited to `OPEN`, `UNDER_REVIEW`, `ESCALATED`, `REPORTED`, or `CLOSED`.
- Case status updates follow explicit forward transitions and closed cases do not reopen.
- `dedup_hint` is non-secret matching metadata stored on `cases` beginning in Wave 07.
- Duplicate candidate discovery first verifies the source case belongs to the requesting owner, then returns same-hint candidates as non-sensitive case/customer metadata only.
- Duplicate candidate status does not grant access to case notes, EDD records, audit payloads, credentials, checker state, or future private fields.

### Case Note

Implemented fields:

- `id`
- `case_id`
- `author_user_id`
- `visibility`
- `body`
- `created_at`
- `updated_at`

Rules:

- Case notes are created and listed only through owner-authorized case methods.
- `visibility` is explicit and limited to `private` or `internal`.
- `body` is a normal private analyst note field in Wave 04.
- `CaseNote.body` is a future checker place, but Wave 04 does not implement checker PUT/GET or public attack data.

## Wave 05 EDD Entity

### EDD Record

Implemented fields:

- `id`
- `customer_id`
- `analyst_user_id`
- `source_of_funds`
- `risk_rationale`
- `confidential_comment`
- `review_status`
- `created_at`
- `updated_at`

Rules:

- EDD records are scoped to owners through `customer_id` and `customers.owner_user_id`.
- `analyst_user_id` is the owning analyst in Wave 05; collaborator assignment is deferred.
- One current EDD record is allowed per customer.
- `review_status` is limited to `DRAFT`, `IN_REVIEW`, `APPROVED`, or `REJECTED`.
- `confidential_comment` is normal private business data in Wave 05.
- The owner EDD journey is: create or read an owned customer, create the customer's current EDD record, read it through the owner EDD view, and patch the review fields/status through the same owner boundary.
- `EDDRecord.confidential_comment` is returned only through the owner EDD view.
- `EDDRecord.confidential_comment` is a future checker place, but Wave 05 does not implement checker PUT/GET, public attack data, or side-view projections.
- No cleanup or retention path deletes EDD records in Wave 05.

## Future Entities

Known future investigation concepts from the Wave 01 contract remain deferred:

- related graph, audit export, and network-room concepts.

## Boundaries

Domain objects must not be serialized directly into HTTP responses. Future APIs must expose explicit response projections that respect owner, investigator, public, and checker visibility boundaries.

All database and future API operations must accept `context.Context` and enforce bounded behavior where I/O or request lifecycle work is involved.

Wave 03 repository methods encode owner scoping where records can cross an owner boundary:

- customers are scoped by `owner_user_id`;
- accounts are scoped through their customer;
- transactions are scoped through their account and customer.

Wave 04 alert and case repositories continue that model:

- alerts are scoped through their customer owner;
- cases are scoped directly by `owner_user_id`;
- case notes are scoped through their case owner.

Wave 05 adds EDD repository and HTTP owner scoping through customers. It does not add future checker-private fields, public attack data, checker storage, checker PUT/GET, reference exploits, vulnerabilities, graph, export, or network-room behavior.
