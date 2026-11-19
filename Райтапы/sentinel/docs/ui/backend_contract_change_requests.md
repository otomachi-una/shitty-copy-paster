# Sentinel AML UI — Backend Contract Change Requests

Backend changes are frozen by default for UI work. This file is the only normal path for proposing a backend capability needed by the frontend.

There are no approved backend contract changes in the UI correction wave. Requests below are proposed only and must not be implemented without a separate backend exception task.

### UI-BCR-001 — Existing case locator for duplicate alert case creation

- **Status:** proposed
- **Requested endpoint or DTO change:** When `POST /api/alerts/{alert_id}/case` rejects with `duplicate_case`, return a safe owner-scoped case locator, or provide an owner-scoped lookup endpoint that resolves the existing case for an alert.
- **Investigator workflow requiring it:** During `/alerts/:alertId` review, an investigator may attempt to open a case and receive `duplicate_case`; the UI needs to recover by taking them to the already-created case file.
- **Why existing endpoints cannot support the workflow:** The current conflict response exposes only an error code. There is no global case list and no alert-to-case lookup, so the frontend cannot derive a case ID without inventing state.
- **Affected UI routes/components:** `/alerts/:alertId` case-creation action and recovery copy; downstream `/cases/:caseId` navigation when an existing case is already known.
- **Security/visibility implications:** The locator must be scoped to the authenticated owner and must preserve closed `404` behavior for foreign alerts/cases. It must not expose cross-owner IDs or private note/EDD material.
- **A/D or competition implications:** Any accepted contract must be checked against duplicate-preview, audit-timeline, graph, export, and network-room vulnerable/fixed profiles so it does not create a new side channel.
- **Checker implications:** Checker flows that rely on case creation conflicts may need assertions that no foreign locator is exposed.
- **Does it block the entire wave or only one subsection?:** Only the duplicate-case recovery subsection; normal case creation and case workspace navigation remain implemented.
- **Frontend fallback:** Show a safe conflict message, ask the analyst to refresh, and avoid pretending a direct existing-case link is available.
- **Suggested minimal contract (not implementation):** Extend the owner-scoped `duplicate_case` response with `case_id` for the authenticated owner only, or add `GET /api/alerts/{alert_id}/case` returning the existing owner case shell when present.
- **Tests that would be required if accepted:** Owner duplicate conflict returns only that owner’s case locator; foreign alert/case remains `404`; response shape excludes private notes, EDD confidential comments, raw dedup internals, and cross-owner identifiers.

### UI-BCR-002 — Customer-scoped safe activity

- **Status:** proposed
- **Requested endpoint or DTO change:** Add an owner-scoped `GET /api/customers/{customer_id}/activity` endpoint returning a safe chronology DTO for customer-level activity.
- **Investigator workflow requiring it:** From `/customers/:customerId` and case-side customer context, an investigator needs to review customer-specific diligence and investigation activity without switching to broader related-entity activity.
- **Why existing endpoints cannot support the workflow:** `GET /api/customers/{customer_id}/activity` currently returns `404 not_found`. `GET /api/cases/{case_id}/timeline` is case-scoped, and `GET /api/entities/{entity_hint}/activity` is related-entity scoped; neither provides a customer-only activity boundary.
- **Affected UI routes/components:** `/customers/:customerId` activity region and `/cases/:caseId` customer-context activity subsection.
- **Security/visibility implications:** The DTO must be owner-scoped through the customer and must omit private note bodies, EDD confidential comments, EDD narrative fields unless explicitly approved for an owner-only component, audit internals, value hashes, credentials, session material, checker-private markers, cross-owner identifiers, and raw database rows.
- **A/D or competition implications:** Any accepted contract must be checked against AML-2 activity/timeline, AML-3 graph, AML-4 export, and AML-5 network-room profiles so it does not create a side channel around note or EDD storage.
- **Checker implications:** Checker flows for case-note and EDD storage would need assertions that customer activity does not expose checker/private values outside the approved owner path.
- **Does it block the entire wave or only one subsection?:** Only customer-scoped activity; owner case timeline and reachable entity activity remain implementable.
- **Frontend fallback:** Defer customer activity, show owner case timeline where case context exists, and show related entity activity only when the customer DTO includes a meaningful entity reference.
- **Suggested minimal contract (not implementation):** Return `{ "activities": [{ "customer_id", "object_type", "object_id", "event_type", "public_message", "changes", "created_at", "visibility_scope" }] }`, using the same redacted `changes` shape as the secure case timeline.
- **Tests that would be required if accepted:** Owner customer activity returns only the owner’s customer events; cross-owner and unknown customers fail closed as `404`; malformed IDs return `400`; response shape excludes private note bodies, EDD confidential comments, EDD narrative fields unless explicitly authorized, audit internals, hashes, auth/session material, checker-private fields, and raw rows.

## Request template

### UI-BCR-XXX — Short name

- **Status:** proposed / accepted / rejected / superseded
- **Requested endpoint or DTO change:**
- **Investigator workflow requiring it:**
- **Why existing endpoints cannot support the workflow:**
- **Affected UI routes/components:**
- **Security/visibility implications:**
- **A/D or competition implications:**
- **Checker implications:**
- **Does it block the entire wave or only one subsection?:**
- **Frontend fallback:** defer / read-only shell / no control shown
- **Suggested minimal contract (not implementation):**
- **Tests that would be required if accepted:**

Do not implement a proposed request until an explicit architecture/orchestrator task authorizes it.
