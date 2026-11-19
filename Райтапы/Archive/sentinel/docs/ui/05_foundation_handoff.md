# Sentinel AML UI - Current Handoff

Last updated: 2026-09-10 during FIX-05 architecture/documentation sync.

## Current state

The frontend is a readiness-candidate internal compliance workspace under `frontend/`. It is built with React, Vite, TypeScript, React Router, TanStack Query, Vitest, Playwright, and a local source/dist security scanner.

## Final UI surfaces

- Register, login, current analyst, logout, and session-expiry handling.
- Alert queue and alert detail.
- Alert claim, triage, and create-case happy path.
- Case workspace with evidence spine, owner private notes, investigation timeline, duplicate candidates, duplicate preview, export creation, and customer context.
- Customer workspace with identity, account records, transaction records, owner EDD create/update/read, and related entity navigation.
- Graph entity workspace with safe related cases, EDD summaries, and related activity fallback.
- Export detail with redacted bundle ledger.
- Network room list, room detail/join, and references-only dossier.
- Loading, empty, error, unauthorized, forbidden, not-found, redacted, and private visibility states.

## Conditional or deferred UI surfaces

- Existing-case recovery after `duplicate_case` remains conditional on UI-BCR-001.
- Customer-scoped activity remains conditional on UI-BCR-002.
- Global customer/case/export collection navigation is deferred because the backend does not expose canonical collection routes.
- Final competition package promotion, manifests, checksums, and player/admin archive acceptance remain outside frontend ownership.

## Architecture notes

- `shared/api/adapters.ts` is now a barrel over domain adapter modules.
- `features/customers/customerWorkflow.ts` owns customer draft validation, request shaping, and safe return-context parsing.
- `CustomerPage` remains responsible for customer route composition and rendered panels.
- `CasePage` remains a route-level case workspace with exported widgets; it is still a good future candidate for splitting into evidence-spine, decision-panel, and activity-timeline widgets if those widgets become reused.
- `styles.css` remains centralized because there is no CSS module pipeline and the current split would be mostly file movement.

## Security and visibility posture

- Rendering uses strict allowlisted DTO adapters.
- Owner private case notes and EDD confidential comments render only in owner-context sections.
- Side views for duplicate, timeline, graph, export, and network dossier have dedicated adapters and do not reuse owner private renderers.
- A centralized session boundary cancels in-flight queries and clears cached server state before credentials are removed or replaced.
- Production source maps are disabled.
- Source, production bundle, and frontend source-package scans are reproducible.
- Playwright covers the two-analyst session isolation path in a browser.

## Known backend/runtime questions

- UI-BCR-001: owner-scoped existing-case locator for duplicate case creation conflicts.
- UI-BCR-002: owner-scoped customer activity endpoint.
- NPM currently reports dependency audit findings during `npm ci`; this frontend wave did not force dependency upgrades.
- The local workspace may not contain Git metadata, so VCS diff/status evidence can be unavailable even when filesystem changes are present.

## Verification baseline

Use the clean gate in `docs/ui/04_validation_and_handoff.md`. The latest FIX-05 handoff must report exact command results for the current workspace rather than relying on this document.

## Backend changes

None. Backend remains outside frontend ownership unless a separate prompt explicitly authorizes a backend contract change.
