# Sentinel AML UI Contract

## Purpose

This document defines the current frontend ownership boundary for Sentinel AML. The UI is a readiness-candidate internal AML investigation workspace built on the implemented HTTP contracts. It must remain evidence-led, product-facing, and safe under owner/private visibility rules.

## Non-negotiable direction

- The UI is an internal compliance investigation workspace, not a developer console, checker surface, or neon security dashboard.
- Use `$sentinel-aml-ui-director` for every user-facing UI task.
- Implement only from current HTTP handlers, DTOs, and documented contracts. Runtime code and tests are the source of truth when older wave wording disagrees.
- Treat owner-scoped `404` as a closed information boundary.
- Never render raw backend objects generically. Every rendered model must pass through an explicit typed adapter or a deliberately named view contract.
- Owner private content is allowed only in owner-context surfaces: case notes and owner EDD. Side views use separate allowlisted projections.
- Do not log response bodies, bearer tokens, private notes, confidential EDD comments, raw audit material, or generated security test payloads.
- Do not introduce debug/admin/raw API/database tooling into the frontend.

## Backend ownership

Backend source is outside frontend ownership.

Frontend work may inspect backend docs, handlers, and tests. It must not modify `cmd/`, `internal/`, `migrations/`, checker, sploits, fixes, worker, build tags, Go modules, ForcAD/runtime packaging, or backend runtime behavior unless a separate task explicitly authorizes that backend exception.

When a UI workflow needs a backend capability that does not exist:

1. Do not invent it in browser state.
2. Do not add a hidden convenience endpoint.
3. Record the gap in `docs/ui/backend_contract_change_requests.md`.
4. Mark only the affected UI subsection as conditional/deferred.
5. Continue all UI work supported by current contracts.

## Current frontend stack

- React 18
- Vite
- TypeScript strict mode
- React Router
- TanStack Query for server state
- semantic CSS tokens and accessible local primitives
- Vitest unit/component tests
- Playwright browser smoke tests
- source and production bundle security scans

## Implemented UI surfaces

Final readiness-candidate surfaces:

- register, login, current analyst session;
- authenticated shell with safe return routing;
- alert queue and alert detail;
- alert claim, triage, and create-case flow when the backend accepts it;
- case workspace with evidence spine, decision context, private owner notes, redacted timeline, duplicate candidates, duplicate preview, and export creation;
- customer workspace with identity, account and transaction evidence, owner EDD create/update/read, and related entity links;
- graph entity view with safe related-case, EDD summary, and activity projections;
- export detail with redacted bundle ledger;
- network room list, detail, join, and references-only dossier;
- loading, empty, error, unauthorized, forbidden, not-found, and session-expired states.

Conditional/deferred surfaces:

- duplicate-case conflict recovery needs an owner-scoped existing-case locator;
- customer-scoped activity needs a dedicated owner customer activity endpoint;
- global customer, case, and export collection pages are not implemented because the backend does not expose those collections.

## UI signature

The interface follows the evidence-led Sentinel direction:

- warm light canvas;
- quiet editorial hierarchy;
- explicit risk/status text;
- evidence spine for chronology and provenance;
- visible Owner private, Confidential, Investigation context, Limited view, and Redacted markers at the evidence block level;
- restrained borders and paper-like surfaces;
- accessible graph/timeline alternatives;
- no raw JSON renderer, giant KPI dashboard, decorative security imagery, or developer copy in product UI.
