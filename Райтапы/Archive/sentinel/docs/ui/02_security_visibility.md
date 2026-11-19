# Sentinel AML UI Security and Visibility Policy

## Rendering rule

Frontend rendering is allowlist-based. A component renders only fields named by its view contract. Extra JSON fields returned by a future server version must be ignored unless a dedicated adapter and UI review explicitly allow them.

The frontend must not use:

- raw JSON rendering;
- generic object spreading from API responses into render models;
- blacklist-only sensitive filtering;
- developer/debug copy in product UI.

## Adapter boundaries

Current adapter responsibilities are split by domain under `frontend/src/shared/api/adapters/`:

- `auth.ts`: user, auth, current analyst;
- `alerts.ts`: alert queue/detail/action responses;
- `cases.ts`: case shell, owner notes, timeline, duplicate preview, entity activity;
- `customer.ts`: customer, accounts, transactions, owner EDD;
- `graph.ts`: related entity side views;
- `exporting.ts`: redacted export bundles;
- `networkRoom.ts`: participant room and references-only dossier views;
- `primitives.ts`: shared runtime DTO guards.

`frontend/src/shared/api/adapters.ts` is a stable barrel export only. Tests must guard the concrete domain adapter files, not only the barrel.

## Owner Private Components

The following data is permitted only in owner-context components:

- case note body;
- EDD confidential comment;
- owner EDD narrative fields when returned by the owner EDD contract.

Owner private components must not be reused in graph, duplicate, export, network-room, or other related/shared views without a new explicit adapter and review.

## Side-view components

Related views use dedicated DTOs and cannot fall back to owner DTOs or raw JSON:

- duplicate preview: overlap/public case information only;
- timeline: documented event summary/change representation only;
- graph: safe relationship metadata only;
- export: documented redacted bundle only;
- network dossier: documented room/case projection only.

Visibility markers belong to the evidence block or projection they describe. A page header may say “Owner context” or “Investigation workspace”, but it must not label a whole mixed page or side view as shareable unless the backend contract explicitly guarantees that permission. The current frontend taxonomy describes display context, not redistribution rights: Owner private, Confidential, Investigation context, Limited view, and Redacted.

## Session boundary

The frontend has a centralized session boundary in `frontend/src/shared/auth/sessionBoundary.ts`.

On explicit logout, `401`/session expiry, successful login, and successful registration:

- in-flight queries are cancelled;
- the previous identity's query cache is cleared before credentials are replaced;
- session credentials are removed or replaced through the dedicated session module;
- authenticated UI is allowed to render only after the new session boundary completes.

Sensitive server state must not be stored in `localStorage`. Query keys may contain resource type plus numeric/public locators, never bearer tokens or private payloads.

## Client state and logs

- Bearer session material is stored only in the session module.
- Never place tokens in query keys, URLs, UI copy, console output, analytics, or error messages.
- Never log API request or response bodies.
- Writes are not globally retried.
- `401` clears the frontend session and redirects to login.
- `403` and `404` render safe product states and do not reveal cross-owner existence.

## Error handling

Errors normalize to safe product messages. UI must not display stack traces, SQL/package names, server internals, raw error bodies, endpoint-debug copy, or raw server codes where they would disclose implementation detail.

## Source maps and package safety

Production source maps are explicitly disabled. The player-facing scanner checks source and production `dist` JS/CSS/HTML output for forbidden/internal tokens and fails on source map artifacts.

The reproducible security chain is:

```bash
npm run security:scan
npm run build
npm run security:scan:dist
```

The Playwright security suite also verifies session isolation, unauthorized redirect, safe `401`/`403`/`404`/`409`/`422`/`500`, network-failure recovery, and session-expiry behavior in a browser.
