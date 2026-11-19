# Sentinel AML Frontend Architecture

## Current structure

```text
frontend/
  e2e/
    investigation-smoke.spec.ts
    responsive-smoke.spec.ts
    security-states.spec.ts
    sentinelMockApi.ts
  public/
    runtime-config.js
  scripts/
    security-scan.mjs
  src/
    app/
      AppShell.tsx
      AuthGate.tsx
      providers.tsx
      router.tsx
    features/
      customers/
        customerWorkflow.ts
    pages/
      AuthPage.tsx
      AlertQueuePage.tsx
      AlertDetailPage.tsx
      CasePage.tsx
      CustomerPage.tsx
      ExportDetailPage.tsx
      GraphEntityPage.tsx
      NetworkRoomsPage.tsx
      NotFoundPage.tsx
    shared/
      api/
        adapters.ts
        adapters/
          alerts.ts
          auth.ts
          cases.ts
          customer.ts
          exporting.ts
          graph.ts
          networkRoom.ts
          primitives.ts
        client.ts
        contracts.ts
        sentinel.ts
      auth/
        redirect.ts
        session.ts
        sessionBoundary.ts
      config/
        runtime.ts
      lib/
        format.ts
        routeParams.ts
      ui/
    styles.css
  tests/
```

## Responsibility boundaries

- `app`: bootstrap, routing, authenticated shell, provider wiring.
- `pages`: route-level composition and screen-specific panels.
- `features/customers`: customer workflow helpers, form validation, request shaping, and safe return-context parsing.
- `shared/api/client.ts`: transport, safe error normalization, bearer header handling.
- `shared/api/sentinel.ts`: endpoint functions only; it does not shape render models.
- `shared/api/adapters/*`: strict DTO allowlists by domain.
- `shared/auth/sessionBoundary.ts`: centralized session/cache isolation for login, registration, logout, and 401 expiry.
- `shared/ui`: low-level accessible primitives.
- `styles.css`: current global design tokens, layout primitives, responsive behavior, and domain-specific styling.

## Deliberate decomposition

The latest correction wave decomposes only overloaded areas that had clear mixed responsibilities:

- the former monolithic API adapter module is split into domain adapters while preserving the `shared/api/adapters.ts` import surface;
- customer form validation and request builders moved out of `CustomerPage` into `features/customers/customerWorkflow.ts`;
- `CustomerPage` keeps route data wiring and UI panels;
- `CasePage` remains a route-level workspace file because its exported widgets are still tightly coupled to the case evidence spine and existing tests;
- global styles remain centralized because this UI has no CSS module pipeline and a style split would be mostly file movement rather than responsibility reduction.

Future decomposition should prefer this direction only when complexity justifies it:

```text
features/
  alerts/
  cases/
  customers/
  edd/
entities/
  alert/
  case/
  customer/
widgets/
  evidence-spine/
  activity-timeline/
  decision-panel/
  relation-graph/
shared/
  api/
  auth/
  ui/
  config/
  errors/
```

Do not move files solely to match that tree. A move should either remove mixed business/rendering responsibility, isolate a reusable widget, or strengthen an adapter/security boundary.

## Server-state policy

TanStack Query owns server state. Do not duplicate canonical server objects into global client stores. Local component state is limited to draft form input, disclosure/selection state, or presentational state.

Writes must not be automatically retried. After successful mutations, invalidate only relevant query keys. Session changes must go through the centralized session boundary rather than local `queryClient.clear()` calls in components.

## Runtime configuration

`runtime-config.js` is loaded before the application and may provide `apiBaseUrl`. Same-origin API calls are the safe default. Do not embed environment secrets into Vite variables or committed JS.

## Testing architecture

- Vitest covers API boundary, adapters, session routing, rendered copy, UI primitives, and page-level states.
- Playwright covers browser smoke flows on desktop and mobile using a mock Sentinel API route layer.
- Production build uses Vite with source maps disabled.
- Source and dist security scans are separate commands.
