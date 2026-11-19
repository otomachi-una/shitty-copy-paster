# Sentinel AML UI Route Map

## Implemented routes

| UI route | Purpose | Backend contract | Status |
| --- | --- | --- | --- |
| `/login` | analyst sign in | `POST /api/auth/login` | implemented |
| `/register` | analyst registration | `POST /api/auth/register` | implemented |
| `/alerts` | owned alert work queue | `GET /api/alerts/queue` | implemented |
| `/alerts/:alertId` | alert evidence and actions | alert detail, claim, triage, create-case routes | implemented |
| `/cases/:caseId` | owner case workspace | case detail, notes, timeline, duplicates, export creation | implemented |
| `/customers/:customerId` | owner customer workspace | customer detail, accounts, transactions, owner EDD | implemented |
| `/graph/entities/:entityHint` | network investigation context | graph entity, related cases, EDD summaries, entity activity where available | implemented with safe fallbacks |
| `/exports/:exportId` | regulatory export ledger | `GET /api/exports/{export_id}` | implemented |
| `/network/rooms` | participant room list | `GET /api/network/rooms` | implemented |
| `/network/rooms/:roomId` | participant room detail and join context | room detail and join routes | implemented |
| `/network/rooms/:roomId/dossier` | references-only network dossier | `GET /api/network/rooms/{room_id}/dossier` | implemented |

The root route redirects authenticated users to `/alerts`. Unknown UI routes render the safe not-found page.

## Navigation boundaries

- Navigation starts from alert queue, alert detail, case, customer, graph, export, and network room contexts that the backend can resolve.
- The UI does not fabricate global customer, case, export, graph, or room discovery beyond implemented backend routes.
- Deep links to protected routes go through the auth gate; after login, the sanitized return path is used.
- Query parameters and URL fragments are not used for bearer tokens or private evidence.

## Conditional workflows

- Creating a case from an alert is complete for successful creates. Duplicate-case conflict recovery remains conditional because the backend does not return an owner-scoped existing-case locator.
- Customer activity is conditional because there is no dedicated `GET /api/customers/{customer_id}/activity` contract.
- Entity activity is treated as a related side view only when the endpoint is available; failure leaves the primary graph context intact.

## Explicitly not assumed

The frontend must not assume collection endpoints such as `/api/customers`, `/api/cases`, or `/api/exports` when the runtime contract does not expose them. If product navigation later needs those surfaces, create or update `docs/ui/backend_contract_change_requests.md` rather than emulating canonical server collections in browser state.
