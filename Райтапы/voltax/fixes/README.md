# VoltaX Reference Fix Artifacts

Wave 10 reference fixes for VoltaX Exchange live here as patch artifacts. The participant build carries the intended gameplay behavior directly; fix patches are applied to a temporary checkout or fixed overlay for validation.

## Required Artifacts

| EX | Patch artifact | Leak closed | Positive workflow evidence |
| --- | --- | --- | --- |
| EX-1 | `EX-1-client-order-id-collision.patch` | Cross-account `Order.execution_memo` through reference lookup | W10-A packaged; apply patch, run EX-1 exploit-negative regression, and keep checker place 1 owner order PUT/GET |
| EX-2 | `EX-2-rfq-preview.patch` | RFQ `workup_terms` through liquidity quote workup | W10-B packaged; apply patch, run EX-2 exploit-negative regression, and keep checker place 3 owner RFQ PUT/GET |
| EX-3 | `EX-3-counterparty-receipt.patch` | Counterparty receipt marker through trade-detail allocation context | W10-C packaged and W17-E refreshed; apply patch, run EX-3 exploit-negative regression, and keep checker place 2 owner receipt PUT/GET plus matching settlement |
| EX-4 | `EX-4-broker-report.patch` | Counterparty receipt marker through partner trade report | W10-D packaged; apply patch, run EX-4 exploit-negative regression, and keep partner campaign, attribution, trade report, monthly report, and checker place 2 owner receipt workflows |
| EX-5 | `EX-5-conditional-feed.patch` | Conditional-order `signal_context` through public feed activation context | W10-E packaged and W17-FIX-B refreshed for the W17 feed-tail anchor route; apply patch, run EX-5 exploit-negative regression, and keep checker place 4 owner conditional-order PUT/GET plus trigger/public feed polling |

## Patch Rules

- Use unified diff patch files with paths rooted at the repository root.
- Keep one patch per EX vector.
- Do not add routes named `/flag`, `/api/admin`, `/api/debug`, `/api/checker`, `/api/exploit`, `/api/fix`, or `/api/vulnerability`.
- Do not require direct database access, privileged credentials, or admin-only setup to validate a fix.
- Do not close a sample by deleting the affected legitimate workflow.
- Keep checker owner PUT/GET behavior valid for all four places.
- Keep secure/fixed behavior as the default in normal runs.

## Validation Expectations

Each per-EX fix handoff must name the patch artifact, the matching Wave 9 exploit script, the focused DB-backed regression specs, and the checker workflow evidence. Validation must prove exploit-negative behavior and legitimate-workflow-positive behavior against the applied patch or fixed-profile overlay.

Run the static Wave 10 packaging gate with:

```powershell
ruby bin\validate-wave10
bundle exec rake validate:wave10
```

The gate is expected to fail until all five per-EX patch artifacts and fix handoffs are present.

## Packaged Fixes

### EX-1 Reference Lookup Collision

`EX-1-client-order-id-collision.patch` removes the unscoped reference lookup from `GET /api/orders/lookup/{reference_code}` in the fixed artifact. The route remains present and uses the authenticated `current_user` plus `reference_code` namespace. Owner reference lookup and owner `GET /api/orders/{order_id}` still return the owner projection, including `execution_memo`; cross-account lookup returns `404 not_found`.

Required validation for W10-A is exploit-negative and legitimate-workflow-positive: the Wave 9 EX-1 exploit must no longer recover another user's `execution_memo`, while checker place 1 owner PUT/GET and ordinary public orderbook/trade views remain valid.

### EX-2 RFQ Workup Leak

`EX-2-rfq-preview.patch` removes the workup-terms branch from the fixed artifact. `GET /api/rfq/{rfq_id}/workup` remains present and usable by liquidity accounts, but it returns the dedicated workup allowlist and never includes `workup_terms`. Owner RFQ create/read and quote/accept workflows remain intact.

Required validation for W10-B is exploit-negative and legitimate-workflow-positive: the Wave 9 EX-2 exploit must no longer recover `workup_terms` from quote workup, while checker place 3 owner RFQ PUT/GET and ordinary RFQ board, workup, quote, accept, and owner GET workflows remain valid.

### EX-3 Counterparty Receipt Leak

`EX-3-counterparty-receipt.patch` removes vulnerable trade-detail counterparty settlement rendering from the fixed artifact. `GET /api/trades/{trade_id}/receipt` remains present and ignores `counterparty=1` safely by returning only the authenticated user's own receipt; authenticated trade details remain scoped to the caller's own settlement context, and uninvolved users receive `404 not_found`. The canonical vulnerable exploit requires the attacker to become a same-trade participant through ordinary public order placement before reading participant trade detail; the fix removes only the over-joined counterparty receipt field. Receipt private fields remain owned by `receipt.user_id == current_user.id`.

Required validation for W10-C/W17-E is exploit-negative and legitimate-workflow-positive: the EX-3 exploit must no longer recover another participant's `desk_ref` from trade details, while checker place 2 owner receipt PUT/GET, public trade facts, two receipt rows per trade, and matching settlement remain valid.

### EX-4 Broker Report Overreach

`EX-4-broker-report.patch` removes receipt-marker collection and extended trade rendering from the fixed artifact. `GET /api/broker/reports/trades` remains present and useful, but always uses the dedicated partner report allowlist containing partner-authorized campaign, attribution, trade, volume, fee, rebate, origin, and time-bucket fields. Monthly reports remain aggregate-only.

Required validation for W10-D is exploit-negative and legitimate-workflow-positive: the Wave 9 EX-4 exploit must no longer recover counterparty `booking_marker` from partner trade reports, while partner campaign ownership, spot attribution preconditions, trade reports, monthly reports, and checker place 2 owner receipt GET remain valid.

### EX-5 Conditional Public Feed Leak

`EX-5-conditional-feed.patch` removes signal context from public feed activation payloads in the fixed artifact. Conditional trigger processing still publishes `market_signal_activated` public events, and `GET /api/feed/public` remains sequence-addressable, including the W17 `next_sequence` freshness cursor, but fixed public events use only the public feed allowlist and never include `signal_context`.

Required validation for W10-E/W17-FIX-B is exploit-negative and legitimate-workflow-positive: the EX-5 exploit must no longer recover conditional-order `signal_context` from public feed polling before or after trigger processing, while checker place 4 owner conditional-order PUT/GET, owner signal-context visibility, trigger worker publication, feed sequence filtering, `next_sequence` freshness anchoring, and public feed polling remain valid.
