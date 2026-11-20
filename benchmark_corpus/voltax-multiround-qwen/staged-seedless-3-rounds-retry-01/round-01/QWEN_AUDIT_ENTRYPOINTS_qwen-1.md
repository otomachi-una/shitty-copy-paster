Attack Surface & Route Reconciliation Report
1. Route Inventory Reconciliation
Direct inspection of lib/voltax/web/application.rb confirms the service map inventory is complete. No hidden subrouters, aliases, or unlisted branches exist.
Static Middleware: UIStatic intercepts GET /, /index.html, /main.js, /styles.css before Sinatra dispatch. Path traversal mitigated by start_with?(root_prefix).
Sinatra Routes: All 38 API routes match the service map exactly.
Fallbacks: not_found (404) and error (500) handlers return generic JSON; no stack traces or sensitive data leaked.
Method Checks: Sinatra enforces method matching; e.g., POST /api/orders does not accept GET.
2. Vulnerability Candidates
Route
	
Resource
	
Gate
	
Serialized Field / Side Effect
	
Source Evidence


GET /api/orders/lookup/:reference_code
	
Order
	
Auth + Cap(orders)
	
Full order object including execution_memo, client_reference, user_id
	
OrderReferenceResolver.reference_context_for hardcodes channel: :desk_order → ReferenceDirectory.reference_scope_for returns :desk_book → AccountReferenceBook.lookup calls order_repository.resolve_order_reference(reference_code:) which queries orders.where(client_order_id: ...) without user_id filter. Any authenticated user with orders capability can enumerate/retrieve any order by guessing/brute-forcing client_order_id.


GET /api/trades/:id
	
Trade Receipt
	
Optional Auth
	
account_booking.booking_ref, venue_allocation.desk_ref
	
When Bearer token present, calls participant_trade_detail_response → TradePresenter.render_participant_detail. If trade_receipt_repository.find_by_trade_for_user finds a receipt for current user, returns full detail. However, booking_rows fetched via bookings_for_execution(trade_id:) returns all receipts for that trade regardless of user. allocation_notice(booking_row) exposes counterparty's client_reference as desk_ref to any trade participant. Counterparty's booking reference leaks to taker/maker.


GET /api/broker/reports/trades
	
Broker Report
	
Auth + Cap(broker_reports)
	
booking_marker (derived from trader's order.client_reference)
	
BrokerReportService.report_row_for includes booking_marker from enrichment_snapshot. Snapshot built via venue_booking_context_for(receipt_rows) which extracts receipt[booking_marker_column] from all receipts for attributed trades. While attribution join scopes trades correctly, the client_reference field on those trades belongs to the trader's order, not the broker. Trader's internal booking references exposed to broker without explicit consent or field-level redaction.


POST /api/rfq/:id/accept
	
RFQ Settlement
	
Auth (Owner)
	
Side effect: creates trade_receipts with client_reference: rfq[:delivery_terms]
	
RFQSettlementService.create_receipts copies rfq[:delivery_terms] verbatim into both owner and maker receipts as client_reference. This value later surfaces in broker reports (see above) and trade detail views. If delivery terms contain sensitive info intended only for RFQ context, it propagates to settlement records accessible via different authorization paths.


GET /api/feed/public
	
Public Feed Event
	
None
	
activation_context.signal_context
	
PublicFeedEventPresenter.event_payload expands activation_context via ActivationContextDTO.deep_event_attributes. While PublicFeedRepository.normalize_payload validates keys at write time, signal_context originates from conditional_orders.signal_context (user-supplied, max 512 chars). The presenter re-expands nested structures. If conditional order creator embeds structured data in signal_context, it gets flattened and exposed publicly. Write-time validation checks reserved markers but does not strip arbitrary nested keys beyond depth/size limits.
3. Reviewed Entry Points Without Candidates
Route
	
Verdict
	
Rationale


POST /api/auth/register, POST /api/auth/login
	
Safe
	
Password hashed via bcrypt; token returned only on create; digest stored. No PII in response beyond username/profile.


GET /api/auth/me
	
Safe
	
Returns only UserPresenter.render fields; password_hash excluded. Session expiry only.


GET /api/markets, /ticker, /candles, /trades, /orderbook
	
Safe
	
Public market data only; no user-scoped fields.


POST /api/faucet
	
Safe
	
Idempotency enforced per-user; ledger append-only; no cross-user leakage.


GET /api/wallets, /ledger
	
Safe
	
Strictly scoped via list_for_user(user_id:); no admin override.


POST /api/orders, DELETE /api/orders/:id
	
Safe
	
Fund locking/unlocking scoped to user_id; matching engine validates ownership before settlement.


GET /api/orders, /orders/:id
	
Safe
	
Scoped via find_by_id_for_user / list_for_user.


POST /api/rfq, GET /api/rfq/:id
	
Safe
	
Owner-scoped via find_by_id_for_owner. Board view uses PUBLIC_BOARD_FIELDS whitelist.


POST /api/rfq/:id/quote
	
Safe
	
Validates maker != owner; capability check enforced.


POST /api/rfq/:id/simulate-settlement
	
Safe
	
Dry-run only; no writes; owner/maker check enforced.


GET /api/rfq/:id/workup, /accepted-counterparty
	
Safe
	
Capability-gated; workup excludes private RFQ fields.


POST /api/broker/campaigns, GET /api/broker/campaigns
	
Safe
	
Scoped to broker_user_id; integrity policy blocks reserved keys.


POST /api/broker/attributions
	
Safe
	
ensure_assignment_payload! blocks all BROKER_ASSIGNMENT_KEYS; trader validated as public profile.


GET /api/broker/reports/monthly
	
Safe
	
Aggregated totals only; no individual trade refs or booking markers.


POST /api/conditional-orders, GET /api/conditional-orders*
	
Safe
	
Owner-scoped; trigger processing is internal actor only.


GET /api/users/me/trades, /trades/:id/receipt
	
Safe
	
Strictly scoped via find_by_trade_for_user.


Static assets (/, /main.js, etc.)
	
Safe
	
Path traversal blocked; no dynamic content.


/health, /ready
	
Safe
	
No sensitive data; migration status is operational metadata.
4. Aggregate & Enrichment Authorization Verification
Broker Reports: Trade rows correctly filtered via broker_attributions join. However, secondary enrichment (execution_enrichment_snapshot) fetches all receipts for matched trades without re-filtering by attribution scope. This is the root cause of booking_marker leakage.
Trade Detail: Primary receipt correctly scoped. Secondary booking_rows query (bookings_for_execution) lacks user filter, causing counterparty data exposure.
Public Feed: Write-time validation is strong (EVENT_PAYLOAD_FIELDS whitelist, reserved text rejection). Read-time expansion is safe only if write-time validation caught all malformed payloads. No evidence of bypass, but defense-in-depth gap exists.
RFQ Board: list_board explicitly selects PUBLIC_BOARD_FIELDS; quote_count derived from count query, not joined quote records. Safe.
5. Generated Text Field Tracing
booking_marker: Sourced from orders.client_reference → copied to trade_receipts.client_reference → extracted in BrokerReportService.venue_booking_context_for → rendered in PartnerReportRowDTO.trade. Audience: broker. Original owner: trader. No redaction.
desk_ref: Same source as above, exposed via VenueAllocationDTO.notice in trade detail. Audience: trade participant. Original owner: counterparty. No redaction.
signal_context: User-supplied string → stored in conditional_orders → embedded in feed event payload → expanded by presenter. Audience: public. Validation: length + control chars + reserved markers. Structured content preserved.
public_comment (RFQ): Validated via MarketIntegrityPolicy.optional_client_text (max 256, no control chars, no reserved markers). Rendered in board/detail. Safe.
execution_memo: Validated same as above. Returned only in owner-scoped order views. Safe.
RECEIVED-46f3dd9743f4
