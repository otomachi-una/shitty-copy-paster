Source-to-Sink Trace Report
1. Sensitive Field Traces
Source Field
	
Writer / Origin
	
Reader Chain
	
Policy / Identity Check
	
Final Sink
	
Verdict


users.password_hash
	
UserRepository.create (bcrypt)
	
UserRepository.password_valid? → Auth::Password.verify?
	
Internal only; never passed to presenter
	
Auth gate logic
	
Safe. Never serialized. UserPresenter.render excludes it.


sessions.token_digest
	
SessionRepository.create (HMAC-SHA256)
	
SessionRepository.find_by_token → authenticated_session
	
HMAC verification w/ credential_key_base
	
Session lookup only
	
Safe. Raw token returned only at creation; digest stored/compared.


orders.client_reference
	
OrderService.place → OrderRepository.create
	
Path A: TradeReceiptRepository.create → BrokerReportService.execution_enrichment_snapshot → venue_booking_context_for → report_row_for → PartnerReportRowDTO.trade
	
Broker cap + attribution join scopes trades, but enrichment fetches all receipts for those trades without re-filtering by attribution or trader consent
	
GET /api/broker/reports/trades response field booking_marker
	
Candidate. Trader’s private booking ref leaks to broker via secondary enrichment query that ignores field-level ownership.


orders.client_reference
	
Same as above
	
Path B: MatchingService.create_receipts → trade_receipts.client_reference → TradePresenter.render_participant_detail → VenueAllocationDTO.notice
	
Participant auth (find_by_trade_for_user) grants access to own receipt, but bookings_for_execution returns all receipts for trade; counterparty’s receipt included in booking_rows
	
GET /api/trades/:id (authed) response field venue_allocation.desk_ref
	
Candidate. Counterparty’s client_reference exposed to trade participant via unscoped batch fetch of sibling receipts.


orders.execution_memo
	
OrderService.place → OrderRepository.create
	
OrderPresenter.render → AccountOrderDTO.render
	
Owner-scoped via find_by_id_for_user / list_for_user
	
GET /api/orders/:id, GET /api/orders
	
Safe. Access strictly limited to order owner.


rfqs.delivery_terms
	
RFQService.create → RFQRepository.create
	
RFQSettlementService.create_receipts → copied to trade_receipts.client_reference for both owner and maker
	
Settlement requires owner auth; maker implicitly consents by quoting
	
trade_receipts table → downstream sinks (see orders.client_reference paths above)
	
Contributing Factor. Private delivery terms propagate into receipt field that later leaks via broker report and trade detail paths.


rfqs.public_comment
	
RFQService.create → RFQRepository.create
	
RFQRepository.list_board → board_row → RFQBoardDTO.render; also search_public_comments
	
Public board field; validated via MarketIntegrityPolicy.optional_client_text (max 256, no control chars/reserved markers)
	
GET /api/rfq/board, GET /api/rfq/:id
	
Safe. Intentionally public; validated at write time.


conditional_orders.signal_context
	
ConditionalOrderService.create → ConditionalOrderRepository.create
	
ConditionalTriggerService.trigger_order → activation_context_for → PublicFeedService.publish_conditional_trigger → public_feed_events.payload_json → PublicFeedEventPresenter.event_payload → ActivationContextDTO.deep_event_attributes
	
Write-time: normalize_payload enforces EVENT_PAYLOAD_FIELDS whitelist + depth/key/string limits. Read-time: presenter re-expands whitelisted activation_context key
	
GET /api/feed/public response field payload.activation_context.*
	
Safe (with caveat). Write-time allowlist prevents arbitrary keys. Presenter expansion is bounded by what was persisted. No bypass found.


broker_attributions.user_reference
	
BrokerService.create_attribution → BrokerAttributionRepository.create_for_trader
	
BrokerAttributionPresenter.render
	
Broker-scoped via list_for_broker(broker_user_id:)
	
GET /api/broker/attributions (implicit via campaign list), attribution create response
	
Safe. Only visible to owning broker. Validated max 128 chars.


ledger_entries.*
	
LedgerRepository.append
	
LedgerPresenter.render
	
Owner-scoped via list_for_user(user_id:)
	
GET /api/ledger
	
Safe. Append-only; no cross-user read path.


wallets.available_balance
	
WalletRepository.apply_delta
	
WalletPresenter.render
	
Owner-scoped via list_for_user(user_id:)
	
GET /api/wallets
	
Safe.


trade_receipts.fee_amount, fee_asset
	
MatchingService.create_receipts, RFQSettlementService.create_receipts
	
MarketDataPresenter.render_user_trade, AccountBookingDTO.receipt, PartnerReportRowDTO.trade
	
User-scoped (user_trades), owner-scoped (receipt_for_user), broker-scoped (attribution join)
	
Multiple API responses
	
Safe. Fee data is transactional metadata; audience matches receipt ownership or authorized broker scope.


public_feed_events.payload_json
	
PublicFeedRepository.append
	
PublicFeedEventPresenter.parsed_payload → event_payload
	
None (public endpoint)
	
GET /api/feed/public
	
Safe. Write-time validation enforces strict schema; read-time parsing respects whitelist.
2. Public Feed & Event Stream Trace
Creation Path:
ConditionalTriggerService.trigger_order → PublicFeedService.publish_conditional_trigger → PublicFeedRepository.append
payload constructed with explicit keys: conditional_order_id, side, trigger_type, trigger_price, limit_price, status, activation_context.
normalize_payload(event_type, payload) called inside append: validates each key against EVENT_PAYLOAD_FIELDS["market_signal_activated"], rejects unknown keys, enforces depth ≤4, string ≤512, total bytes ≤4096.
activation_context itself built via ActivationContextDTO.render(signal: {...}) which only includes kind, threshold, routing_profile, signal_context — all derived from conditional order fields already validated at creation.
Persisted as JSON string in payload_json.
Read Path:
PublicFeedEventPresenter.render(event) → event_payload(event) → parsed_payload(event[:payload_json]) → iterates keys, keeps only those in EVENT_PAYLOAD_FIELDS[event_type], expands activation_context via deep_event_attributes.
Expansion is recursive but bounded by what was persisted (write-time validated).
No separate copy or mirror exists; single source of truth is public_feed_events table.
No queue, cache, or subscriber layer in codebase.
Verdict: Safe. Write-time allowlist is authoritative; read-time expansion cannot exceed it.
3. Aggregate & Batch Enrichment Traces
Broker Trade Report Enrichment:
BrokerReportService.trade_rows → base dataset correctly joins broker_attributions to scope trades.
→ execution_enrichment_snapshot(rows) extracts trade_ids, queries trade_receipts.where(trade_id: trade_ids) without user/attribution filter.
→ venue_booking_context_for(receipt_rows) picks first non-empty client_reference from any receipt for that trade.
→ This value (trader’s order.client_reference) included in report row as booking_marker.
Identity Mismatch: Broker authorized for trade via attribution, but not for counterparty’s receipt fields. Batch fetch ignores field-level ownership.
Trade Detail Participant View:
OrderService.participant_trade_detail → trade_receipt_repository.find_by_trade_for_user (scoped) gets own receipt.
→ bookings_for_execution(trade_id:) fetches all receipts for trade.
→ TradePresenter.render_participant_detail passes full booking_rows to template; allocation_notice(booking_row) renders counterparty’s client_reference as desk_ref.
Identity Mismatch: Participant authorized for own receipt, but batch fetch exposes sibling receipt’s private field.
4. Reviewed Flows Without Candidates
Flow
	
Rationale


User registration/login
	
Password never leaves bcrypt verify; token digest stored; raw token ephemeral.


Wallet/Ledger reads
	
Strict user_id scoping in repository; no admin/backdoor.


Order CRUD
	
All operations scoped via user_id param matched to session user.


RFQ board/detail
	
Board uses field whitelist; detail owner-scoped; workup capability-gated.


Conditional order CRUD
	
Owner-scoped; trigger service is internal actor with no HTTP exposure.


Faucet
	
Per-user idempotency; ledger append-only; no cross-user state.


Market data endpoints
	
Public data only; no user fields.


Static asset serving
	
Path traversal blocked; no dynamic content.


Health/readiness
	
Operational metadata only.


Broker campaign/attribution management
	
Scoped to broker; payload validation blocks reserved keys.


Monthly broker reports
	
Aggregated totals; no individual refs or markers.
5. Candidate Findings Summary
Trader Booking Reference Leakage to Broker
Source: orders.client_reference
Sink: GET /api/broker/reports/trades → booking_marker
Evidence: BrokerReportService.execution_enrichment_snapshot line ~147: database[:trade_receipts].where(trade_id: trade_ids).order(:id).all lacks user/attribution filter. venue_booking_context_for extracts client_reference from any matching receipt.
Gate Failure: Attribution join authorizes trade visibility but not counterparty receipt field access.
Counterparty Booking Reference Leakage in Trade Detail
Source: orders.client_reference (via trade_receipts.client_reference)
Sink: GET /api/trades/:id (authenticated) → venue_allocation.desk_ref
Evidence: OrderService.participant_trade_detail calls bookings_for_execution(trade_id:) which returns all receipts. TradePresenter.render_participant_detail renders non-owner receipt’s client_reference via VenueAllocationDTO.notice.
Gate Failure: Own-receipt auth does not extend to sibling receipt fields.
Delivery Terms Propagation Amplifies Leakage
Source: rfqs.delivery_terms
Sink: Same as #1 and #2 via trade_receipts.client_reference
Evidence: RFQSettlementService.create_receipts copies rfq[:delivery_terms] to both receipts’ client_reference. This makes RFQ-specific private terms subject to the same unauthorized exposure paths.
RECEIVED-19dde41773e6
