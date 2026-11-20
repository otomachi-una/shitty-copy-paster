A. HTTP Entry Points & Handler Map
Method
	
Path
	
Handler / Gate
	
Call Chain (Terminal Sink)
	
Output / Side Effects


GET
	
/health
	
Web::Application#get /health
	
None
	
{status: "ok", service: config.service_name}


GET
	
/ready
	
Web::Application#get /ready
	
DB.connect → SELECT 1 → DB.current_version
	
{status, checks: {postgres, migrations}}


POST
	
/api/auth/register
	
Public
	
UserRepository.create → SessionRepository.create
	
Returns user + session token. Writes users, sessions.


POST
	
/api/auth/login
	
Public
	
UserRepository.find_by_username → password_valid? → SessionRepository.create
	
Returns user + session token. Writes sessions.


GET
	
/api/auth/me
	
Auth (authenticated_session_and_user)
	
UserRepository.find_by_id
	
Returns current user + session expiry.


GET
	
/api/markets
	
Public
	
DB.seed_markets → MarketRepository.list
	
List of markets. Side effect: seeds default market if missing.


GET
	
/api/feed/public
	
Public
	
PublicFeedRepository.list → PublicFeedEventPresenter.render
	
Feed events. Filters by market_symbol, since_sequence.


POST
	
/api/faucet
	
Auth
	
FaucetService.claim → WalletService.credit_available → LedgerRepository.append
	
Credits VOLT/USDT. Idempotent via idempotency_key. Writes wallets, ledger_entries.


GET
	
/api/wallets
	
Auth
	
WalletRepository.list_for_user
	
User's wallet balances.


GET
	
/api/ledger
	
Auth
	
LedgerRepository.list_for_user
	
User's ledger entries.


GET
	
/api/users/me/trades
	
Auth
	
MarketDataService.user_trades → TradeRepository.find_by_id
	
User's trade receipts + trade details.


POST
	
/api/orders
	
Auth + Cap(orders)
	
OrderService.place → MatchingService.match_order → Ledger/Wallet/Trade/Receipt Repos
	
Creates order, locks funds, matches, settles. Writes orders, trades, trade_receipts, ledger_entries, wallets.


GET
	
/api/orders
	
Auth + Cap(orders)
	
OrderService.list_for_user
	
User's open/filled orders.


GET
	
/api/orders/lookup/:ref
	
Auth + Cap(orders)
	
OrderService.resolve_order_reference → ReferenceDirectory
	
Order by client_order_id. Scoped to user unless desk_order channel (hardcoded in resolver).


GET
	
/api/orders/:id
	
Auth + Cap(orders)
	
OrderService.find_for_user
	
Single order detail. Scoped to user_id.


DELETE
	
/api/orders/:id
	
Auth + Cap(orders)
	
OrderService.cancel → Wallet/Ledger Repos
	
Cancels order, unlocks funds. Writes orders, wallets, ledger_entries.


GET
	
/api/markets/:sym/orderbook
	
Public
	
OrderService.orderbook
	
Aggregated bids/asks.


GET
	
/api/markets/:sym/ticker
	
Public
	
MarketDataService.ticker
	
Last price, best bid/ask, volume.


GET
	
/api/markets/:sym/candles
	
Public
	
MarketDataService.candles
	
OHLCV candles.


GET
	
/api/markets/:sym/trades
	
Public
	
OrderService.trades_for_market
	
Recent public trades.


GET
	
/api/trades/:id/receipt
	
Auth
	
OrderService.receipt_for_user
	
Trade receipt scoped to user_id.


GET
	
/api/trades/:id
	
Optional Auth
	
OrderService.public_trade OR participant_trade_detail
	
If auth: full detail + booking/allocation. If anon: public summary only.


POST
	
/api/rfq
	
Auth
	
RFQService.create → RFQRepository.create
	
Creates RFQ. Writes rfqs.


GET
	
/api/rfq/board
	
Auth
	
RFQService.board → RFQRepository.list_board
	
Public board fields only (PUBLIC_BOARD_FIELDS).


GET
	
/api/rfq/:id/workup
	
Auth + Cap(rfq_quote)
	
RFQService.quote_workup_for
	
Workup packet for liquidity providers. Checks eligibility.


POST
	
/api/rfq/:id/quote
	
Auth + Cap(rfq_quote)
	
RFQService.submit_quote → RFQQuoteRepository.create
	
Submits quote. Validates maker != owner. Writes rfq_quotes.


POST
	
/api/rfq/:id/accept
	
Auth (Owner)
	
RFQService.accept_quote → RFQSettlementService.accept
	
Settles RFQ. Locks/transfers assets. Writes trades, receipts, ledger, wallets.


POST
	
/api/rfq/:id/simulate-settlement
	
Auth (Owner/Maker)
	
RFQService.simulate_settlement
	
Dry-run settlement legs. No writes.


GET
	
/api/rfq/:id/accepted-counterparty
	
Auth + Cap(rfq_quote)
	
RFQService.accepted_counterparty
	
Counterparty view for settled RFQ.


GET
	
/api/rfq/:id
	
Auth (Owner)
	
RFQService.owner_detail
	
Full RFQ + quotes. Scoped to user_id.


POST
	
/api/broker/campaigns
	
Auth + Cap(broker_campaigns)
	
BrokerService.create_campaign
	
Creates campaign. Writes broker_campaigns.


GET
	
/api/broker/campaigns
	
Auth + Cap(broker_campaigns)
	
BrokerService.list_campaigns
	
Broker's campaigns. Scoped to broker_user_id.


POST
	
/api/broker/attributions
	
Auth
	
BrokerService.create_attribution → ensure_safe_attribution_payload!
	
Links trader to campaign. Blocks reserved keys. Writes broker_attributions.


GET
	
/api/broker/reports/trades
	
Auth + Cap(broker_reports)
	
BrokerReportService.trade_rows
	
Trade rows linked via attribution. Joins attributions, campaigns, receipts, trades.


GET
	
/api/broker/reports/monthly
	
Auth + Cap(broker_reports)
	
BrokerReportService.monthly_rows
	
Aggregated monthly stats. Same join scope as trades.


POST
	
/api/conditional-orders
	
Auth
	
ConditionalOrderService.create
	
Creates conditional order. Writes conditional_orders.


GET
	
/api/conditional-orders
	
Auth
	
ConditionalOrderService.list_for_owner
	
User's conditional orders. Scoped to user_id.


GET
	
/api/conditional-orders/:id
	
Auth
	
ConditionalOrderService.owner_detail
	
Single conditional order. Scoped to user_id.
B. Sensitive Field Flow & Audience Map
Source Field
	
Reader / Transformer
	
Policy / Context Check
	
Audience / Sink
	
Notes


users.password_hash
	
UserRepository.password_valid?
	
Internal only; never serialized
	
Auth check
	
UserPresenter.render explicitly omits hash.


sessions.token_digest
	
SessionRepository.find_by_token
	
HMAC-SHA256 w/ credential_key_base
	
Auth gate
	
Raw token returned only on create; stored as digest.


orders.execution_memo
	
OrderPresenter.render
	
Owner-scoped (find_for_user)
	
API Response
	
Passed through AccountOrderDTO; no redaction but access-controlled.


orders.client_reference
	
TradePresenter.render_participant_detail
	
Owner-scoped via receipt_for_user
	
API Response
	
Included in account_booking packet only for trade participant.


trade_receipts.client_reference
	
BrokerReportService.report_row_for
	
Broker-scoped via attribution join
	
Broker Report
	
Mapped to booking_marker. Only visible if broker has valid attribution for trader.


rfqs.public_comment
	
RFQRepository.search_public_comments
	
Public board field
	
API /rfq/board
	
Searchable via ILIKE. Validated against control chars/reserved words.


rfqs.delivery_terms
	
RFQSettlementService.create_receipts
	
Owner/Maker only during settlement
	
trade_receipts.client_reference
	
Copied verbatim to receipt; later visible to broker via report if attributed.


conditional_orders.signal_context
	
PublicFeedEventPresenter.event_payload
	
Public feed event
	
/api/feed/public
	
Nested under activation_context. Expanded via ActivationContextDTO.deep_event_attributes.


broker_attributions.user_reference
	
BrokerAttributionPresenter.render
	
Broker-scoped (list_for_broker)
	
API Response
	
Trader-supplied ref visible only to broker who owns the campaign.


public_feed_events.payload_json
	
PublicFeedEventPresenter.event_payload
	
Whitelist filter (EVENT_PAYLOAD_FIELDS)
	
Public Feed
	
Keys not in whitelist are dropped. Reserved text markers rejected at write time.


broker_campaigns.name
	
BrokerCampaignPresenter.render
	
Broker-scoped
	
API Response
	
Validated max 128 chars; no PII filtering beyond integrity policy.


trades.* (all fields)
	
MarketDataService.user_trades
	
Owner-scoped (receipt.user_id == current_user)
	
API /users/me/trades
	
Join ensures user only sees own trades. Public endpoint returns subset.


ledger_entries.*
	
LedgerPresenter.render
	
Owner-scoped (list_for_user)
	
API /ledger
	
Append-only; no admin override in codebase.


wallets.available_balance
	
WalletPresenter.render
	
Owner-scoped
	
API /wallets
	
Faucet credits visible immediately.
Unresolved Edges & Observations
Order Reference Resolver Scope: OrderReferenceResolver.reference_context_for hardcodes channel: :desk_order, which forces ReferenceDirectory.reference_scope_for to return :desk_book. This causes AccountReferenceBook.lookup to call resolve_order_reference (global search by client_order_id) instead of find_reference_for_account (user-scoped). The API route /api/orders/lookup/:reference_code passes the authenticated user but the resolver ignores the user scope due to this hardcoded channel.
RFQ Board Authentication: GET /api/rfq/board calls authenticated_session_and_user but does not enforce a specific capability or ownership check before returning board data. It requires any valid session.
Conditional Trigger Service Actor: bin/matching-engine runs ConditionalTriggerService.process_from_latest_trades without a user context. It places orders via OrderService.place using order[:user_id] from the conditional record. This is an internal system actor path; no external HTTP entry point exists for this flow.
Market Simulator Actor: bin/market-simulator publishes feed events and triggers conditionals deterministically. It operates outside HTTP but writes to public_feed_events and triggers the same settlement paths as user actions.
Broker Report Enrichment: BrokerReportService.execution_enrichment_snapshot performs a secondary query on trade_receipts to find booking_marker. This marker originates from orders.client_reference via MatchingService.create_receipts. The link is indirect: order -> receipt -> broker_report.
Public Feed Payload Expansion: ActivationContextDTO.deep_event_attributes recursively flattens nested hashes in signal_context. While PublicFeedRepository validates payload depth/keys at write time, the presenter re-expands them. If signal_context contains unexpected nesting from conditional orders, it could surface fields not explicitly whitelisted in EVENT_PAYLOAD_FIELDS (though normalize_payload at write time should prevent this).
Static Asset Serving: UIStatic middleware serves files from public/ or frontend/dist/. Path traversal is mitigated by start_with?(root_prefix) check. No dynamic content injection observed in static handler.
Missing Admin/Auditor Endpoints: AccountProfiles defines auditor and system_bot roles with empty capabilities. No API routes exist for these profiles despite schema support.
Faucet Idempotency Scope: FaucetService.claim uses ledger_idempotency_key combining user-supplied key + asset. Global uniqueness is enforced via DB unique constraint on (user_id, idempotency_key). Replay protection is per-user, not global.
Trade Detail Conditional Auth: GET /api/trades/:id checks bearer_token presence to decide between public vs participant view. If token is present but invalid/expired, authenticated_session_and_user halts with 401 rather than falling back to public view.
RECEIVED-9ce4e0132b48
