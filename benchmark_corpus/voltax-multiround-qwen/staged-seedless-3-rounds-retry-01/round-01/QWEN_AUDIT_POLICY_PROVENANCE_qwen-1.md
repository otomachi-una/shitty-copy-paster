Policy & Object-Provenance Pass
1. Policy-Metadata Lifecycles (producer → persistence → consumer → enforcement verdict)
Metadata
	
Producer/Assignment
	
Persisted As
	
Consumers & Branch Behavior
	
Verdict


account_profile
	
POST /api/auth/register → UserRepository.create (public profiles only)
	
users.account_profile
	
AccountProfiles.can? gates orders/broker/rfq-quote routes; BrokerAttributionRepository.validate_trader! re-checks public profile
	
Enforced for most routes; not consumed on RFQ create/accept and conditional create (see C4/C5)


capability orders
	
AccountProfiles::CAPABILITIES_BY_PROFILE
	
derived per session user
	
Checked in all /api/orders* HTTP routes; not present in OrderService#place itself
	
Retained but bypassed on deferred placement path (C4)


capability rfq_board
	
same
	
derived
	
No consumer anywhere in router or services; GET /api/rfq/board only requires any active session
	
Assigned but ignored (low impact; board fields are near-public)


capability broker_attribution
	
same
	
derived
	
Not checked in route; equivalently enforced by validate_trader! profile check in repository
	
Indirectly enforced; capability flag itself ignored


client_order_id scope
	
OrderService.place / RFQ anchors
	
orders.client_order_id (unique per user)
	
find_reference_for_account (user-scoped) vs resolve_order_reference (global)
	
Global branch reachable for all users (C1)


channel (reference scope)
	
OrderReferenceResolver.reference_context_for
	
in-memory only
	
ReferenceDirectory.reference_scope_for branches on it
	
Misassigned: hardcoded :desk_order for every caller; :account scope unreachable


delivery_terms
	
POST /api/rfq
	
rfqs.delivery_terms
	
Workup (QuoteWorkupAssembler#term_sheet → workup_terms); copied to owner-receipt client_reference in RFQSettlementService.create_receipts
	
Retained and re-audiented: later surfaces as desk_ref to counterparty (C3); maker already saw it via workup, so RFQ-case audience consistent


signal_context
	
POST /api/conditional-orders (≤512, control-char/reserved-marker filtered)
	
conditional_orders.signal_context
	
Owner DTO; at trigger embedded in feed payload activation_context, expanded by ActivationContextDTO.deep_event_attributes
	
Intentional public publication at trigger; write-time allowlist + ensure_public_event_text! hold


EVENT_PAYLOAD_FIELDS
	
duplicated constants in repository and presenter
	
payload_json
	
Write: unknown keys dropped; Read: second allowlist filter
	
Both copies consistent; no separate unfiltered consumer found


feed reference_type/reference_id
	
PublicFeedService publishers
	
stored
	
Not emitted by PublicEventDTO.render
	
Stored internally only — safe


broker_attributions.status/revoked_at/attributed_at
	
attribution repo
	
persisted
	
BrokerReportService base dataset filters created_at >= attributed_at and (revoked_at IS NULL OR trade < revoked_at)
	
Revocation honored in aggregation


sessions.revoked_at
	
SessionRepository.revoke
	
persisted
	
find_by_token filters revoked_at: nil
	
Flag honored by reader but revoke has no caller (no logout route) — see unresolved


expires_at (conditional)
	
create route
	
persisted
	
Filtered in pending_trigger_candidates; no transition to expired, publish_conditional_expiry never called
	
Partially enforced (see unresolved)


expires_at (RFQ)
	
create route
	
persisted
	
Checked in quote create/accept; not filtered in list_board (stale rows displayed, writes still gated)
	
Write-gate holds; display hygiene gap
2. Token/Session Verification
Accepted algorithms (complete): one bearer scheme. Token = SecureRandom.urlsafe_base64(32); verifier recomputes OpenSSL::HMAC.hexdigest("SHA256", credential_key_base, token) and matches DB digest. No JWT, no alg negotiation, no "none", no asymmetric variant.
Key: VOLTAX_SECRET_KEY_BASE (≥32 chars, placeholder patterns rejected; test default only in test env). No public verification key exists; symmetric material not derivable from any public output. /health, /ready, presenters never emit it (accessed only via instance_variable_get in session repo construction).
Checks: expires_at > now, revoked_at IS NULL, user status == "active" re-checked on every authenticated request. GET /api/trades/:id: invalid token → 401 (no silent fallback to public view); valid token without receipt → 404 (stricter than public).
Password: bcrypt cost 12 (4 test), min length 12; hash never serialized.
3. Aggregate/Batch Provenance
Broker report rows: primary row owner = attributed trader; join scoping correct. Enrichment: execution_enrichment_snapshot queries trade_receipts.where(trade_id: trade_ids) with no user/attribution filter; venue_booking_context_for takes first non-empty client_reference across both legs (insertion order: buyer receipt first in MatchingService.create_receipts). Marker provenance is order-dependent, not attribution-dependent → related-party substitution (C2). Only applied when origin == "orderbook" (RFQ trades excluded by client_order_id prefix check). Monthly rows carry no marker.
Trade detail: primary receipt scoped (find_by_trade_for_user); sibling lookup bookings_for_execution(trade_id:) unscoped; presenter selects row[:id] != receipt[:id] and serializes its client_reference (C3).
Market data/user trades: joins on user_id only; no secondary party records.
Workers: matching-engine/market-simulator write feeds/triggers with system identity; trigger_order uses order[:user_id] (owner preserved through composed flow); feed reference_id values are non-sensitive ids.
4. Candidate Findings
#
	
Route/Path
	
Violated Invariant
	
Exact Failing Branch/Argument


C1
	
GET /api/orders/lookup/:reference_code
	
Reference resolution must be scoped to requesting account
	
OrderReferenceResolver#reference_context_for hardcodes channel: :desk_order → reference_scope_for returns :desk_book → AccountReferenceBook#lookup takes global branch order_repository.resolve_order_reference(reference_code:) (orders.where(client_order_id:), no user_id). Any orders-capable user reads any user's order incl. private execution_memo


C2
	
GET /api/broker/reports/trades
	
Enrichment row must be owned by the attributed trader
	
BrokerReportService#execution_enrichment_snapshot: database[:trade_receipts].where(trade_id: trade_ids) (no owner filter); venue_booking_context_for `.find {


C3
	
GET /api/trades/:id (authed)
	
Access to own receipt does not authorize sibling receipt fields
	
TradeReceiptRepository#bookings_for_execution(trade_id:) unscoped; TradePresenter#render_participant_detail picks `booking_rows.find {


C4
	
POST /api/conditional-orders + worker trigger
	
Capability policy must hold on every order-placement path
	
Route lacks AccountProfiles.can?(user, "orders"); on trigger ConditionalTriggerService#trigger_order calls OrderService#place(user_id: order[:user_id]) which contains no capability check (enforcement exists only at the direct HTTP route). Profiles without orders (auditor/system_bot, if present) obtain placed orders; also POST /api/conditional-orders itself has no capability gate


C5
	
POST /api/rfq, POST /api/rfq/:id/accept, POST /api/rfq/:id/simulate-settlement
	
Capability model must be consistent across object types
	
These routes enforce only session auth (+ owner equality for accept/simulate); no capability check, unlike /api/orders. rfq_board capability assigned but never consumed. Internal profiles (auditor/system_bot, if pre-seeded) could create and settle RFQs; faucet likewise ungated by profile


C6
	
POST /api/rfq board/workup
	
Board row visibility limited to open-and-relevant RFQs (minor)
	
list_board does not filter expires_at; workup returns delivery_terms (workup_terms) for expired/cancelled RFQs since quote_workup_for only checks existence + capability
5. Reviewed Flows Without Candidates
Session create/verify; HMAC digest storage; bcrypt handling; config/secret validation and placeholder rejection.
Owner-scoped reads: wallets, ledger, orders list/detail, conditional list/detail, RFQ owner detail, receipts — all filter by session user_id.
RFQ quote create/accept settlement: owner equality enforced twice (service + settlement), maker capability re-validated at settlement, expiry validated, self-quoting blocked, wallet availability verified before debits; anchor order ids preserve buy/sell/maker/taker roles consistently.
Matching: self-trade skipped (incoming[:user_id] == resting[:user_id]), locked-wallet sufficiency asserted, ledger append-only (update/delete raise).
Public feed: dual allowlist (write + read), depth/byte/string caps, reserved-marker rejection, idempotency dedup; feed internal references never emitted.
Broker campaigns/attribution writes: reserved-key blocklist enforced before repo call; trader_user is the session principal (payload cannot substitute identity); status transition table enforced.
Attribution-window filtering in reports (attributed_at / revoked_at) — revocation metadata actually consumed.
Static assets, health/ready, worker stdout logs (no sensitive fields).
6. Unresolved Leads
SessionRepository#revoke is dead code — no logout/revocation endpoint; sessions valid until 24h TTL.
ConditionalOrderRepository supports expired status and publish_conditional_expiry exists, but no producer transitions or emits it; expired conditionals stay pending in owner views.
VOLTAX_PUBLIC_BASE_URL is loaded/validated but no consumer found in supplied source.
PublicFeedRepository#list_feed_events and find_market_snapshot have no route/worker callers (dead read paths).
Internal profiles (auditor, system_bot) cannot be registered via API; C4/C5 exploitability depends on pre-seeded accounts outside supplied source.
No rate limiting on /api/auth/login (credential guessing); not elevated to candidate without brute-force evidence in scope.
Sequel nested transaction semantics in trigger_order (place inside process_market transaction) assumed single-transaction; no savepoint configuration observed — behavior under partial failure not fully provable from supplied code.
RECEIVED-074ebeb3d24f
