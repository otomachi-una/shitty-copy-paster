{
"F1": {
"status": "confirmed",
"title": "IDOR in Order Lookup via Reference Code",
"file": "lib/voltax/services/order_reference_resolver.rb",
"evidence": "reference_context_for hardcodes channel: :desk_order. ReferenceDirectory#reference_scope_for returns :desk_book for this channel. AccountReferenceBook#lookup calls order_repository.resolve_order_reference without user_id when scope is :desk_book. OrderRepository#resolve_order_reference queries orders.where(client_order_id: ...).order(:id).first globally. The route /api/orders/lookup/:reference_code exposes this to any authenticated user with orders capability.",
"preconditions": "Authenticated user with orders capability (spot, liquidity, partner).",
"impact": "Information disclosure of any order's details (including limit price, quantity, status, execution memo) by guessing or knowing its client_order_id."
},
"F2": {
"status": "confirmed",
"title": "Information Leak of Counterparty's Client Reference in Trade Detail",
"file": "lib/voltax/services/order_service.rb",
"evidence": "participant_trade_detail fetches booking_rows = trade_receipt_repository.bookings_for_execution(trade_id: trade_id) which returns ALL receipts for the trade. TradePresenter.render_participant_detail merges venue_allocation: allocation_notice(booking_row) for the counterparty's receipt. VenueAllocationDTO.notice includes desk_ref: receipt[:client_reference], leaking the counterparty's private booking reference.",
"preconditions": "Authenticated user who participated in a trade.",
"impact": "Leaks the counterparty's private client_reference (booking reference) to the user."
}
}
RECEIVED-ed1808af156e
