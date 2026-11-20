{
"F1": {
"status": "confirmed",
"title": "IDOR in order reference lookup",
"file": "lib/voltax/reference_directory.rb",
"evidence": "GET /api/orders/lookup/:reference_code flows through OrderReferenceResolver with channel :desk_order, forcing the global desk_book branch. The repository lookup filters only by client_order_id and drops account ownership before serializing the order.",
"preconditions": "Authenticated account with the orders capability and a known or guessable client_order_id belonging to another account.",
"impact": "Read cross-account order data, including price, quantity, status, and execution memo."
},
"F2": {
"status": "confirmed",
"title": "Counterparty booking reference leak in trade detail",
"file": "lib/voltax/presenters/trade_presenter.rb",
"evidence": "A participant-scoped trade detail fetches every booking for the trade, selects the other participant row, and emits its client_reference as desk_ref without an audience check.",
"preconditions": "Authenticated participant in a trade with a counterparty booking reference.",
"impact": "Read the counterparty’s private booking reference through trade detail."
},
"F3": {
"status": "confirmed",
"title": "Counterparty booking references leak in broker reports",
"file": "lib/voltax/services/broker_report_service.rb",
"evidence": "Broker report enrichment reads both receipts for a trade and places the other participant's booking reference in the report booking_marker.",
"preconditions": "Access to an eligible broker trade report containing a trade with two participant receipts.",
"impact": "Read client_reference values from both sides of reported trades."
},
"F4": {
"status": "confirmed",
"title": "Conditional-order strategy context enters the public feed",
"file": "lib/voltax/dtos/activation_context_dto.rb",
"evidence": "ActivationContextDTO includes the conditional order signal_context in activation_context, which is persisted and expanded into public feed event attributes without redaction.",
"preconditions": "A user creates a conditional order with signal_context and the order is triggered; reading the public feed requires no authentication.",
"impact": "Disclose private strategy notes to unauthenticated feed readers."
},
"F5": {
"status": "confirmed",
"title": "RFQ delivery terms exposed to all liquidity providers",
"file": "lib/voltax/services/rfq_service.rb",
"evidence": "GET /api/rfq/:rfq_id/workup checks only for the rfq_quote capability and returns the RFQ's delivery_terms in the workup_terms field via QuoteWorkupAssembler, without verifying that the requester is the RFQ owner or has submitted a quote.",
"preconditions": "Authenticated account with rfq_quote capability (e.g., liquidity profile) and knowledge of an existing RFQ ID.",
"impact": "Disclosure of private OTC settlement instructions or delivery terms to any market maker."
}
}
RECEIVED-63cd7c2a3d6c
