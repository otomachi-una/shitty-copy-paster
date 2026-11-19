#!/usr/bin/env python3
"""VoltaX ForcAD-compatible checker skeleton."""

from __future__ import annotations

import hashlib
import os
import json
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from typing import Sequence

from checker_lib import (
    ApiClient,
    CheckerError,
    Corrupt,
    Mumble,
    ServiceDown,
    decode_state,
    encode_state,
    normalize_base_url,
    register_account,
    validate_public_attack_data,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows direct runs fall back to no lock.
    fcntl = None


_HOST_PLACE_LOCKS: dict[str, threading.Lock] = {}
_HOST_PLACE_LOCKS_GUARD = threading.Lock()


EXIT_CODES = {
    "OK": 101,
    "CORRUPT": 102,
    "MUMBLE": 103,
    "DOWN": 104,
    "CHECKER_ERROR": 110,
}


@dataclass(frozen=True)
class CheckerResult:
    status: str
    public_message: str = ""
    private_message: str = ""

    def __iter__(self):
        yield self.status
        yield self.public_message

    def __eq__(self, other: object) -> bool:
        if isinstance(other, tuple):
            return (self.status, self.public_message) == other
        return super().__eq__(other)


class CheckerProtocolError(CheckerError):
    status = "CHECKER_ERROR"


SMOKE_PRIVATE_KEYS = {
    "password",
    "token",
    "token_digest",
    "session_id",
    "user_id",
    "owner_user_id",
    "broker_user_id",
    "trader_user_id",
    "idempotency_key",
    "reference_id",
    "execution_memo",
    "client_reference",
    "client_reference",
    "booking_ref",
    "booking_marker",
    "desk_ref",
    "delivery_terms",
    "settlement_marker",
    "workup_terms",
    "signal_context",
    "wallet_id",
    "ledger_id",
    "database_url",
    "internal_path",
    "stack",
    "backtrace",
    "raw",
    "orm",
}

SMOKE_POLICY_ENV = "VOLTAX_CHECKER_POLICY"
SMOKE_EXPECT_VULNERABLE_ENV = "VOLTAX_EXPECT_VULNERABLE_BUILD"
TRUE_ENV_VALUES = {"1", "true", "yes", "on"}
EXTERNAL_SMOKE_POLICIES = {
    "competition": "competition_vulnerable",
    "competition-vulnerable": "competition_vulnerable",
    "competition_vulnerable": "competition_vulnerable",
    "strict": "strict",
    "strict-fix-validation": "strict",
    "strict_fix_validation": "strict",
}


def check(host: str, client: ApiClient | None = None) -> CheckerResult:
    client = client or ApiClient(host)
    run_smoke(client, policy=smoke_policy_from_environment())
    return CheckerResult("OK", "service smoke passed")


def havoc(host: str, client: ApiClient | None = None) -> CheckerResult:
    client = client or ApiClient(host)
    run_smoke(client, policy=smoke_policy_from_environment())
    return CheckerResult("OK", "havoc smoke passed")


def put(
    host: str,
    incoming_flag_id: str,
    flag: str,
    place: str,
    client: ApiClient | None = None,
    credential: str | None = None,
) -> CheckerResult:
    if not incoming_flag_id:
        raise CheckerProtocolError("incoming flag_id missing")
    place_number = parse_place(place)
    if place_number not in {1, 2, 3, 4}:
        raise Corrupt("unsupported place")

    client = client or ApiClient(host)
    credential = credential or state_credential()
    owner = setup_owner(client, place_number)

    if place_number == 1:
        public, ids = put_place_1(client, owner["token"], flag, owner["nonce"])
    elif place_number == 2:
        public, ids = put_place_2(client, owner, flag)
    elif place_number == 3:
        public, ids = put_place_3(client, owner["token"], flag, owner["nonce"])
    else:
        public, ids = put_place_4(client, owner["token"], flag, owner["nonce"])

    state = {
        "place": place_number,
        "host": normalize_base_url(host),
        "username": owner["username"],
        "password": owner["password"],
        "account_profile": "spot",
        "ids": ids,
        "public": public,
        "nonce": owner["nonce"],
    }
    flag_id = encode_state(state, credential)
    validate_public_attack_data(public, expected_flag=flag)

    public_message = json.dumps(public, sort_keys=True, separators=(",", ":"))
    return CheckerResult("OK", public_message, flag_id)


def get(
    host: str,
    flag_id: str,
    flag: str,
    place: str,
    client: ApiClient | None = None,
    credential: str | None = None,
) -> CheckerResult:
    place_number = parse_place(place)
    if place_number not in {1, 2, 3, 4}:
        raise Corrupt("unsupported place")

    client = client or ApiClient(host)
    credential = credential or state_credential()
    state = decode_state(flag_id, credential)
    validate_state_for_request(state, host=host, place=place_number)
    token = client.token_from(client.login(str(state["username"]), str(state["password"])))

    if place_number == 1:
        observed = read_place_1(client, token, state)
    elif place_number == 2:
        observed = read_place_2(client, token, state)
    elif place_number == 3:
        observed = read_place_3(client, token, state)
    else:
        observed = read_place_4(client, token, state)

    if observed != flag:
        raise Corrupt("flag mismatch")

    return CheckerResult("OK", "flag found")


def dispatch(argv: Sequence[str]) -> CheckerResult:
    if len(argv) < 2:
        raise CheckerProtocolError("usage: checker.py <check|havoc|put|get> ...")

    action = argv[1].lower()
    if action == "check" and len(argv) == 3:
        return check(argv[2])
    if action == "havoc" and len(argv) == 3:
        return havoc(argv[2])
    if action == "put" and len(argv) == 6:
        return put(argv[2], argv[3], argv[4], argv[5])
    if action == "get" and len(argv) == 6:
        return get(argv[2], argv[3], argv[4], argv[5])

    raise CheckerProtocolError("invalid checker arguments")


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(argv or sys.argv)
    try:
        result = dispatch(argv)
    except ServiceDown as error:
        result = CheckerResult(error.status, safe_message(str(error)))
    except (Mumble, Corrupt) as error:
        result = CheckerResult(error.status, safe_message(str(error)))
    except CheckerError as error:
        result = CheckerResult(error.status, safe_message(str(error)))
    except Exception:
        result = CheckerResult("CHECKER_ERROR", "internal checker error")

    if result.public_message:
        print(safe_message(result.public_message))
    if result.private_message:
        print(safe_message(result.private_message), file=sys.stderr)
    return EXIT_CODES.get(result.status, EXIT_CODES["CHECKER_ERROR"])


def safe_message(message: str) -> str:
    credential = os.environ.get("VOLTAX_CHECKER_SECRET")
    cleaned = str(message).replace("\n", " ").replace("\r", " ")
    if credential:
        cleaned = cleaned.replace(credential, "[redacted]")
    return cleaned[:4096]


def parse_place(place: str) -> int:
    try:
        place_number = int(place)
    except ValueError as error:
        raise Corrupt("invalid place") from error
    if place_number < 1 or place_number > 4:
        raise Corrupt("invalid place")
    return place_number


def state_credential() -> str:
    credential = os.environ.get("VOLTAX_CHECKER_SECRET", "")
    if not credential:
        raise CheckerProtocolError("checker state credential missing")
    return credential


def setup_owner(client: ApiClient, place: int) -> Mapping[str, str]:
    return setup_user(client, place, "owner")


def setup_user(client: ApiClient, place: int, label: str, account_profile: str = "spot", fund: bool = True) -> Mapping[str, str]:
    account = register_account(client, account_profile, label=label, place=place, fund=fund)
    return {
        "username": str(account["username"]),
        "password": str(account["password"]),
        "token": str(account["token"]),
        "nonce": str(account["nonce"]),
        "account_profile": str(account["account_profile"]),
    }


def smoke_policy_from_environment() -> str:
    explicit = os.environ.get(SMOKE_POLICY_ENV, "").strip().lower()
    legacy_value = os.environ.get(SMOKE_EXPECT_VULNERABLE_ENV, "")
    legacy_competition = legacy_value.strip().lower() in TRUE_ENV_VALUES

    if explicit:
        if explicit not in EXTERNAL_SMOKE_POLICIES:
            raise CheckerError("invalid checker policy")
        selected = EXTERNAL_SMOKE_POLICIES[explicit]
        if selected == "strict" and legacy_competition:
            raise CheckerError("conflicting checker policy")
        return selected

    return "competition_vulnerable" if legacy_competition else "strict"


def run_smoke(client: ApiClient, *, policy: str = "strict") -> None:
    market_symbol = smoke_service_surface(client)
    trader = smoke_identity_and_finance(client)
    broker = smoke_broker_campaigns(client, trader)
    smoke_order_lifecycle(client, trader, market_symbol)
    try:
        smoke_matching_and_receipt(client, trader, market_symbol, policy=policy)
    except Mumble as error:
        if str(error) != "owner receipt not found":
            raise
    smoke_broker_reports(client, broker, policy=policy)
    smoke_rfq_flow(client, market_symbol, policy=policy)
    smoke_conditional_flow(client, trader, market_symbol, policy=policy)
    smoke_public_feed(client, market_symbol, policy=policy)


def smoke_service_surface(client: ApiClient) -> str:
    health = client.get("/health")
    ready = client.get("/ready")
    markets = client.get("/api/markets")

    if health.get("status") != "ok":
        raise Mumble("health endpoint returned unexpected status")
    if ready.get("status") != "ready":
        raise Mumble("ready endpoint returned unexpected status")

    market_rows = list_field(markets, "markets")
    for market in market_rows:
        if isinstance(market, Mapping) and market.get("symbol") == "VOLT-USDT":
            return "VOLT-USDT"
    raise Mumble("VOLT-USDT market missing")


def smoke_identity_and_finance(client: ApiClient) -> Mapping[str, str]:
    trader = setup_user(client, 8, "chk")
    logged_in_token = client.token_from(client.login(trader["username"], trader["password"]))
    me = response_object(client.me(logged_in_token), "user")
    if me.get("username") != trader["username"]:
        raise Mumble("auth me username mismatch")

    list_field(client.wallets(logged_in_token), "wallets")
    list_field(client.ledger(logged_in_token), "ledger_entries")
    return {**trader, "token": logged_in_token}


def smoke_order_lifecycle(client: ApiClient, trader: Mapping[str, str], market_symbol: str) -> None:
    reference_code = f"smoke-cancel-{trader['nonce']}"
    response = client.create_order(
        trader["token"],
        market_symbol=market_symbol,
        side="buy",
        limit_price="99.0",
        quantity="1.0000",
        reference_code=reference_code,
        execution_memo="smoke order note",
    )
    order = response_object(response, "order")
    order_id = required_value(order, "id")
    owner_order = response_object(client.get_order(trader["token"], order_id), "order")
    if reference_value(owner_order) != reference_code:
        raise Mumble("owner order lookup mismatch")
    client_order_lookup = response_object(client.get_order_by_reference(trader["token"], reference_code), "order")
    if str(client_order_lookup.get("id")) != str(order_id) or reference_value(client_order_lookup) != reference_code:
        raise Mumble("owner order reference lookup mismatch")

    list_field(client.list_orders(trader["token"]), "orders")
    status = owner_order.get("status")
    if status not in {"open", "partially_filled", "filled", "cancelled"}:
        raise Mumble("owner order returned unexpected status")
    if status in {"open", "partially_filled"}:
        cancelled = response_object(client.cancel_order(trader["token"], order_id), "order")
        if cancelled.get("status") not in {"cancelled", "partially_filled", "filled"}:
            raise Mumble("order cancellation returned unexpected status")


def smoke_matching_and_receipt(client: ApiClient, trader: Mapping[str, str], market_symbol: str, *, policy: str = "strict") -> None:
    counterparty = setup_user(client, 8, "mat")
    price = isolated_buy_price(client, market_symbol, trader["nonce"])
    quantity = "1.0000"
    receipt_marker = f"smoke-receipt-{trader['nonce']}"
    owner_reference_code = f"smoke-buy-{trader['nonce']}"
    owner_order = response_object(
        client.create_order(
            trader["token"],
            market_symbol=market_symbol,
            side="buy",
            limit_price=price,
            quantity=quantity,
            reference_code=owner_reference_code,
            execution_memo="smoke order note",
            booking_ref=receipt_marker,
        ),
        "order",
    )
    owner_order_id = required_value(owner_order, "id")
    try:
        trade_id, receipt = find_owner_receipt_for_flag(
            client,
            token=trader["token"],
            market_symbol=market_symbol,
            price=normalize_decimal_string(owner_order.get("limit_price"), "10.00000000"),
            quantity=normalize_decimal_string(owner_order.get("original_quantity"), "1.00000000"),
            flag=receipt_marker,
            owner_order_id=owner_order_id,
            owner_reference_code=owner_reference_code,
        )
        smoke_trade_detail_surface(
            client,
            token=trader["token"],
            trade_id=trade_id,
            owner_reference_code=owner_reference_code,
            owner_receipt=receipt,
            policy=policy,
        )
        return
    except Mumble:
        pass

    client.create_order(
        counterparty["token"],
        market_symbol=market_symbol,
        side="sell",
        limit_price=price,
        quantity=quantity,
        reference_code=f"smoke-sell-{trader['nonce']}",
        execution_memo="smoke counterparty note",
    )
    trade_id, receipt = find_owner_receipt_for_flag(
        client,
        token=trader["token"],
        market_symbol=market_symbol,
        price=normalize_decimal_string(owner_order.get("limit_price"), "10.00000000"),
        quantity=normalize_decimal_string(owner_order.get("original_quantity"), "1.00000000"),
        flag=receipt_marker,
        owner_order_id=owner_order_id,
        owner_reference_code=owner_reference_code,
    )
    smoke_trade_detail_surface(
        client,
        token=trader["token"],
        trade_id=trade_id,
        owner_reference_code=owner_reference_code,
        owner_receipt=receipt,
        policy=policy,
    )


def smoke_trade_detail_surface(
    client: ApiClient,
    *,
    token: str,
    trade_id: Any,
    owner_reference_code: str,
    owner_receipt: Mapping[str, Any],
    policy: str,
) -> None:
    detail = response_object(client.get_trade(token, trade_id), "trade")
    if str(detail.get("id")) != str(trade_id):
        raise Mumble("trade detail id mismatch")
    account_booking = detail.get("account_booking")
    if not isinstance(account_booking, Mapping):
        raise Mumble("trade detail account booking missing")
    if str(account_booking.get("trade_id")) != str(trade_id):
        raise Mumble("trade detail account booking trade mismatch")
    if reference_value(account_booking) != owner_reference_code:
        raise Mumble("trade detail booking reference mismatch")
    if account_booking.get("booking_ref") != owner_receipt.get("booking_ref"):
        raise Mumble("trade detail owner booking reference mismatch")

    venue_allocation = detail.get("venue_allocation")
    if venue_allocation is None:
        return
    if not isinstance(venue_allocation, Mapping):
        raise Mumble("trade detail venue allocation malformed")
    if policy != "competition_vulnerable":
        raise Mumble("private field sampleed in smoke response")
    ensure_no_private_fields(
        venue_allocation,
        allowed_keys=approved_smoke_private_keys(policy, "trade_venue_allocation"),
    )


def move_market_to_trigger_price(client: ApiClient, trader: Mapping[str, str], market_symbol: str) -> None:
    counterparty = setup_user(client, 8, "cnd")
    nonce = trader["nonce"]
    for attempt in range(3):
        client.create_order(
            counterparty["token"],
            market_symbol=market_symbol,
            side="sell",
            limit_price="100.0",
            quantity="1.0000",
            reference_code=f"smoke-cond-sell-{nonce}-{attempt}",
            execution_memo="smoke trigger maker",
        )
        client.create_order(
            trader["token"],
            market_symbol=market_symbol,
            side="buy",
            limit_price="100.0",
            quantity="1.0000",
            reference_code=f"smoke-cond-buy-{nonce}-{attempt}",
            execution_memo="smoke trigger taker",
        )
        time.sleep(0.2)


def wait_for_conditional_trigger_event(
    client: ApiClient,
    *,
    market_symbol: str,
    since_sequence: int,
    conditional_order_id: Any,
    policy: str,
) -> None:
    saw_fresh_conditional_event = False
    for _attempt in range(60):
        feed = client.public_feed(after_sequence=since_sequence, limit=100, market_symbol=market_symbol)
        events = list_field(feed, "events")
        ensure_no_private_fields(feed, allowed_keys=approved_smoke_private_keys(policy, "public_feed"))
        for event in events:
            if not isinstance(event, Mapping):
                continue
            if event.get("event_type") != "market_signal_activated":
                continue
            try:
                event_sequence = int(str(event.get("sequence")), 10)
            except (TypeError, ValueError):
                raise Mumble("conditional feed event sequence invalid")
            if event_sequence <= since_sequence:
                continue
            payload = event.get("payload")
            if not isinstance(payload, Mapping):
                raise Mumble("conditional feed event payload missing")
            saw_fresh_conditional_event = True
            if str(payload.get("conditional_order_id")) != str(conditional_order_id):
                continue
            return
        time.sleep(0.25)
    if saw_fresh_conditional_event:
        return
    raise Mumble("conditional trigger feed event missing")


def smoke_rfq_flow(client: ApiClient, market_symbol: str, *, policy: str = "strict") -> None:
    owner = setup_user(client, 8, "rfq")
    maker = setup_user(client, 8, "mmk", account_profile="liquidity")
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    rfq = response_object(
        client.create_rfq(
            owner["token"],
            market_symbol=market_symbol,
            side="buy",
            quantity="1.0000",
            target_price="10.00",
            delivery_terms="smoke delivery terms",
            expires_at=expires_at,
        ),
        "rfq",
    )
    rfq_id = required_value(rfq, "id")
    ensure_no_private_fields(client.rfq_board(maker["token"]))
    workup_response = client.rfq_workup(maker["token"], rfq_id)
    workup = response_object(workup_response, "rfq")
    if str(workup.get("id")) != str(rfq_id):
        raise Mumble("RFQ workup id mismatch")
    if workup.get("eligible_to_quote") is False:
        raise Mumble("RFQ workup unexpectedly not quoteable")
    ensure_no_private_fields(
        workup_response,
        allowed_keys=approved_smoke_private_keys(policy, "rfq_workup"),
    )
    quote = response_object(client.quote_rfq(maker["token"], rfq_id, price="10.00", quantity="1.0000"), "quote")
    quote_id = required_value(quote, "id")
    response_object(client.accept_rfq(owner["token"], rfq_id, quote_id=quote_id), "rfq")


def smoke_broker_campaigns(client: ApiClient, trader: Mapping[str, str]) -> Mapping[str, str]:
    broker = setup_user(client, 8, "brk", account_profile="partner", fund=False)
    campaign_code = f"smoke-{broker['nonce']}"
    campaign = response_object(
        client.create_broker_campaign(broker["token"], campaign_code=campaign_code, name="Smoke Campaign"),
        "campaign",
    )
    if campaign.get("campaign_code") != campaign_code:
        raise Mumble("broker campaign code mismatch")
    list_field(client.list_broker_campaigns(broker["token"]), "campaigns")
    response_object(
        client.create_broker_attribution(
            trader["token"],
            campaign_code=campaign_code,
            user_reference=f"smoke-ref-{trader['nonce']}",
        ),
        "attribution",
    )
    return {**broker, "campaign_code": campaign_code}


def smoke_broker_reports(client: ApiClient, broker: Mapping[str, str], *, policy: str = "strict") -> None:
    trades = client.broker_report_trades(broker["token"])
    monthly = client.broker_report_monthly(broker["token"])
    list_field(trades, "trades")
    list_field(monthly, "monthly")
    ensure_no_private_fields(trades, allowed_keys=approved_smoke_private_keys(policy, "broker_report_trades"))
    ensure_no_private_fields(monthly)


def smoke_conditional_flow(client: ApiClient, trader: Mapping[str, str], market_symbol: str, *, policy: str = "strict") -> None:
    since_sequence = current_public_feed_tail_sequence(client, market_symbol)
    response = client.create_conditional_order(
        trader["token"],
        market_symbol=market_symbol,
        side="buy",
        trigger_type="last_trade_price_at_or_above",
        trigger_price="1.0",
        limit_price="1.0",
        quantity="1.0000",
        reference_code=f"smoke-cond-{trader['nonce']}",
        signal_context="smoke signal context",
    )
    order = response_object(response, "conditional_order")
    conditional_order_id = required_value(order, "id")
    response_object(client.get_conditional_order(trader["token"], conditional_order_id), "conditional_order")
    list_field(client.list_conditional_orders(trader["token"]), "conditional_orders")
    feed = client.public_feed(after_sequence=since_sequence, limit=10, market_symbol=market_symbol)
    list_field(feed, "events")
    ensure_no_private_fields(feed, allowed_keys=approved_smoke_private_keys(policy, "public_feed"))


def smoke_public_feed(client: ApiClient, market_symbol: str, *, policy: str = "strict") -> None:
    client.market_orderbook(market_symbol)
    trades = client.market_trades(market_symbol)
    list_field(trades, "trades")
    feed = client.public_feed(after_sequence=0, limit=1, market_symbol=market_symbol)
    list_field(feed, "events")
    ensure_no_private_fields(feed, allowed_keys=approved_smoke_private_keys(policy, "public_feed"))


def put_place_1(client: ApiClient, token: str, flag: str, nonce: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    market_symbol = "VOLT-USDT"
    reference_code = f"p1-{nonce}"
    side = "buy"
    limit_price = "1.00"
    quantity = "1.0000"
    response = client.create_order(
        token,
        market_symbol=market_symbol,
        side=side,
        limit_price=limit_price,
        quantity=quantity,
        reference_code=reference_code,
        execution_memo=flag,
    )
    order = response_object(response, "order")
    order_id = required_value(order, "id")
    public = {
        "service": "voltax",
        "place": 1,
        "store": "order_note",
        "market": market_symbol,
        "order_ref": reference_code,
        "order_id": str(order_id),
        "side": side,
        "limit_price": normalize_decimal_string(order.get("limit_price"), limit_price),
        "quantity": normalize_decimal_string(order.get("original_quantity"), "1.00000000"),
    }
    return public, {"order_id": order_id, "order_ref": reference_code}


def put_place_2(client: ApiClient, owner: Mapping[str, str], flag: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    with host_place_lock(client, "place2"):
        return put_place_2_locked(client, owner, flag)


def put_place_2_locked(client: ApiClient, owner: Mapping[str, str], flag: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    market_symbol = "VOLT-USDT"
    owner_quantity = "2.0000"
    attack_quantity = "1.00000000"
    last_error: Mumble | None = None
    price_plans = place_2_execution_plans(client, market_symbol, owner["nonce"])

    for attempt, (price, setup_fill_quantity) in enumerate(price_plans):
        counterparty = setup_user(client, 2, f"cpty{attempt}")
        counterparty_reference_code = f"p2c-{owner['nonce']}-{attempt}"
        owner_reference_code = f"p2-{owner['nonce']}-{attempt}"

        owner_response = client.create_order(
            owner["token"],
            market_symbol=market_symbol,
            side="sell",
            limit_price=price,
            quantity=owner_quantity,
            reference_code=owner_reference_code,
            execution_memo="place-2-order-note-decoy",
            booking_ref=flag,
        )
        owner_order = response_object(owner_response, "order")
        owner_order_id = required_value(owner_order, "id")
        if owner_order.get("execution_memo") == flag:
            raise Mumble("place 2 flag sampleed through owner order note")

        client.create_order(
            counterparty["token"],
            market_symbol=market_symbol,
            side="buy",
            limit_price=price,
            quantity=setup_fill_quantity,
            reference_code=counterparty_reference_code,
            execution_memo="counterparty-reference",
        )

        try:
            trade_id, receipt = find_owner_receipt_for_flag(
                client,
                token=owner["token"],
                market_symbol=market_symbol,
                price=normalize_decimal_string(owner_order.get("limit_price"), "10.00000000"),
                quantity=normalize_decimal_string(owner_order.get("original_quantity"), "1.00000000"),
                flag=flag,
                owner_order_id=owner_order_id,
                owner_reference_code=owner_reference_code,
                wait_seconds=1.0,
            )
        except Mumble as error:
            last_error = error
            continue

        public = {
            "service": "voltax",
            "place": 2,
            "store": "trade_receipt",
            "market": market_symbol,
            "trade_id": trade_id,
            "owner_order_ref": owner_reference_code,
            "price_bucket": price_bucket(owner_order.get("limit_price", price)),
            "side_hint": "sell",
            "quantity": attack_quantity,
        }
        ids = {
            "trade_id": trade_id,
            "receipt_id": receipt.get("id"),
            "owner_order_id": owner_order_id,
            "order_ref": owner_reference_code,
        }
        return public, ids

    raise last_error or Mumble("owner receipt not found")


@contextmanager
def host_place_lock(client: ApiClient, place_name: str):
    lock_id = hashlib.sha256(f"{client.base_url}:{place_name}".encode("utf-8")).hexdigest()[:16]
    with _HOST_PLACE_LOCKS_GUARD:
        thread_lock = _HOST_PLACE_LOCKS.setdefault(lock_id, threading.Lock())

    with thread_lock:
        if fcntl is None:
            yield
            return

        with open(f"/tmp/voltax-checker-{place_name}-{lock_id}.lock", "w", encoding="ascii") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def place_2_candidate_prices(client: ApiClient, market_symbol: str, nonce: str) -> list[str]:
    return [price for price, _quantity in place_2_execution_plans(client, market_symbol, nonce)]


def place_2_execution_plans(client: ApiClient, market_symbol: str, nonce: str) -> list[tuple[str, str]]:
    tick = Decimal("0.1")
    owner_fill_quantity = Decimal("1.0000")
    bids: list[Decimal] = []
    asks: dict[Decimal, Decimal] = {}
    try:
        orderbook_response = client.market_orderbook(market_symbol)
        orderbook = orderbook_response.get("orderbook", orderbook_response)
        bid_rows = orderbook.get("bids")
        if isinstance(bid_rows, list):
            for bid in bid_rows:
                if not isinstance(bid, Mapping):
                    continue
                try:
                    bids.append(Decimal(str(bid.get("price"))))
                except (InvalidOperation, TypeError, ValueError):
                    continue
        ask_rows = orderbook.get("asks")
        if isinstance(ask_rows, list):
            for ask in ask_rows:
                if not isinstance(ask, Mapping):
                    continue
                try:
                    ask_price = Decimal(str(ask.get("price")))
                    ask_quantity = Decimal(str(ask.get("quantity")))
                except (InvalidOperation, TypeError, ValueError):
                    continue
                asks[ask_price] = asks.get(ask_price, Decimal("0")) + ask_quantity
    except Mumble:
        pass

    best_bid = max(bids) if bids else None
    best_ask = min(asks) if asks else None
    floor_price = (best_bid + tick) if best_bid is not None else Decimal("1.0")
    candidate_pool: list[Decimal] = []
    if best_ask is not None and best_ask - floor_price >= tick:
        slots = int(((best_ask - tick - floor_price) / tick).to_integral_value()) + 1
        candidate_pool = [floor_price + (Decimal(slot) * tick) for slot in range(max(1, slots))]
    else:
        start_price = max(floor_price, best_ask or floor_price)
        candidate_pool = [start_price + (Decimal(slot) * tick) for slot in range(16)]

    try:
        offset = int(nonce[:6], 16) % len(candidate_pool)
    except ValueError:
        offset = 0
    rotated = candidate_pool[offset:] + candidate_pool[:offset]
    prices = rotated[:16]
    plans: list[tuple[str, str]] = []
    for price in prices:
        clear_quantity = sum(quantity for ask_price, quantity in asks.items() if ask_price <= price)
        setup_quantity = clear_quantity + owner_fill_quantity
        plans.append((f"{price:.1f}", f"{setup_quantity:.4f}"))
    return plans


def put_place_3(client: ApiClient, token: str, flag: str, nonce: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    market_symbol = "VOLT-USDT"
    side = "buy"
    target_price = "10.00"
    quantity = "1.0000"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    response = client.create_rfq(
        token,
        market_symbol=market_symbol,
        side=side,
        quantity=quantity,
        target_price=target_price,
        delivery_terms=flag,
        expires_at=expires_at,
    )
    rfq = response_object(response, "rfq")
    rfq_id = required_value(rfq, "id")
    public = {
        "service": "voltax",
        "place": 3,
        "store": "rfq",
        "market": market_symbol,
        "rfq_id": rfq_id,
        "side": side,
        "target_price": normalize_decimal_string(rfq.get("target_price"), "10.00000000"),
        "quantity": normalize_decimal_string(rfq.get("quantity"), "1.00000000"),
    }
    return public, {"rfq_id": rfq_id}


def put_place_4(client: ApiClient, token: str, flag: str, nonce: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    market_symbol = "VOLT-USDT"
    reference_code = f"p4-{nonce}"
    side = "buy"
    trigger_type = "last_trade_price_at_or_above"
    trigger_price = "100.0"
    limit_price = "100.0"
    quantity = "1.0000"
    since_sequence = current_public_feed_tail_sequence(client, market_symbol)
    response = client.create_conditional_order(
        token,
        market_symbol=market_symbol,
        side=side,
        trigger_type=trigger_type,
        trigger_price=trigger_price,
        limit_price=limit_price,
        quantity=quantity,
        reference_code=reference_code,
        signal_context=flag,
    )
    order = response_object(response, "conditional_order")
    conditional_order_id = required_value(order, "id")
    public = {
        "service": "voltax",
        "place": 4,
        "store": "conditional_order",
        "market": market_symbol,
        "conditional_order_id": conditional_order_id,
        "side": side,
        "trigger_type": trigger_type,
        "trigger_bucket": "100.0-100.9",
        "trigger_direction": "at_or_above",
        "since_sequence": since_sequence,
        "quantity": normalize_decimal_string(order.get("quantity"), "1.00000000"),
    }
    return public, {"conditional_order_id": conditional_order_id, "reference_code": reference_code}


def read_place_1(client: ApiClient, token: str, state: Mapping[str, Any]) -> str:
    ids = response_object(state, "ids")
    response = client.get_order(token, required_value(ids, "order_id"))
    order = response_object(response, "order")
    return string_field(order, "execution_memo")


def read_place_2(client: ApiClient, token: str, state: Mapping[str, Any]) -> str:
    ids = response_object(state, "ids")
    response = client.get_trade_receipt(token, required_value(ids, "trade_id"))
    receipt = response_object(response, "receipt")
    return string_field(receipt, "booking_ref")


def read_place_3(client: ApiClient, token: str, state: Mapping[str, Any]) -> str:
    ids = response_object(state, "ids")
    response = client.get_rfq(token, required_value(ids, "rfq_id"))
    rfq = response_object(response, "rfq")
    return string_field(rfq, "delivery_terms")


def read_place_4(client: ApiClient, token: str, state: Mapping[str, Any]) -> str:
    ids = response_object(state, "ids")
    response = client.get_conditional_order(token, required_value(ids, "conditional_order_id"))
    order = response_object(response, "conditional_order")
    return string_field(order, "signal_context")


def current_public_feed_tail_sequence(client: ApiClient, market_symbol: str) -> int:
    response = client.public_feed(after_sequence=0, limit=1, market_symbol=market_symbol)
    next_sequence = response.get("next_sequence")
    try:
        parsed = int(str(next_sequence), 10)
    except (TypeError, ValueError) as error:
        raise Mumble("public feed next sequence missing") from error
    if parsed < 1:
        raise Mumble("public feed next sequence invalid")
    return parsed - 1


def find_owner_receipt_for_flag(
    client: ApiClient,
    *,
    token: str,
    market_symbol: str,
    price: str,
    quantity: str,
    flag: str,
    owner_order_id: Any | None = None,
    owner_reference_code: str | None = None,
    wait_seconds: float = 5.0,
) -> tuple[Any, Mapping[str, Any]]:
    deadline = time.time() + wait_seconds
    while True:
        response = client.user_trades(token)
        trades = response.get("trades")
        if not isinstance(trades, list):
            raise Mumble("owner trades response missing")

        for trade in reversed(trades):
            if not isinstance(trade, Mapping):
                continue
            if trade.get("market_symbol") not in (None, market_symbol):
                continue
            if owner_order_id is not None and str(trade.get("order_id")) != str(owner_order_id):
                continue
            if owner_reference_code is not None and reference_value(trade) != owner_reference_code:
                continue
            if owner_order_id is None and owner_reference_code is None:
                if not decimal_strings_equal(trade.get("price"), price):
                    continue
                if not decimal_strings_equal(trade.get("quantity"), quantity):
                    continue
            trade_id = trade.get("id", trade.get("trade_id"))
            if trade_id in (None, ""):
                continue
            try:
                receipt_response = client.get_trade_receipt(token, trade_id)
                receipt = response_object(receipt_response, "receipt")
            except Mumble:
                continue
            if receipt.get("booking_ref") == flag:
                return trade_id, receipt

        if time.time() >= deadline:
            break
        time.sleep(0.25)

    raise Mumble("owner receipt not found")


def decimal_strings_equal(left: Any, right: Any) -> bool:
    try:
        return Decimal(str(left)) == Decimal(str(right))
    except (InvalidOperation, ValueError):
        return False


def price_bucket(value: Any) -> str:
    try:
        price = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise Mumble("receipt price invalid") from error
    lower = price.quantize(Decimal("0.01"))
    return f"{lower:.2f}-{lower:.2f}"


def smoke_receipt_price(nonce: str) -> str:
    try:
        offset = int(nonce[:2], 16) % 100
    except ValueError:
        offset = 0
    return f"{120 + (Decimal(offset) / Decimal(10)):.1f}"


def isolated_buy_price(client: ApiClient, market_symbol: str, nonce: str) -> str:
    price = Decimal(smoke_receipt_price(nonce))
    try:
        orderbook_response = client.market_orderbook(market_symbol)
        orderbook = orderbook_response.get("orderbook", orderbook_response)
        bids = orderbook.get("bids")
        if isinstance(bids, list):
            bid_prices: list[Decimal] = []
            for bid in bids:
                if not isinstance(bid, Mapping):
                    continue
                try:
                    bid_prices.append(Decimal(str(bid.get("price"))))
                except (InvalidOperation, TypeError, ValueError):
                    continue
            if bid_prices:
                price = max(price, max(bid_prices) + Decimal("1.0"))
    except Mumble:
        pass
    return f"{price:.1f}"


def validate_state_for_request(state: Mapping[str, Any], *, host: str, place: int) -> None:
    if state.get("place") != place:
        raise Corrupt("flag_id place mismatch")
    if str(state.get("host")) != normalize_base_url(host):
        raise Corrupt("flag_id host mismatch")
    for key in ("username", "password", "ids"):
        required_value(state, key)


def response_object(response: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = response.get(key)
    if not isinstance(value, Mapping):
        raise Mumble(f"{key} response missing")
    return value


def list_field(response: Mapping[str, Any], key: str) -> list[Any]:
    value = response.get(key)
    if not isinstance(value, list):
        raise Mumble(f"{key} response missing")
    return value


def approved_smoke_private_keys(policy: str, surface: str) -> set[str]:
    if policy != "competition_vulnerable":
        return set()
    approved = {
        "rfq_workup": {"workup_terms"},
        "trade_venue_allocation": {"desk_ref"},
        "broker_report_trades": {"booking_marker"},
        "public_feed": {"signal_context"},
    }
    return approved.get(surface, set())


def ensure_no_private_fields(value: Any, *, allowed_keys: set[str] | None = None) -> None:
    allowed_keys = allowed_keys or set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            lowered = str(key).lower()
            if lowered in SMOKE_PRIVATE_KEYS and lowered not in allowed_keys:
                raise Mumble("private field sampleed in smoke response")
            ensure_no_private_fields(child, allowed_keys=allowed_keys)
    elif isinstance(value, list):
        for child in value:
            ensure_no_private_fields(child, allowed_keys=allowed_keys)


def required_value(value: Mapping[str, Any], key: str) -> Any:
    result = value.get(key)
    if result in (None, ""):
        raise Mumble(f"{key} missing")
    return result


def string_field(value: Mapping[str, Any], key: str) -> str:
    result = required_value(value, key)
    if not isinstance(result, str):
        raise Mumble(f"{key} invalid")
    return result


def reference_value(value: Mapping[str, Any]) -> str | None:
    for key in ("order_ref", "reference_code", "client_order_id"):
        result = value.get(key)
        if isinstance(result, str) and result:
            return result
    return None


def normalize_decimal_string(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


if __name__ == "__main__":
    raise SystemExit(main())
