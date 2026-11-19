"""Shared VoltaX checker helpers.

This module is intentionally standalone: it uses only Python's standard
library and talks to VoltaX through documented HTTP APIs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping


DEFAULT_TIMEOUT = 5.0
DEFAULT_RETRIES = 1
STATE_VERSION = 1
PUBLIC_ACCOUNT_PROFILES = {"spot", "liquidity", "partner"}


class CheckerError(Exception):
    status = "MUMBLE"

    def __init__(self, message: str = "") -> None:
        super().__init__(message or self.status)


class ServiceDown(CheckerError):
    status = "DOWN"


class Mumble(CheckerError):
    status = "MUMBLE"


class Corrupt(CheckerError):
    status = "CORRUPT"


@dataclass(frozen=True)
class HttpResult:
    status_code: int
    body: Mapping[str, Any]


class ApiClient:
    def __init__(
        self,
        host: str,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self.base_url = normalize_base_url(host)
        self.timeout = timeout
        self.retries = retries
        self._opener = opener or urllib.request.urlopen

    def get(self, path: str, token: str | None = None) -> Mapping[str, Any]:
        return self.request_json("GET", path, token=token).body

    def post(self, path: str, payload: Mapping[str, Any], token: str | None = None) -> Mapping[str, Any]:
        return self.request_json("POST", path, payload=payload, token=token).body

    def delete(self, path: str, token: str | None = None) -> Mapping[str, Any]:
        return self.request_json("DELETE", path, token=token).body

    def request_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        token: str | None = None,
    ) -> HttpResult:
        url = self.url_for(path)
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"

        request = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
        last_error: Exception | None = None
        attempts = max(0, self.retries) + 1

        for attempt in range(attempts):
            try:
                return self._open_json(request)
            except ServiceDown as error:
                last_error = error
                if attempt + 1 == attempts:
                    raise
            except Mumble:
                raise

        raise ServiceDown(str(last_error) if last_error else "service unavailable")

    def register(self, username: str, password: str, account_profile: str = "spot") -> Mapping[str, Any]:
        if account_profile not in PUBLIC_ACCOUNT_PROFILES:
            raise ValueError("unsupported account profile")
        return self.post(
            "/api/auth/register",
            {"username": username, "password": password, "account_profile": account_profile},
        )

    def login(self, username: str, password: str) -> Mapping[str, Any]:
        return self.post("/api/auth/login", {"username": username, "password": password})

    def me(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/auth/me", token=token)

    def faucet(self, token: str, idempotency_key: str) -> Mapping[str, Any]:
        return self.post("/api/faucet", {"idempotency_key": idempotency_key}, token=token)

    def wallets(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/wallets", token=token)

    def ledger(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/ledger", token=token)

    def create_order(
        self,
        token: str,
        *,
        market_symbol: str,
        side: str,
        limit_price: str,
        quantity: str,
        reference_code: str | None = None,
        order_ref: str | None = None,
        client_order_id: str | None = None,
        execution_memo: str | None = None,
        booking_ref: str | None = None,
    ) -> Mapping[str, Any]:
        reference_code = normalize_order_reference(reference_code or order_ref or client_order_id)
        payload = {
            "market_symbol": market_symbol,
            "side": side,
            "order_type": "limit",
            "limit_price": limit_price,
            "quantity": quantity,
            "order_ref": reference_code,
            "reference_code": reference_code,
            "client_order_id": reference_code,
        }
        if execution_memo is not None:
            payload["execution_memo"] = execution_memo
        if booking_ref is not None:
            payload["booking_ref"] = booking_ref
        return self.post(
            "/api/orders",
            payload,
            token=token,
        )

    def get_order(self, token: str, order_id: Any) -> Mapping[str, Any]:
        return self.get(f"/api/orders/{order_id}", token=token)

    def get_order_by_reference(self, token: str, order_ref: Any) -> Mapping[str, Any]:
        encoded_order_ref = urllib.parse.quote(str(order_ref), safe="")
        return self.get(f"/api/orders/lookup/{encoded_order_ref}", token=token)

    def list_orders(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/orders", token=token)

    def cancel_order(self, token: str, order_id: Any) -> Mapping[str, Any]:
        return self.delete(f"/api/orders/{order_id}", token=token)

    def market_orderbook(self, market_symbol: str) -> Mapping[str, Any]:
        encoded_symbol = urllib.parse.quote(str(market_symbol), safe="")
        return self.get(f"/api/markets/{encoded_symbol}/orderbook")

    def market_trades(self, market_symbol: str) -> Mapping[str, Any]:
        encoded_symbol = urllib.parse.quote(str(market_symbol), safe="")
        return self.get(f"/api/markets/{encoded_symbol}/trades")

    def user_trades(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/users/me/trades", token=token)

    def get_trade_receipt(self, token: str, trade_id: Any) -> Mapping[str, Any]:
        return self.get(f"/api/trades/{trade_id}/receipt", token=token)

    def get_trade(self, token: str, trade_id: Any) -> Mapping[str, Any]:
        return self.get(f"/api/trades/{trade_id}", token=token)

    def create_rfq(
        self,
        token: str,
        *,
        market_symbol: str,
        side: str,
        quantity: str,
        target_price: str,
        delivery_terms: str,
        expires_at: str,
    ) -> Mapping[str, Any]:
        return self.post(
            "/api/rfq",
            {
                "market_symbol": market_symbol,
                "side": side,
                "quantity": quantity,
                "target_price": target_price,
                "delivery_terms": delivery_terms,
                "expires_at": expires_at,
            },
            token=token,
        )

    def get_rfq(self, token: str, rfq_id: Any) -> Mapping[str, Any]:
        return self.get(f"/api/rfq/{rfq_id}", token=token)

    def rfq_board(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/rfq/board", token=token)

    def rfq_workup(self, token: str, rfq_id: Any) -> Mapping[str, Any]:
        return self.get(f"/api/rfq/{rfq_id}/workup", token=token)

    def quote_rfq(self, token: str, rfq_id: Any, *, price: str, quantity: str) -> Mapping[str, Any]:
        return self.post(f"/api/rfq/{rfq_id}/quote", {"price": price, "quantity": quantity}, token=token)

    def accept_rfq(self, token: str, rfq_id: Any, *, quote_id: Any) -> Mapping[str, Any]:
        return self.post(f"/api/rfq/{rfq_id}/accept", {"quote_id": quote_id}, token=token)

    def create_conditional_order(
        self,
        token: str,
        *,
        market_symbol: str,
        side: str,
        trigger_type: str,
        trigger_price: str,
        limit_price: str,
        quantity: str,
        reference_code: str | None = None,
        order_ref: str | None = None,
        client_order_id: str | None = None,
        signal_context: str,
    ) -> Mapping[str, Any]:
        reference_code = normalize_order_reference(reference_code or order_ref or client_order_id)
        return self.post(
            "/api/conditional-orders",
            {
                "market_symbol": market_symbol,
                "side": side,
                "trigger_type": trigger_type,
                "trigger_price": trigger_price,
                "limit_price": limit_price,
                "quantity": quantity,
                "order_ref": reference_code,
                "reference_code": reference_code,
                "client_order_id": reference_code,
                "signal_context": signal_context,
            },
            token=token,
        )

    def get_conditional_order(self, token: str, conditional_order_id: Any) -> Mapping[str, Any]:
        return self.get(f"/api/conditional-orders/{conditional_order_id}", token=token)

    def list_conditional_orders(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/conditional-orders", token=token)

    def public_feed(
        self,
        *,
        after_sequence: int = 0,
        limit: int = 1,
        market_symbol: str | None = None,
    ) -> Mapping[str, Any]:
        query: dict[str, Any] = {"after_sequence": after_sequence, "limit": limit}
        if market_symbol:
            query["market_symbol"] = market_symbol
        return self.get(f"/api/feed/public?{urllib.parse.urlencode(query)}")

    def create_broker_campaign(self, token: str, *, campaign_code: str, name: str) -> Mapping[str, Any]:
        return self.post(
            "/api/broker/campaigns",
            {"campaign_code": campaign_code, "name": name, "starts_at": None, "ends_at": None},
            token=token,
        )

    def list_broker_campaigns(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/broker/campaigns", token=token)

    def create_broker_attribution(self, token: str, *, campaign_code: str, user_reference: str) -> Mapping[str, Any]:
        return self.post(
            "/api/broker/attributions",
            {"campaign_code": campaign_code, "user_reference": user_reference},
            token=token,
        )

    def broker_report_trades(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/broker/reports/trades", token=token)

    def broker_report_monthly(self, token: str) -> Mapping[str, Any]:
        return self.get("/api/broker/reports/monthly", token=token)

    def token_from(self, response: Mapping[str, Any]) -> str:
        token = response.get("session", {}).get("token") if isinstance(response.get("session"), Mapping) else None
        if not isinstance(token, str) or not token:
            raise Mumble("session token missing")
        return token

    def url_for(self, path: str) -> str:
        if not path.startswith("/"):
            raise ValueError("path must start with /")
        return urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))

    def _open_json(self, request: urllib.request.Request) -> HttpResult:
        try:
            response = self._opener(request, timeout=self.timeout)
            status_code = response.getcode()
            raw = response.read()
        except urllib.error.HTTPError as error:
            status_code = error.code
            raw = error.read()
        except (TimeoutError, socket.timeout, urllib.error.URLError, OSError) as error:
            raise ServiceDown("service unavailable") from error

        if status_code >= 500:
            raise ServiceDown("service unavailable")
        if status_code < 200 or status_code >= 300:
            raise Mumble(f"unexpected HTTP status {status_code}")

        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise Mumble("invalid JSON response") from error
        if not isinstance(parsed, Mapping):
            raise Mumble("JSON response is not an object")

        return HttpResult(status_code=status_code, body=parsed)


def normalize_base_url(host: str) -> str:
    if not host:
        raise ValueError("host is required")
    host = host.strip()
    if not host.startswith(("http://", "https://")):
        if ":" not in host:
            host = f"{host}:8082"
        host = f"http://{host}"
    return host.rstrip("/")


def normalize_order_reference(value: Any) -> str:
    text = str(value or "")
    if not text or len(text) > 64:
        raise Mumble("order reference invalid")
    return text


def register_account(
    host: str | ApiClient,
    profile: str = "spot",
    *,
    label: str = "acct",
    place: int = 0,
    client: ApiClient | None = None,
    fund: bool = True,
) -> Mapping[str, Any]:
    if profile not in PUBLIC_ACCOUNT_PROFILES:
        raise Corrupt("unsupported account profile")
    api = client or (host if hasattr(host, "register") and hasattr(host, "token_from") else ApiClient(str(host)))
    nonce = secrets.token_hex(8)
    username = f"chk{place}-{label[:3]}-{nonce}"
    password = f"Vx-{secrets.token_urlsafe(18)}"
    registered = api.register(username, password, account_profile=profile)
    token = api.token_from(registered)
    user = response_object(registered, "user")
    observed_profile = user.get("account_profile", profile)
    if observed_profile != profile:
        raise Mumble("account profile mismatch")
    if fund:
        api.faucet(token, f"faucet-{nonce}")
    return {
        "username": username,
        "password": password,
        "token": token,
        "user": user,
        "account_profile": observed_profile,
        "nonce": nonce,
    }


def create_order_flag_store(host: str, flag: str, credential: str, *, client: ApiClient | None = None) -> Mapping[str, Any]:
    api = client or ApiClient(host)
    owner = register_account(host, "spot", label="own", place=1, client=api)
    market = "VOLT-USDT"
    order_ref = f"p1-{owner['nonce']}"
    response = api.create_order(
        owner["token"],
        market_symbol=market,
        side="buy",
        limit_price="1.00",
        quantity="1.0000",
        reference_code=order_ref,
        execution_memo=flag,
    )
    order = response_object(response, "order")
    public = {
        "service": "voltax",
        "place": 1,
        "store": "order_note",
        "market": market,
        "order_ref": order_ref,
        "order_id": str(required_value(order, "id")),
    }
    state = flag_state(host, 1, owner, public, {"order_id": required_value(order, "id"), "order_ref": order_ref})
    flag_id = encode_state(state, credential)
    validate_public_attack_data(public, expected_flag=flag)
    return {"private_flag_id": flag_id, "public": public}


def get_order_flag_store(host: str, flag_id: str, flag: str, credential: str, *, client: ApiClient | None = None) -> str:
    api, state, token = authenticated_state_client(host, flag_id, credential, place=1, client=client)
    ids = response_object(state, "ids")
    order = response_object(api.get_order(token, required_value(ids, "order_id")), "order")
    observed = string_field(order, "execution_memo")
    if observed != flag:
        raise Corrupt("flag mismatch")
    return observed


def create_trade_receipt_flag_store(host: str, flag: str, credential: str, *, client: ApiClient | None = None) -> Mapping[str, Any]:
    api = client or ApiClient(host)
    owner = register_account(host, "spot", label="own", place=2, client=api)
    counterparty = register_account(host, "spot", label="cpt", place=2, client=api)
    market = "VOLT-USDT"
    order_ref = f"p2-{owner['nonce']}"
    price = "10.00"
    api.create_order(
        owner["token"],
        market_symbol=market,
        side="sell",
        limit_price=price,
        quantity="2.0000",
        reference_code=order_ref,
        execution_memo="place-2-order-note-decoy",
        booking_ref=flag,
    )
    api.create_order(
        counterparty["token"],
        market_symbol=market,
        side="buy",
        limit_price=price,
        quantity="1.0000",
        reference_code=f"p2c-{owner['nonce']}",
        execution_memo="counterparty-reference",
    )
    trade_id, receipt = find_owner_receipt(
        api,
        token=owner["token"],
        market=market,
        order_ref=order_ref,
        flag=flag,
    )
    public = {
        "service": "voltax",
        "place": 2,
        "store": "trade_receipt",
        "market": market,
        "trade_id": trade_id,
        "owner_order_ref": order_ref,
        "price_bucket": price_bucket(price),
        "side_hint": "sell",
        "quantity": "1.00000000",
    }
    state = flag_state(host, 2, owner, public, {"trade_id": trade_id, "receipt_id": receipt.get("id")})
    flag_id = encode_state(state, credential)
    validate_public_attack_data(public, expected_flag=flag)
    return {"private_flag_id": flag_id, "public": public}


def get_trade_receipt_flag_store(host: str, flag_id: str, flag: str, credential: str, *, client: ApiClient | None = None) -> str:
    api, state, token = authenticated_state_client(host, flag_id, credential, place=2, client=client)
    ids = response_object(state, "ids")
    receipt = response_object(api.get_trade_receipt(token, required_value(ids, "trade_id")), "receipt")
    observed = first_string(receipt, "booking_ref", "desk_ref")
    if observed != flag:
        raise Corrupt("flag mismatch")
    return observed


def create_rfq_flag_store(host: str, flag: str, credential: str, *, client: ApiClient | None = None) -> Mapping[str, Any]:
    api = client or ApiClient(host)
    owner = register_account(host, "spot", label="own", place=3, client=api, fund=False)
    market = "VOLT-USDT"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    rfq = response_object(
        api.create_rfq(
            owner["token"],
            market_symbol=market,
            side="buy",
            quantity="1.0000",
            target_price="10.00",
            delivery_terms=flag,
            expires_at=expires_at,
        ),
        "rfq",
    )
    public = {"service": "voltax", "place": 3, "store": "rfq", "market": market, "rfq_id": required_value(rfq, "id")}
    state = flag_state(host, 3, owner, public, {"rfq_id": required_value(rfq, "id")})
    flag_id = encode_state(state, credential)
    validate_public_attack_data(public, expected_flag=flag)
    return {"private_flag_id": flag_id, "public": public}


def get_rfq_flag_store(host: str, flag_id: str, flag: str, credential: str, *, client: ApiClient | None = None) -> str:
    api, state, token = authenticated_state_client(host, flag_id, credential, place=3, client=client)
    ids = response_object(state, "ids")
    rfq = response_object(api.get_rfq(token, required_value(ids, "rfq_id")), "rfq")
    observed = string_field(rfq, "delivery_terms")
    if observed != flag:
        raise Corrupt("flag mismatch")
    return observed


def create_conditional_flag_store(host: str, flag: str, credential: str, *, client: ApiClient | None = None) -> Mapping[str, Any]:
    api = client or ApiClient(host)
    owner = register_account(host, "spot", label="own", place=4, client=api)
    market = "VOLT-USDT"
    feed = api.public_feed(after_sequence=0, limit=1, market_symbol=market)
    since_sequence = tail_sequence_from(feed)
    order = response_object(
        api.create_conditional_order(
            owner["token"],
            market_symbol=market,
            side="buy",
            trigger_type="last_trade_price_at_or_above",
            trigger_price="100.0",
            limit_price="100.0",
            quantity="1.0000",
            reference_code=f"p4-{owner['nonce']}",
            signal_context=flag,
        ),
        "conditional_order",
    )
    public = {
        "service": "voltax",
        "place": 4,
        "store": "conditional_order",
        "market": market,
        "conditional_order_id": required_value(order, "id"),
        "trigger_bucket": "100.0-100.9",
        "trigger_direction": "at_or_above",
        "since_sequence": since_sequence,
        "quantity": normalize_decimal_string(order.get("quantity"), "1.00000000"),
    }
    state = flag_state(host, 4, owner, public, {"conditional_order_id": required_value(order, "id")})
    flag_id = encode_state(state, credential)
    validate_public_attack_data(public, expected_flag=flag)
    return {"private_flag_id": flag_id, "public": public}


def get_conditional_flag_store(host: str, flag_id: str, flag: str, credential: str, *, client: ApiClient | None = None) -> str:
    api, state, token = authenticated_state_client(host, flag_id, credential, place=4, client=client)
    ids = response_object(state, "ids")
    order = response_object(api.get_conditional_order(token, required_value(ids, "conditional_order_id")), "conditional_order")
    observed = string_field(order, "signal_context")
    if observed != flag:
        raise Corrupt("flag mismatch")
    return observed


def flag_state(host: str, place: int, owner: Mapping[str, Any], public: Mapping[str, Any], ids: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "place": place,
        "host": normalize_base_url(host),
        "username": owner["username"],
        "password": owner["password"],
        "account_profile": owner.get("account_profile", "spot"),
        "ids": ids,
        "public": public,
        "nonce": owner["nonce"],
    }


def authenticated_state_client(
    host: str,
    flag_id: str,
    credential: str,
    *,
    place: int,
    client: ApiClient | None = None,
) -> tuple[ApiClient, Mapping[str, Any], str]:
    api = client or ApiClient(host)
    state = decode_state(flag_id, credential)
    if state.get("place") != place or str(state.get("host")) != normalize_base_url(host):
        raise Corrupt("flag_id scope mismatch")
    token = api.token_from(api.login(str(required_value(state, "username")), str(required_value(state, "password"))))
    return api, state, token


def find_owner_receipt(
    client: ApiClient,
    *,
    token: str,
    market: str,
    order_ref: str,
    flag: str,
) -> tuple[Any, Mapping[str, Any]]:
    deadline = time.time() + 5.0
    while True:
        trades = list_field(client.user_trades(token), "trades")
        for trade in reversed(trades):
            if not isinstance(trade, Mapping):
                continue
            observed_ref = first_string(trade, "order_ref", "reference_code", "client_order_id", required=False)
            if trade.get("market_symbol", trade.get("market")) not in (None, market):
                continue
            if observed_ref and observed_ref != order_ref:
                continue
            trade_id = trade.get("id", trade.get("trade_id"))
            if trade_id in (None, ""):
                continue
            try:
                receipt = response_object(client.get_trade_receipt(token, trade_id), "receipt")
            except Mumble:
                continue
            if first_string(receipt, "booking_ref", "desk_ref", required=False) == flag:
                return trade_id, receipt

        if time.time() >= deadline:
            break
        time.sleep(0.25)
    raise Mumble("owner receipt not found")


def price_bucket(value: Any) -> str:
    try:
        price = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise Mumble("receipt price invalid") from error
    lower = price.quantize(Decimal("0.01"))
    return f"{lower:.2f}-{lower:.2f}"


def tail_sequence_from(feed: Mapping[str, Any]) -> int:
    try:
        parsed = int(str(feed.get("next_sequence")), 10)
    except (TypeError, ValueError) as error:
        raise Mumble("public feed next sequence missing") from error
    if parsed < 1:
        raise Mumble("public feed next sequence invalid")
    return parsed - 1


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


def required_value(value: Mapping[str, Any], key: str) -> Any:
    result = value.get(key)
    if result in (None, ""):
        raise Mumble(f"{key} missing")
    return result


def first_string(value: Mapping[str, Any], *keys: str, required: bool = True) -> str | None:
    for key in keys:
        result = value.get(key)
        if isinstance(result, str) and result:
            return result
    if required:
        raise Mumble(f"{keys[0]} missing")
    return None


def string_field(value: Mapping[str, Any], key: str) -> str:
    result = required_value(value, key)
    if not isinstance(result, str):
        raise Mumble(f"{key} invalid")
    return result


def normalize_decimal_string(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def encode_state(state: Mapping[str, Any], credential: str) -> str:
    if not credential:
        raise ValueError("state credential is required")
    payload = dict(state)
    payload.setdefault("v", STATE_VERSION)
    payload.setdefault("created_at", int(time.time()))
    signature = hmac.new(credential.encode("utf-8"), canonical_json(payload), hashlib.sha256).hexdigest()
    envelope = {"payload": payload, "sig": signature}
    return base64.urlsafe_b64encode(canonical_json(envelope)).decode("ascii").rstrip("=")


def decode_state(flag_id: str, credential: str) -> Mapping[str, Any]:
    if not credential:
        raise ValueError("state credential is required")
    try:
        raw = base64.urlsafe_b64decode(flag_id + "=" * (-len(flag_id) % 4))
        envelope = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as error:
        raise Corrupt("malformed flag_id") from error

    if not isinstance(envelope, Mapping):
        raise Corrupt("malformed flag_id")
    payload = envelope.get("payload")
    signature = envelope.get("sig")
    if not isinstance(payload, Mapping) or not isinstance(signature, str):
        raise Corrupt("malformed flag_id")

    expected = hmac.new(credential.encode("utf-8"), canonical_json(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise Corrupt("tampered flag_id")

    if payload.get("v") != STATE_VERSION:
        raise Corrupt("unsupported flag_id version")

    return payload


FORBIDDEN_PUBLIC_KEYS = {
    "username",
    "password",
    "token",
    "bearer_token",
    "session",
    "session_id",
    "token_digest",
    "hmac_key",
    "credential",
    "flag",
    "flag_id",
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
    "stack",
    "backtrace",
    "raw",
    "orm",
}


def validate_public_attack_data(data: Mapping[str, Any], expected_flag: str | None = None) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise Corrupt("public attack data must be an object")
    _walk_public_data(data, expected_flag=expected_flag)
    return data


def _walk_public_data(value: Any, expected_flag: str | None) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            lowered = str(key).lower()
            if lowered in FORBIDDEN_PUBLIC_KEYS:
                raise Corrupt(f"forbidden public attack-data key: {key}")
            _walk_public_data(child, expected_flag)
    elif isinstance(value, list):
        for child in value:
            _walk_public_data(child, expected_flag)
    elif expected_flag and isinstance(value, str) and expected_flag in value:
        raise Corrupt("flag sampleed in public attack data")
