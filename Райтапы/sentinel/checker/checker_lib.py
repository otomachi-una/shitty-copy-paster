"""Sentinel AML checker foundation for Wave 12 places 1 and 2.

The checker talks only to normal HTTP business APIs. It does not import product
packages, read databases, or expose credential-bearing public attack data.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import importlib
import json
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, TypeAlias


_url_error = importlib.import_module("urllib.error")
_url_parse = importlib.import_module("urllib.parse")
_url_request = importlib.import_module("urllib.request")


SERVICE_NAME = "sentinel_aml"
CHECKER_PATH = "sentinel_aml/checker.py"
CHECKER_TYPE = "pfr"
CHECKER_TIMEOUT_SECONDS = 30
DEFAULT_HTTP_TIMEOUT_SECONDS = 5.0
NETWORK_ROOM_WAIT_SECONDS = 12.0
NETWORK_ROOM_POLL_SECONDS = 0.25
PLACES = 2
PUTS = 2
GETS = 2

PLACE_1 = 1
PLACE_1_STORE = "CaseNote.body"
PLACE_2 = 2
PLACE_2_STORE = "EDDRecord.confidential_comment"
PLACE_2_PUBLIC_STORE = "EDDRecord"

SUPPORTED_ACTIONS = ("check", "havoc", "put", "get", "putnoise", "getnoise")
DEFAULT_CHECK_SUBCHECKS = (
    "health",
    "check_basic",
    "check_case_notes",
    "check_edd",
    "check_dedup",
    "check_audit",
    "check_graph",
    "check_export",
    "check_network_room",
    "check_retention",
)
RETENTION_SENSITIVE_TABLES = ("case_notes", "edd_records")
RETENTION_SCAN_DIRS = ("migrations", "internal", "scripts")
PLACE_DESCRIPTIONS = {
    PLACE_1: "CaseNote.body owner flow",
    PLACE_2: "EDDRecord.confidential_comment owner flow",
}

CHECKER_SECRET_ENV = "SENTINEL_AML_CHECKER_SECRET"
LEGACY_DEV_CHECKER_SECRET_SHA256 = "0d4d26fe2adc9e17dc977b2626c13ba72b3b062b5a3b33be70ac2ac5ccdebaee"
DEFAULT_CHECKER_SECRET = ""
PRIVATE_STATE_SCHEMA_VERSION = 2
NOISE_STATE_SCHEMA_VERSION = 1

EXIT_OK = 101
EXIT_CORRUPT = 102
EXIT_MUMBLE = 103
EXIT_DOWN = 104
EXIT_CHECKER_ERROR = 110


class CheckerError(Exception):
    """Base checker exception with a Hackerdom-compatible exit code."""

    exit_code = EXIT_CHECKER_ERROR


class UnsupportedActionError(CheckerError):
    exit_code = EXIT_MUMBLE


class UnsupportedPlaceError(CheckerError):
    exit_code = EXIT_MUMBLE


class StateIntegrityError(CheckerError):
    exit_code = EXIT_CORRUPT


class ServiceDownError(CheckerError):
    exit_code = EXIT_DOWN


class ServiceMumbleError(CheckerError):
    exit_code = EXIT_MUMBLE


class ServiceCorruptError(CheckerError):
    exit_code = EXIT_CORRUPT


class CheckerConfigurationError(CheckerError):
    exit_code = EXIT_CHECKER_ERROR


class CheckFailedError(CheckerError):
    def __init__(self, failures: list[str], exit_code: int = EXIT_MUMBLE) -> None:
        self.failures = failures
        self.exit_code = exit_code
        super().__init__("CHECK failed: " + "; ".join(failures))


class HTTPStatusError(ServiceMumbleError):
    def __init__(self, status: int, api_error: str = "") -> None:
        self.status = status
        self.api_error = api_error
        super().__init__(f"unexpected HTTP status {status}")


@dataclass(frozen=True)
class CheckerAction:
    action: str
    host: str
    place: int | None = None
    flag: str | None = None
    private_state: str | None = None
    seed: str | None = None


@dataclass(frozen=True)
class Place1PrivateState:
    schema_version: int
    service: str
    store: str
    place: int
    customer_id: int
    case_id: int
    note_id: int
    entity_hint: str
    dedup_hint: str
    typology_hint: str
    idempotency_key: str


@dataclass(frozen=True)
class Place2PrivateState:
    schema_version: int
    service: str
    store: str
    place: int
    customer_id: int
    edd_record_id: int
    entity_hint: str
    typology_hint: str
    idempotency_key: str


PrivateState: TypeAlias = Place1PrivateState | Place2PrivateState


@dataclass(frozen=True)
class NoisePrivateState:
    schema_version: int
    service: str
    kind: str
    username: str
    password: str
    token: str
    seed: str
    customer_ids: list[int]
    case_ids: list[int]
    transaction_ids: list[int]
    edd_record_id: int
    export_id: int
    graph_hint: str
    network_room_id: int
    idempotency_key: str


@dataclass(frozen=True)
class PutResult:
    private_state: str
    public_attack_data: dict[str, Any]


@dataclass(frozen=True)
class CheckSubcheck:
    name: str
    description: str
    runner: Callable[["SentinelAMLClient", str, "CheckRunContext"], None]


@dataclass(frozen=True)
class CheckRunContext:
    mode: str
    run_id: str


Place1PutResult = PutResult
Place2PutResult = PutResult
NoisePutResult = PutResult


def checker_scenario_inventory() -> list[dict[str, Any]]:
    """Return the final checker scenario matrix as JSON-compatible data."""
    return [
        {
            "name": "place1_put",
            "action": "put",
            "place": PLACE_1,
            "owner_flow": "case review note",
            "normal_api_paths": (
                "POST /api/auth/register",
                "POST /api/auth/login",
                "POST /api/customers",
                "POST /api/customers/{customer_id}/accounts",
                "POST /api/transactions",
                "GET /api/alerts/queue",
                "POST /api/alerts/{alert_id}/claim",
                "POST /api/alerts/{alert_id}/case",
                "POST /api/cases/{case_id}/notes",
            ),
            "public_attack_data_keys": (
                "service",
                "case_ref",
                "case_id",
                "customer_ref",
                "customer_id",
                "entity_ref",
                "party_ref",
                "matching_reference",
            ),
            "forbidden_public_markers": public_attack_data_forbidden_markers(),
        },
        {
            "name": "place1_get",
            "action": "get",
            "place": PLACE_1,
            "owner_flow": "case review note",
            "normal_api_paths": ("GET /api/cases/{case_id}/notes", "POST /api/auth/login"),
            "owner_view_only": True,
            "forbidden_get_paths": forbidden_checker_get_side_view_paths(),
        },
        {
            "name": "place2_put",
            "action": "put",
            "place": PLACE_2,
            "owner_flow": "enhanced review record",
            "normal_api_paths": (
                "POST /api/auth/register",
                "POST /api/auth/login",
                "POST /api/customers",
                "POST /api/customers/{customer_id}/edd",
            ),
            "public_attack_data_keys": ("service", "customer_ref", "customer_id", "entity_ref", "party_ref"),
            "forbidden_public_markers": public_attack_data_forbidden_markers(),
        },
        {
            "name": "place2_get",
            "action": "get",
            "place": PLACE_2,
            "owner_flow": "enhanced review record",
            "normal_api_paths": ("GET /api/customers/{customer_id}/edd", "POST /api/auth/login"),
            "owner_view_only": True,
            "forbidden_get_paths": forbidden_checker_get_side_view_paths(),
        },
        *[
            {
                "name": subcheck,
                "action": "check/havoc",
                "place": None,
                "store": None,
                "normal_api_paths": check_subcheck_api_paths()[subcheck],
                "bounded_timeout_seconds": DEFAULT_HTTP_TIMEOUT_SECONDS,
            }
            for subcheck in DEFAULT_CHECK_SUBCHECKS
        ],
        {
            "name": "putnoise",
            "action": "putnoise",
            "place": None,
            "store": "non-flag noise",
            "normal_api_paths": (
                "POST /api/auth/register",
                "POST /api/auth/login",
                "POST /api/customers",
                "POST /api/customers/{customer_id}/accounts",
                "POST /api/transactions",
                "GET /api/alerts/queue",
                "POST /api/alerts/{alert_id}/claim",
                "POST /api/alerts/{alert_id}/case",
                "POST /api/cases/{case_id}/notes",
                "POST /api/customers/{customer_id}/edd",
                "POST /api/cases/{case_id}/exports",
                "GET /api/graph/entities/{entity_hint}",
                "GET /api/graph/entities/{entity_hint}/related-cases",
                "GET /api/network/rooms",
                "GET /api/network/rooms/{room_id}/dossier",
            ),
            "public_attack_data_keys": (
                "service",
                "kind",
                "customer_ids",
                "case_ids",
                "transaction_ids",
                "edd_record_id",
                "export_id",
                "graph_hint",
                "network_room_id",
            ),
            "forbidden_public_markers": noise_public_data_forbidden_markers(),
        },
        {
            "name": "getnoise",
            "action": "getnoise",
            "place": None,
            "store": "non-flag noise",
            "normal_api_paths": (
                "POST /api/auth/login",
                "GET /api/customers/{customer_id}",
                "GET /api/exports/{export_id}",
                "GET /api/graph/entities/{entity_hint}",
                "GET /api/graph/entities/{entity_hint}/related-cases",
                "GET /api/network/rooms/{room_id}/dossier",
            ),
            "bounded_timeout_seconds": DEFAULT_HTTP_TIMEOUT_SECONDS,
        },
    ]


def check_subcheck_api_paths() -> dict[str, tuple[str, ...]]:
    return {
        "health": ("GET /healthz",),
        "check_basic": (
            "POST /api/auth/register",
            "POST /api/auth/login",
            "POST /api/customers",
            "GET /api/customers/{customer_id}",
            "POST /api/customers/{customer_id}/accounts",
            "GET /api/customers/{customer_id}/accounts",
            "POST /api/transactions",
            "GET /api/transactions/{transaction_id}",
            "GET /api/customers/{customer_id}/transactions",
        ),
        "check_case_notes": (
            "POST /api/cases/{case_id}/notes",
            "GET /api/cases/{case_id}/notes",
        ),
        "check_edd": (
            "POST /api/customers/{customer_id}/edd",
            "GET /api/customers/{customer_id}/edd",
        ),
        "check_dedup": (
            "GET /api/cases/{case_id}/duplicates",
            "GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview",
        ),
        "check_audit": ("GET /api/cases/{case_id}/timeline",),
        "check_graph": (
            "GET /api/graph/entities/{entity_hint}",
            "GET /api/graph/entities/{entity_hint}/related-cases",
        ),
        "check_export": (
            "POST /api/cases/{case_id}/exports",
            "GET /api/exports/{export_id}",
        ),
        "check_network_room": (
            "GET /api/network/rooms",
            "GET /api/network/rooms/{room_id}/dossier",
        ),
        "check_retention": ("source scan: migrations internal scripts",),
    }


def public_attack_data_forbidden_markers() -> tuple[str, ...]:
    return (
        "username",
        "password",
        "token",
        "session",
        "flag",
        "checker_secret",
        "private_state",
        "private state",
        "confidential_comment",
        "casenote.body",
        "eddrecord",
    )


def noise_public_data_forbidden_markers() -> tuple[str, ...]:
    return (
        *public_attack_data_forbidden_markers(),
        "body",
        "source_of_funds",
        "risk_rationale",
    )


def forbidden_checker_get_side_view_paths() -> tuple[str, ...]:
    return (
        "GET /api/cases/{case_id}/duplicates",
        "GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview",
        "GET /api/cases/{case_id}/timeline",
        "GET /api/graph/entities/{entity_hint}",
        "GET /api/graph/entities/{entity_hint}/related-cases",
        "GET /api/graph/entities/{entity_hint}/edd-summaries",
        "GET /api/exports/{export_id}",
        "GET /api/network/rooms",
        "GET /api/network/rooms/{room_id}/dossier",
    )


def checker_secret() -> str:
    value = os.environ.get(CHECKER_SECRET_ENV, "")
    legacy_digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    if value == "" or value == DEFAULT_CHECKER_SECRET or legacy_digest == LEGACY_DEV_CHECKER_SECRET_SHA256:
        raise CheckerConfigurationError("checker secret is not configured")
    return value


def forcad_cquit(exit_code: int, public: str = "", private: str | None = None) -> int:
    if private is None:
        private = public
    print(public)
    print(private, file=sys.stderr)
    return exit_code


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _secret_bytes(secret: str) -> bytes:
    if not secret:
        raise ValueError("checker secret is required")
    return secret.encode("utf-8")


def hmac_hex(secret: str, message: str) -> str:
    return hmac.new(_secret_bytes(secret), message.encode("utf-8"), hashlib.sha256).hexdigest()


def redact_sensitive(message: str, extra_values: Iterable[str] = ()) -> str:
    redacted = str(message)
    for value in extra_values:
        if value:
            redacted = redacted.replace(value, "[redacted]")
    redacted = re.sub(r"(FLAG|CTF|SENTINEL)\{[^}]*\}", "[redacted]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(
        r"(?i)\b(password|token|session|secret|flag|private_state|authorization)(\s*[=:]\s*)([^\s,;}\]]+)",
        r"\1\2[redacted]",
        redacted,
    )
    return redacted


def safe_error_message(exc: Exception, extra_values: Iterable[str] = (), max_length: int = 240) -> str:
    message = str(exc) or exc.__class__.__name__
    return redact_sensitive(message, extra_values)[:max_length]


def derive_idempotency_key(flag: str, place: int, secret: str | None = None) -> str:
    validate_supported_place(place)
    material = f"{flag}\x00{place}\x00{SERVICE_NAME}"
    return hmac_hex(secret or checker_secret(), material)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(token: str) -> bytes:
    padding = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode((token + padding).encode("ascii"))


def encode_private_state(state: PrivateState, secret: str | None = None) -> str:
    payload = dataclasses.asdict(state)
    _validate_private_payload(payload)
    mac = hmac_hex(secret or checker_secret(), canonical_json(payload))
    envelope = {"payload": payload, "mac": mac}
    return _b64url_encode(canonical_json(envelope).encode("utf-8"))


def decode_private_state(encoded: str, secret: str | None = None, expected_place: int | None = None) -> PrivateState:
    try:
        envelope = json.loads(_b64url_decode(encoded).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise StateIntegrityError("private state is not valid base64url JSON") from exc

    if not isinstance(envelope, dict):
        raise StateIntegrityError("private state envelope must be an object")
    payload = envelope.get("payload")
    mac = envelope.get("mac")
    if not isinstance(payload, dict) or not isinstance(mac, str):
        raise StateIntegrityError("private state envelope is missing payload or mac")

    expected = hmac_hex(secret or checker_secret(), canonical_json(payload))
    if not hmac.compare_digest(mac, expected):
        raise StateIntegrityError("private state MAC mismatch")

    _validate_private_payload(payload)
    if expected_place is not None and payload["place"] != expected_place:
        raise StateIntegrityError("private state place mismatch")
    if payload["place"] == PLACE_1:
        return Place1PrivateState(**payload)
    if payload["place"] == PLACE_2:
        return Place2PrivateState(**payload)
    raise StateIntegrityError("unsupported private state place")


def encode_noise_state(state: NoisePrivateState, secret: str | None = None) -> str:
    payload = dataclasses.asdict(state)
    _validate_noise_payload(payload)
    mac = hmac_hex(secret or checker_secret(), canonical_json(payload))
    envelope = {"payload": payload, "mac": mac}
    return _b64url_encode(canonical_json(envelope).encode("utf-8"))


def decode_noise_state(encoded: str, secret: str | None = None) -> NoisePrivateState:
    try:
        envelope = json.loads(_b64url_decode(encoded).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise StateIntegrityError("noise state is not valid base64url JSON") from exc
    if not isinstance(envelope, dict):
        raise StateIntegrityError("noise state envelope must be an object")
    payload = envelope.get("payload")
    mac = envelope.get("mac")
    if not isinstance(payload, dict) or not isinstance(mac, str):
        raise StateIntegrityError("noise state envelope is missing payload or mac")

    expected = hmac_hex(secret or checker_secret(), canonical_json(payload))
    if not hmac.compare_digest(mac, expected):
        raise StateIntegrityError("noise state MAC mismatch")
    _validate_noise_payload(payload)
    return NoisePrivateState(**payload)


def _validate_private_payload(payload: dict[str, Any]) -> None:
    place = payload.get("place")
    if place == PLACE_1:
        required = {field.name for field in dataclasses.fields(Place1PrivateState)}
        expected_store = PLACE_1_STORE
        id_fields = ("customer_id", "case_id", "note_id")
        text_fields = ("entity_hint", "dedup_hint", "typology_hint", "idempotency_key")
    elif place == PLACE_2:
        required = {field.name for field in dataclasses.fields(Place2PrivateState)}
        expected_store = PLACE_2_STORE
        id_fields = ("customer_id", "edd_record_id")
        text_fields = ("entity_hint", "typology_hint", "idempotency_key")
    else:
        raise StateIntegrityError("unsupported private state place")

    if set(payload) != required:
        raise StateIntegrityError("private state schema mismatch")
    if payload["schema_version"] != PRIVATE_STATE_SCHEMA_VERSION:
        raise StateIntegrityError("unsupported private state schema")
    if payload["service"] != SERVICE_NAME:
        raise StateIntegrityError("private state service mismatch")
    if payload["store"] != expected_store:
        raise StateIntegrityError("private state place/store mismatch")
    for key in text_fields:
        if not isinstance(payload[key], str) or not payload[key]:
            raise StateIntegrityError(f"private state field {key} is required")
    for key in id_fields:
        if not isinstance(payload[key], int) or payload[key] <= 0:
            raise StateIntegrityError(f"private state field {key} must be a positive integer")


def _validate_noise_payload(payload: dict[str, Any]) -> None:
    required = {field.name for field in dataclasses.fields(NoisePrivateState)}
    if set(payload) != required:
        raise StateIntegrityError("noise state schema mismatch")
    if payload["schema_version"] != NOISE_STATE_SCHEMA_VERSION:
        raise StateIntegrityError("unsupported noise state schema")
    if payload["service"] != SERVICE_NAME or payload["kind"] != "noise":
        raise StateIntegrityError("noise state service/kind mismatch")
    for key in ("username", "password", "token", "seed", "graph_hint", "idempotency_key"):
        if not isinstance(payload[key], str) or not payload[key]:
            raise StateIntegrityError(f"noise state field {key} is required")
    for key in ("customer_ids", "case_ids", "transaction_ids"):
        value = payload[key]
        if not isinstance(value, list) or not value or not all(isinstance(item, int) and item > 0 for item in value):
            raise StateIntegrityError(f"noise state field {key} must contain positive integers")
    for key in ("edd_record_id", "export_id"):
        if not isinstance(payload[key], int) or payload[key] <= 0:
            raise StateIntegrityError(f"noise state field {key} must be a positive integer")
    if not isinstance(payload["network_room_id"], int) or payload["network_room_id"] < 0:
        raise StateIntegrityError("noise state field network_room_id must be non-negative")


def public_attack_data_for_place1(state: Place1PrivateState) -> dict[str, Any]:
    return {
        "service": SERVICE_NAME,
        "store": "case_note",
        "case_ref": f"case-{state.case_id}",
        "case_id": state.case_id,
        "customer_ref": f"customer-{state.customer_id}",
        "customer_id": state.customer_id,
        "entity_hint": state.entity_hint,
        "entity_ref": state.entity_hint,
        "party_ref": state.entity_hint,
        "dedup_hint": state.dedup_hint,
        "typology_hint": state.typology_hint,
        "matching_reference": state.dedup_hint,
    }


def public_attack_data_for_place2(state: Place2PrivateState) -> dict[str, Any]:
    return {
        "service": SERVICE_NAME,
        "store": "edd",
        "customer_ref": f"customer-{state.customer_id}",
        "customer_id": state.customer_id,
        "entity_hint": state.entity_hint,
        "entity_ref": state.entity_hint,
        "party_ref": state.entity_hint,
        "typology_hint": state.typology_hint,
    }


def public_attack_data_for_state(state: PrivateState) -> dict[str, Any]:
    if isinstance(state, Place1PrivateState):
        return public_attack_data_for_place1(state)
    if isinstance(state, Place2PrivateState):
        return public_attack_data_for_place2(state)
    raise TypeError("unsupported private state type")


def assert_public_attack_data_safe(public_attack_data: dict[str, Any]) -> None:
    serialized = canonical_json(public_attack_data).lower()
    forbidden = public_attack_data_forbidden_markers()
    leaked = [marker for marker in forbidden if marker in serialized]
    if leaked:
        raise ValueError(f"public attack data contains forbidden markers: {', '.join(leaked)}")


def public_noise_data_for_state(state: NoisePrivateState) -> dict[str, Any]:
    public = {
        "service": SERVICE_NAME,
        "kind": "noise",
        "customer_ids": list(state.customer_ids),
        "case_ids": list(state.case_ids),
        "transaction_ids": list(state.transaction_ids),
        "edd_record_id": state.edd_record_id,
        "export_id": state.export_id,
        "graph_hint": state.graph_hint,
    }
    if state.network_room_id > 0:
        public["network_room_id"] = state.network_room_id
    assert_noise_public_data_safe(public)
    return public


def assert_noise_public_data_safe(public_data: dict[str, Any]) -> None:
    serialized = canonical_json(public_data).lower()
    forbidden = noise_public_data_forbidden_markers()
    leaked = [marker for marker in forbidden if marker in serialized]
    if leaked:
        raise ValueError(f"noise public data contains forbidden markers: {', '.join(leaked)}")


def validate_supported_place(place: int) -> None:
    if place not in (PLACE_1, PLACE_2):
        raise UnsupportedPlaceError(f"unsupported checker place: {place}")


def parse_checker_args(argv: list[str]) -> CheckerAction:
    if len(argv) < 2:
        raise UnsupportedActionError("missing checker action")

    action = argv[1].lower()
    if action not in SUPPORTED_ACTIONS:
        raise UnsupportedActionError(f"unsupported checker action: {argv[1]}")

    args = argv[2:]
    if action in ("check", "havoc"):
        if len(args) != 1:
            raise UnsupportedActionError(f"{action.upper()} requires: {action} <host>")
        return CheckerAction(action=action, host=args[0])

    if action == "putnoise":
        if len(args) not in (1, 2):
            raise UnsupportedActionError("PUTNOISE requires: putnoise <host> [seed]")
        seed = args[1] if len(args) == 2 else None
        return CheckerAction(action=action, host=args[0], seed=seed)

    if action == "getnoise":
        if len(args) != 2:
            raise UnsupportedActionError("GETNOISE requires: getnoise <host> <noise_id>")
        return CheckerAction(action=action, host=args[0], private_state=args[1])

    if action == "put":
        if len(args) == 3:
            host, flag, place_raw = args
        elif len(args) == 4:
            host, _external_flag_id, flag, place_raw = args
        else:
            raise UnsupportedActionError("PUT requires: put <host> [external_flag_id] <flag> <place>")
        place = parse_place(place_raw)
        validate_supported_place(place)
        return CheckerAction(action=action, host=host, flag=flag, place=place)

    if len(args) != 4:
        raise UnsupportedActionError("GET requires: get <host> <private_flag_id> <flag> <place>")
    host, private_state, flag, place_raw = args
    place = parse_place(place_raw)
    validate_supported_place(place)
    return CheckerAction(action=action, host=host, private_state=private_state, flag=flag, place=place)


def parse_place(raw: str) -> int:
    try:
        place = int(raw, 10)
    except ValueError as exc:
        raise UnsupportedPlaceError(f"invalid checker place: {raw}") from exc
    return place


class SentinelAMLClient:
    def __init__(self, host: str, timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.base_url = normalize_base_url(host)
        self.timeout = timeout

    def request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        bearer_token: str | None = None,
        expected_statuses: Iterable[int] = (200,),
        timeout: float | None = None,
    ) -> dict[str, Any]:
        url = _url_parse.urljoin(self.base_url + "/", path.lstrip("/"))
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = canonical_json(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        req = _url_request.Request(url, data=body, headers=headers, method=method.upper())
        effective_timeout = self.timeout if timeout is None else timeout
        try:
            with _url_request.urlopen(req, timeout=effective_timeout) as response:
                status = response.getcode()
                raw = response.read()
        except _url_error.HTTPError as exc:
            status = exc.code
            raw = exc.read()
        except (TimeoutError, OSError, _url_error.URLError) as exc:
            raise ServiceDownError("service request failed") from exc

        decoded = decode_json_body(raw)
        if status not in set(expected_statuses):
            raise HTTPStatusError(status, api_error=str(decoded.get("error", "")))
        return decoded

    def health(self) -> dict[str, Any]:
        return self.request_json("GET", "/healthz", expected_statuses=(200,))

    def register(self, username: str, password: str) -> dict[str, Any]:
        return self.request_json(
            "POST",
            "/api/auth/register",
            {"username": username, "password": password},
            expected_statuses=(201,),
        )

    def login(self, username: str, password: str) -> dict[str, Any]:
        return self.request_json(
            "POST",
            "/api/auth/login",
            {"username": username, "password": password},
            expected_statuses=(200,),
        )

    def create_customer(self, token: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request_json("POST", "/api/customers", payload, token, expected_statuses=(201,))

    def get_customer(self, token: str, customer_id: int) -> dict[str, Any]:
        return self.request_json("GET", f"/api/customers/{customer_id}", bearer_token=token)

    def create_account(self, token: str, customer_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/api/customers/{customer_id}/accounts",
            payload,
            token,
            expected_statuses=(201,),
        )

    def list_customer_accounts(self, token: str, customer_id: int) -> list[dict[str, Any]]:
        response = self.request_json("GET", f"/api/customers/{customer_id}/accounts", bearer_token=token)
        accounts = response.get("accounts")
        if not isinstance(accounts, list):
            raise ServiceMumbleError("accounts response is missing accounts list")
        return accounts

    def create_transaction(self, token: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request_json("POST", "/api/transactions", payload, token, expected_statuses=(201,))

    def get_transaction(self, token: str, transaction_id: int) -> dict[str, Any]:
        return self.request_json("GET", f"/api/transactions/{transaction_id}", bearer_token=token)

    def list_customer_transactions(self, token: str, customer_id: int) -> list[dict[str, Any]]:
        response = self.request_json("GET", f"/api/customers/{customer_id}/transactions", bearer_token=token)
        transactions = response.get("transactions")
        if not isinstance(transactions, list):
            raise ServiceMumbleError("transactions response is missing transactions list")
        return transactions

    def list_alerts(self, token: str) -> list[dict[str, Any]]:
        response = self.request_json("GET", "/api/alerts/queue", bearer_token=token)
        alerts = response.get("alerts")
        if not isinstance(alerts, list):
            raise ServiceMumbleError("alerts response is missing alerts list")
        return alerts

    def claim_alert(self, token: str, alert_id: int) -> dict[str, Any]:
        return self.request_json("POST", f"/api/alerts/{alert_id}/claim", bearer_token=token)

    def create_case(self, token: str, alert_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/api/alerts/{alert_id}/case",
            payload,
            token,
            expected_statuses=(201,),
        )

    def create_case_note(self, token: str, case_id: int, body: str) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/api/cases/{case_id}/notes",
            {"visibility": "private", "body": body},
            token,
            expected_statuses=(201,),
        )

    def list_case_notes(self, token: str, case_id: int) -> list[dict[str, Any]]:
        response = self.request_json("GET", f"/api/cases/{case_id}/notes", bearer_token=token)
        notes = response.get("notes")
        if not isinstance(notes, list):
            raise ServiceMumbleError("case notes response is missing notes list")
        return notes

    def list_duplicate_candidates(self, token: str, case_id: int) -> list[dict[str, Any]]:
        response = self.request_json("GET", f"/api/cases/{case_id}/duplicates", bearer_token=token)
        candidates = response.get("candidates")
        if not isinstance(candidates, list):
            raise ServiceMumbleError("duplicates response is missing candidates list")
        return candidates

    def list_case_timeline(self, token: str, case_id: int) -> list[dict[str, Any]]:
        response = self.request_json("GET", f"/api/cases/{case_id}/timeline", bearer_token=token)
        events = response.get("events")
        if not isinstance(events, list):
            raise ServiceMumbleError("timeline response is missing events list")
        return events

    def get_duplicate_merge_preview(self, token: str, source_case_id: int, duplicate_case_id: int) -> dict[str, Any]:
        return self.request_json(
            "GET",
            f"/api/cases/{source_case_id}/duplicates/{duplicate_case_id}/merge-preview",
            bearer_token=token,
        )

    def get_graph_entity(self, token: str, entity_hint: str) -> dict[str, Any]:
        return self.request_json("GET", f"/api/graph/entities/{_url_parse.quote(entity_hint, safe='')}", bearer_token=token)

    def list_graph_related_cases(self, token: str, entity_hint: str) -> list[dict[str, Any]]:
        response = self.request_json(
            "GET",
            f"/api/graph/entities/{_url_parse.quote(entity_hint, safe='')}/related-cases",
            bearer_token=token,
        )
        cases = response.get("cases")
        if not isinstance(cases, list):
            raise ServiceMumbleError("graph related-cases response is missing cases list")
        return cases

    def create_edd_record(self, token: str, customer_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/api/customers/{customer_id}/edd",
            payload,
            token,
            expected_statuses=(201,),
        )

    def get_edd_record(self, token: str, customer_id: int) -> dict[str, Any]:
        return self.request_json("GET", f"/api/customers/{customer_id}/edd", bearer_token=token)

    def create_case_export(self, token: str, case_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request_json(
            "POST",
            f"/api/cases/{case_id}/exports",
            payload,
            token,
            expected_statuses=(201,),
        )

    def get_export(self, token: str, export_id: int) -> dict[str, Any]:
        return self.request_json("GET", f"/api/exports/{export_id}", bearer_token=token)

    def list_network_rooms(self, token: str) -> list[dict[str, Any]]:
        response = self.request_json("GET", "/api/network/rooms", bearer_token=token)
        rooms = response.get("rooms")
        if not isinstance(rooms, list):
            raise ServiceMumbleError("network-room response is missing rooms list")
        return rooms

    def get_network_room_dossier(self, token: str, room_id: int) -> dict[str, Any]:
        return self.request_json("GET", f"/api/network/rooms/{room_id}/dossier", bearer_token=token)


def check_subchecks() -> dict[str, CheckSubcheck]:
    return {
        "health": CheckSubcheck("health", "health endpoint responds", _check_health),
        "check_basic": CheckSubcheck(
            "check_basic",
            "auth, customer, account, transaction, and readback APIs work",
            _check_basic,
        ),
        "check_case_notes": CheckSubcheck(
            "check_case_notes",
            "owner case-note creation and readback APIs work",
            _check_case_notes,
        ),
        "check_edd": CheckSubcheck(
            "check_edd",
            "owner EDD creation and confidential-comment readback APIs work",
            _check_edd,
        ),
        "check_dedup": CheckSubcheck(
            "check_dedup",
            "secure duplicate candidate and merge-preview APIs work",
            _check_dedup,
        ),
        "check_audit": CheckSubcheck(
            "check_audit",
            "owner audit timeline exists and redacts sensitive changes",
            _check_audit,
        ),
        "check_graph": CheckSubcheck(
            "check_graph",
            "secure graph entity and related-case DTOs work",
            _check_graph,
        ),
        "check_export": CheckSubcheck(
            "check_export",
            "secure case export creation and redacted retrieval work",
            _check_export,
        ),
        "check_network_room": CheckSubcheck(
            "check_network_room",
            "secure network-room summary and dossier APIs work",
            _check_network_room,
        ),
        "check_retention": CheckSubcheck(
            "check_retention",
            "retention-sensitive flag stores have no premature physical delete path",
            _check_retention,
        ),
        "auth_customer": CheckSubcheck("auth_customer", "legacy alias for check_basic", _check_basic),
    }


def run_check(
    host: str,
    subchecks: Iterable[str] = DEFAULT_CHECK_SUBCHECKS,
    secret: str | None = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> list[str]:
    client = SentinelAMLClient(host, timeout=timeout)
    return run_check_subchecks(client, subchecks, secret or checker_secret(), context=new_check_run_context("check"))


def run_havoc(
    host: str,
    subchecks: Iterable[str] = DEFAULT_CHECK_SUBCHECKS,
    secret: str | None = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> list[str]:
    client = SentinelAMLClient(host, timeout=timeout)
    return run_check_subchecks(client, subchecks, secret or checker_secret(), context=new_check_run_context("havoc"))


def run_check_subchecks(
    client: SentinelAMLClient,
    subchecks: Iterable[str],
    secret: str,
    context: CheckRunContext | None = None,
    registry: dict[str, CheckSubcheck] | None = None,
) -> list[str]:
    available = check_subchecks() if registry is None else registry
    context = context or new_check_run_context("check")
    completed: list[str] = []
    failures: list[str] = []
    exit_code = EXIT_MUMBLE
    for name in subchecks:
        subcheck = available.get(name)
        if subcheck is None:
            failures.append(f"{name}: unsupported subcheck")
            continue
        try:
            subcheck.runner(client, secret, context)
            completed.append(name)
        except ServiceDownError as exc:
            failures.append(f"{name}: {safe_error_message(exc)}")
            exit_code = EXIT_DOWN
        except CheckerError as exc:
            failures.append(f"{name}: {safe_error_message(exc)}")
        except Exception as exc:
            failures.append(f"{name}: {safe_error_message(exc)}")
    if failures:
        raise CheckFailedError(failures, exit_code=exit_code)
    return completed


def new_check_run_context(mode: str) -> CheckRunContext:
    if mode not in {"check", "havoc"}:
        raise ValueError("unsupported check run mode")
    return CheckRunContext(mode=mode, run_id=secrets.token_hex(16))


def _check_health(client: SentinelAMLClient, _secret: str, _context: CheckRunContext) -> None:
    client.health()


def _check_basic(client: SentinelAMLClient, secret: str, context: CheckRunContext) -> None:
    fixture = _check_fixture_values(client.base_url, "basic", secret, context)
    token = _register_or_login(client, fixture["username"], fixture["password"])
    customer = client.create_customer(token, _check_customer_payload(fixture, risk_level="low"))
    _require_int(customer, "id")
    _require_str(customer, "entity_hint")
    customer_id = _require_int(customer, "id")

    read_customer = client.get_customer(token, customer_id)
    if _require_int(read_customer, "id") != customer_id:
        raise ServiceMumbleError("CHECK customer readback id mismatch")

    account = client.create_account(token, customer_id, {"iban_like": fixture["iban_like"], "currency": "USD"})
    account_id = _require_int(account, "id")
    accounts = client.list_customer_accounts(token, customer_id)
    if not any(account_item.get("id") == account_id and account_item.get("customer_id") == customer_id for account_item in accounts):
        raise ServiceMumbleError("CHECK account readback missing created account")

    transaction = client.create_transaction(
        token,
        {
            "account_id": account_id,
            "counterparty_name": "Checker Basic Counterparty",
            "counterparty_country": "US",
            "counterparty_fingerprint": fixture["counterparty_fingerprint"],
            "amount": "125.25",
            "currency": "USD",
            "direction": "outbound",
            "purpose": "invoice",
            "trace_id": fixture["trace_id"],
        },
    )
    transaction_id = _require_int(transaction, "id")
    read_transaction = client.get_transaction(token, transaction_id)
    if _require_int(read_transaction, "id") != transaction_id:
        raise ServiceMumbleError("CHECK transaction readback id mismatch")
    transactions = client.list_customer_transactions(token, customer_id)
    if not any(item.get("id") == transaction_id and item.get("account_id") == account_id for item in transactions):
        raise ServiceMumbleError("CHECK customer transaction readback missing created transaction")


def _check_case_notes(client: SentinelAMLClient, secret: str, context: CheckRunContext) -> None:
    fixture = _check_fixture_values(client.base_url, "case-notes", secret, context)
    token = _register_or_login(client, fixture["username"], fixture["password"])
    created = _create_check_case(client, token, fixture, fixture["dedup_hint"])
    note_body = fixture["note_body"]
    note = client.create_case_note(token, created["case_id"], note_body)
    note_id = _require_int(note, "id")
    notes = client.list_case_notes(token, created["case_id"])
    if not any(
        note_item.get("id") == note_id and note_item.get("case_id") == created["case_id"] and note_item.get("body") == note_body
        for note_item in notes
    ):
        raise ServiceMumbleError("CHECK case-note readback missing created note")


def _check_edd(client: SentinelAMLClient, secret: str, context: CheckRunContext) -> None:
    fixture = _check_fixture_values(client.base_url, "edd", secret, context)
    token = _register_or_login(client, fixture["username"], fixture["password"])
    customer = client.create_customer(token, _check_customer_payload(fixture, risk_level="medium"))
    customer_id = _require_int(customer, "id")
    record = client.create_edd_record(
        token,
        customer_id,
        {
            "source_of_funds": fixture["source_of_funds"],
            "risk_rationale": fixture["risk_rationale"],
            "confidential_comment": fixture["confidential_comment"],
            "review_status": "IN_REVIEW",
        },
    )
    record_id = _require_int(record, "id")
    if _require_int(record, "customer_id") != customer_id:
        raise ServiceMumbleError("CHECK EDD create customer mismatch")
    if record.get("confidential_comment") != fixture["confidential_comment"]:
        raise ServiceMumbleError("CHECK EDD confidential comment create mismatch")

    fetched = client.get_edd_record(token, customer_id)
    if _require_int(fetched, "id") != record_id or _require_int(fetched, "customer_id") != customer_id:
        raise ServiceMumbleError("CHECK EDD readback identity mismatch")
    if fetched.get("confidential_comment") != fixture["confidential_comment"]:
        raise ServiceMumbleError("CHECK EDD readback missing confidential comment")


def _check_dedup(client: SentinelAMLClient, secret: str, context: CheckRunContext) -> None:
    source_fixture = _check_fixture_values(client.base_url, "dedup-source", secret, context)
    candidate_fixture = _check_fixture_values(client.base_url, "dedup-candidate", secret, context)
    shared_dedup_hint = source_fixture["dedup_hint"]
    token = _register_or_login(client, source_fixture["username"], source_fixture["password"])
    source = _create_check_case(client, token, source_fixture, shared_dedup_hint)
    candidate = _create_check_case(client, token, candidate_fixture, shared_dedup_hint)

    candidates = client.list_duplicate_candidates(token, source["case_id"])
    matching = [item for item in candidates if item.get("case_id") == candidate["case_id"]]
    if not matching:
        raise ServiceMumbleError("CHECK dedup candidate missing")
    _assert_dedup_candidate_public_only(matching[0], expected_case_id=candidate["case_id"])

    preview = client.get_duplicate_merge_preview(token, source["case_id"], candidate["case_id"])
    if preview.get("source_case_id") != source["case_id"]:
        raise ServiceMumbleError("CHECK merge-preview source case mismatch")
    preview_candidate = preview.get("candidate")
    if not isinstance(preview_candidate, dict):
        raise ServiceMumbleError("CHECK merge-preview candidate is missing")
    _assert_dedup_candidate_public_only(preview_candidate, expected_case_id=candidate["case_id"])


def _check_audit(client: SentinelAMLClient, secret: str, context: CheckRunContext) -> None:
    fixture = _check_fixture_values(client.base_url, "audit", secret, context)
    token = _register_or_login(client, fixture["username"], fixture["password"])
    created = _create_check_case(client, token, fixture, fixture["dedup_hint"])
    note_body = fixture["note_body"]
    client.create_case_note(token, created["case_id"], note_body)

    timeline = client.list_case_timeline(token, created["case_id"])
    if not timeline:
        raise ServiceMumbleError("CHECK audit timeline is empty")

    note_events = [
        event
        for event in timeline
        if event.get("object_type") == "case_note" or "note" in str(event.get("public_message", "")).lower()
    ]
    if not note_events:
        raise ServiceMumbleError("CHECK audit timeline missing case-note event")
    for event in timeline:
        _assert_audit_event_public_only(event, private_sentinel=note_body)
    if not any(_event_has_redacted_change(event) for event in note_events):
        raise ServiceMumbleError("CHECK audit timeline missing redacted note change")


def _check_graph(client: SentinelAMLClient, secret: str, context: CheckRunContext) -> None:
    first_fixture = _check_fixture_values(client.base_url, "graph-source", secret, context)
    second_fixture = _check_fixture_values(client.base_url, "graph-related", secret, context)
    shared_entity_hint = first_fixture["entity_hint"]
    token = _register_or_login(client, first_fixture["username"], first_fixture["password"])

    first = _create_check_case(client, token, first_fixture, first_fixture["dedup_hint"], entity_hint=shared_entity_hint)
    second = _create_check_case(client, token, second_fixture, second_fixture["dedup_hint"], entity_hint=shared_entity_hint)

    summary = client.get_graph_entity(token, shared_entity_hint)
    _assert_graph_entity_public_only(summary, expected_entity_hint=shared_entity_hint, min_customer_count=2, min_case_count=2)

    related_cases = client.list_graph_related_cases(token, shared_entity_hint)
    for related in related_cases:
        _assert_graph_related_case_public_only(related, expected_entity_hint=shared_entity_hint)
    related_case_ids = {case.get("case_id") for case in related_cases}
    if first["case_id"] not in related_case_ids or second["case_id"] not in related_case_ids:
        raise ServiceMumbleError("CHECK graph related cases missing created cases")


def _check_export(client: SentinelAMLClient, secret: str, context: CheckRunContext) -> None:
    fixture = _check_fixture_values(client.base_url, "export", secret, context)
    token = _register_or_login(client, fixture["username"], fixture["password"])
    created = _create_check_case(client, token, fixture, fixture["dedup_hint"])
    note_body = fixture["note_body"]
    client.create_case_note(token, created["case_id"], note_body)
    client.create_edd_record(
        token,
        created["customer_id"],
        {
            "source_of_funds": fixture["source_of_funds"],
            "risk_rationale": fixture["risk_rationale"],
            "confidential_comment": fixture["confidential_comment"],
            "review_status": "IN_REVIEW",
        },
    )

    request = {
        "purpose": "case_review",
        "allowed_scopes": ["root_case", "linked_cases", "audit_summary", "edd_summary", "item_metadata"],
    }
    created_export = client.create_case_export(token, created["case_id"], request)
    export_id = _require_int(created_export, "id")
    _assert_export_public_only(created_export, created["case_id"], private_sentinels=(note_body, fixture["confidential_comment"]))

    fetched_export = client.get_export(token, export_id)
    if _require_int(fetched_export, "id") != export_id:
        raise ServiceMumbleError("CHECK export readback id mismatch")
    _assert_export_public_only(fetched_export, created["case_id"], private_sentinels=(note_body, fixture["confidential_comment"]))


def _check_network_room(client: SentinelAMLClient, secret: str, context: CheckRunContext) -> None:
    first_fixture = _check_fixture_values(client.base_url, "network-source", secret, context)
    second_fixture = _check_fixture_values(client.base_url, "network-related", secret, context)
    shared_entity_hint = first_fixture["entity_hint"]
    token = _register_or_login(client, first_fixture["username"], first_fixture["password"])

    first = _create_check_case(client, token, first_fixture, first_fixture["dedup_hint"], entity_hint=shared_entity_hint)
    second = _create_check_case(client, token, second_fixture, second_fixture["dedup_hint"], entity_hint=shared_entity_hint)

    room = _wait_for_network_room(
        client,
        token,
        expected_entity_hint=shared_entity_hint,
        min_case_count=2,
    )
    room_id = _require_int(room, "id")

    dossier = client.get_network_room_dossier(token, room_id)
    _assert_network_dossier_public_only(dossier, expected_entity_hint=shared_entity_hint, expected_case_ids={first["case_id"], second["case_id"]})


def _wait_for_network_room(
    client: SentinelAMLClient,
    token: str,
    *,
    expected_entity_hint: str,
    min_case_count: int,
    wait_seconds: float = NETWORK_ROOM_WAIT_SECONDS,
    poll_seconds: float = NETWORK_ROOM_POLL_SECONDS,
) -> dict[str, Any]:
    deadline = time.monotonic() + wait_seconds
    last_error = "CHECK network-room summary missing"
    while True:
        rooms = client.list_network_rooms(token)
        matching_rooms = [
            room
            for room in rooms
            if room.get("entity_hint") == expected_entity_hint and room.get("typology_hint") == "counterparty-watchlist"
        ]
        if matching_rooms:
            room = matching_rooms[0]
            try:
                _assert_network_room_summary_public_only(room, expected_entity_hint=expected_entity_hint, min_case_count=min_case_count)
                return room
            except ServiceMumbleError as exc:
                last_error = str(exc)
        if time.monotonic() >= deadline:
            raise ServiceMumbleError(f"{last_error} after bounded wait")
        time.sleep(poll_seconds)


def _check_retention(_client: SentinelAMLClient, _secret: str, _context: CheckRunContext) -> None:
    issues = retention_smoke_check()
    if issues:
        raise ServiceMumbleError("CHECK retention smoke failed")


def _create_check_case(
    client: SentinelAMLClient,
    token: str,
    fixture: dict[str, str],
    dedup_hint: str,
    entity_hint: str | None = None,
) -> dict[str, int]:
    customer_payload = _check_customer_payload(fixture, risk_level="medium")
    if entity_hint is not None:
        customer_payload["entity_hint"] = entity_hint
    customer = client.create_customer(token, customer_payload)
    customer_id = _require_int(customer, "id")
    account = client.create_account(token, customer_id, {"iban_like": fixture["iban_like"], "currency": "USD"})
    account_id = _require_int(account, "id")
    transaction = client.create_transaction(
        token,
        {
            "account_id": account_id,
            "counterparty_name": "Checker Review Counterparty",
            "counterparty_country": "GB",
            "counterparty_fingerprint": fixture["counterparty_fingerprint"],
            "amount": "60000.00",
            "currency": "USD",
            "direction": "outbound",
            "purpose": "invoice",
            "trace_id": fixture["trace_id"],
        },
    )
    transaction_id = _require_int(transaction, "id")
    alert = _find_alert_for_transaction(client.list_alerts(token), transaction_id)
    alert_id = _require_int(alert, "id")
    client.claim_alert(token, alert_id)
    investigation_case = client.create_case(
        token,
        alert_id,
        {"public_summary": fixture["public_summary"], "dedup_hint": dedup_hint},
    )
    case_id = _require_int(investigation_case, "id")
    return {
        "customer_id": customer_id,
        "account_id": account_id,
        "transaction_id": transaction_id,
        "alert_id": alert_id,
        "case_id": case_id,
    }


def normalize_base_url(host: str) -> str:
    host = host.strip()
    if not host:
        raise ValueError("host is required")
    if "://" not in host:
        if ":" not in host:
            host = host + ":8081"
        host = "http://" + host
    return host.rstrip("/")


def decode_json_body(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServiceMumbleError("response body is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ServiceMumbleError("response body must be a JSON object")
    return decoded


def place1_put(host: str, flag: str, secret: str | None = None, timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS) -> Place1PutResult:
    secret = secret or checker_secret()
    idempotency_key = derive_idempotency_key(flag, PLACE_1, secret)
    fixture = _place1_fixture_values(idempotency_key, secret)
    client = SentinelAMLClient(host, timeout=timeout)

    token = _register_or_login(client, fixture["username"], fixture["password"])
    customer = client.create_customer(
        token,
        {
            "display_name": fixture["customer_name"],
            "customer_type": "organization",
            "country": "US",
            "registration_number": fixture["registration_number"],
            "risk_level": "medium",
            "entity_hint": fixture["entity_hint"],
        },
    )
    customer_id = _require_int(customer, "id")

    account = client.create_account(
        token,
        customer_id,
        {"iban_like": fixture["iban_like"], "currency": "USD"},
    )
    account_id = _require_int(account, "id")

    transaction = client.create_transaction(
        token,
        {
            "account_id": account_id,
            "counterparty_name": "Globex Compliance Desk",
            "counterparty_country": "GB",
            "counterparty_fingerprint": fixture["counterparty_fingerprint"],
            "amount": "60000.00",
            "currency": "USD",
            "direction": "outbound",
            "purpose": "invoice",
            "trace_id": fixture["trace_id"],
        },
    )
    transaction_id = _require_int(transaction, "id")

    alert = _find_alert_for_transaction(client.list_alerts(token), transaction_id)
    alert_id = _require_int(alert, "id")
    client.claim_alert(token, alert_id)
    typology_hint = _require_str(alert, "typology_hint")

    case_payload = {"public_summary": fixture["public_summary"], "dedup_hint": fixture["dedup_hint"]}
    investigation_case = client.create_case(token, alert_id, case_payload)
    case_id = _require_int(investigation_case, "id")
    note = client.create_case_note(token, case_id, flag)
    note_id = _require_int(note, "id")

    state = Place1PrivateState(
        schema_version=PRIVATE_STATE_SCHEMA_VERSION,
        service=SERVICE_NAME,
        store=PLACE_1_STORE,
        place=PLACE_1,
        customer_id=customer_id,
        case_id=case_id,
        note_id=note_id,
        entity_hint=fixture["entity_hint"],
        dedup_hint=fixture["dedup_hint"],
        typology_hint=typology_hint,
        idempotency_key=idempotency_key,
    )
    public_attack_data = public_attack_data_for_place1(state)
    assert_public_attack_data_safe(public_attack_data)
    return Place1PutResult(encode_private_state(state, secret), public_attack_data)


def place1_get(host: str, private_state: str, flag: str, secret: str | None = None, timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS) -> None:
    secret = secret or checker_secret()
    state = decode_private_state(private_state, secret, expected_place=PLACE_1)
    if not isinstance(state, Place1PrivateState):
        raise StateIntegrityError("private state place mismatch")
    expected_key = derive_idempotency_key(flag, state.place, secret)
    if not hmac.compare_digest(state.idempotency_key, expected_key):
        raise StateIntegrityError("private state does not match requested flag/place")

    client = SentinelAMLClient(host, timeout=timeout)
    fixture = _place1_fixture_values(state.idempotency_key, secret)
    token = _login_for_token(client, fixture["username"], fixture["password"])
    try:
        notes = client.list_case_notes(token, state.case_id)
    except HTTPStatusError as exc:
        if exc.status == 404:
            raise ServiceCorruptError("place 1 case or note view was not found") from exc
        raise

    for note in notes:
        if note.get("id") == state.note_id and note.get("case_id") == state.case_id and note.get("body") == flag:
            return
    raise ServiceCorruptError("place 1 flag was not found in case note body")


def place2_put(host: str, flag: str, secret: str | None = None, timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS) -> Place2PutResult:
    secret = secret or checker_secret()
    idempotency_key = derive_idempotency_key(flag, PLACE_2, secret)
    fixture = _place2_fixture_values(idempotency_key, secret)
    client = SentinelAMLClient(host, timeout=timeout)

    token = _register_or_login(client, fixture["username"], fixture["password"])
    customer = client.create_customer(
        token,
        {
            "display_name": fixture["customer_name"],
            "customer_type": "organization",
            "country": "US",
            "registration_number": fixture["registration_number"],
            "risk_level": "high",
            "entity_hint": fixture["entity_hint"],
        },
    )
    customer_id = _require_int(customer, "id")
    entity_hint = _require_str(customer, "entity_hint")

    edd_record = client.create_edd_record(
        token,
        customer_id,
        {
            "source_of_funds": fixture["source_of_funds"],
            "risk_rationale": fixture["risk_rationale"],
            "confidential_comment": flag,
            "review_status": "IN_REVIEW",
        },
    )
    edd_record_id = _require_int(edd_record, "id")
    edd_customer_id = _require_int(edd_record, "customer_id")
    if edd_customer_id != customer_id:
        raise ServiceMumbleError("EDD response customer_id mismatch")

    account = client.create_account(
        token,
        customer_id,
        {"iban_like": fixture["iban_like"], "currency": "USD"},
    )
    account_id = _require_int(account, "id")
    transaction = client.create_transaction(
        token,
        {
            "account_id": account_id,
            "counterparty_name": "Enhanced Review Counterparty",
            "counterparty_country": "IR",
            "counterparty_fingerprint": fixture["counterparty_fingerprint"],
            "amount": "60000.00",
            "currency": "USD",
            "direction": "outbound",
            "purpose": "enhanced diligence review",
            "trace_id": fixture["trace_id"],
        },
    )
    transaction_id = _require_int(transaction, "id")
    alert = _find_alert_for_transaction(client.list_alerts(token), transaction_id)
    alert_id = _require_int(alert, "id")
    client.claim_alert(token, alert_id)
    investigation_case = client.create_case(
        token,
        alert_id,
        {"public_summary": fixture["public_summary"], "dedup_hint": fixture["dedup_hint"]},
    )
    typology_hint = _require_str(investigation_case, "typology_hint")

    state = Place2PrivateState(
        schema_version=PRIVATE_STATE_SCHEMA_VERSION,
        service=SERVICE_NAME,
        store=PLACE_2_STORE,
        place=PLACE_2,
        customer_id=customer_id,
        edd_record_id=edd_record_id,
        entity_hint=entity_hint,
        typology_hint=typology_hint,
        idempotency_key=idempotency_key,
    )
    public_attack_data = public_attack_data_for_place2(state)
    assert_public_attack_data_safe(public_attack_data)
    return Place2PutResult(encode_private_state(state, secret), public_attack_data)


def place2_get(host: str, private_state: str, flag: str, secret: str | None = None, timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS) -> None:
    secret = secret or checker_secret()
    state = decode_private_state(private_state, secret, expected_place=PLACE_2)
    if not isinstance(state, Place2PrivateState):
        raise StateIntegrityError("private state place mismatch")
    expected_key = derive_idempotency_key(flag, state.place, secret)
    if not hmac.compare_digest(state.idempotency_key, expected_key):
        raise StateIntegrityError("private state does not match requested flag/place")

    client = SentinelAMLClient(host, timeout=timeout)
    fixture = _place2_fixture_values(state.idempotency_key, secret)
    token = _login_for_token(client, fixture["username"], fixture["password"])
    try:
        edd_record = client.get_edd_record(token, state.customer_id)
    except HTTPStatusError as exc:
        if exc.status == 404:
            raise ServiceCorruptError("place 2 EDD owner view was not found") from exc
        raise

    _verify_place2_edd_record(edd_record, state, flag)


def put_noise(
    host: str,
    seed: str | None = None,
    secret: str | None = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> NoisePutResult:
    secret = secret or checker_secret()
    client = SentinelAMLClient(host, timeout=timeout)
    idempotency_key = derive_noise_idempotency_key(client.base_url, seed, secret)
    first_fixture = _noise_fixture_values(idempotency_key, "source", secret)
    second_fixture = _noise_fixture_values(idempotency_key, "related", secret)
    shared_entity_hint = first_fixture["entity_hint"]

    token = _register_or_login(client, first_fixture["username"], first_fixture["password"])
    first = _create_check_case(client, token, first_fixture, first_fixture["dedup_hint"], entity_hint=shared_entity_hint)
    second = _create_check_case(client, token, second_fixture, second_fixture["dedup_hint"], entity_hint=shared_entity_hint)
    client.create_case_note(token, first["case_id"], first_fixture["note_body"])
    edd_record = client.create_edd_record(
        token,
        first["customer_id"],
        {
            "source_of_funds": first_fixture["source_of_funds"],
            "risk_rationale": first_fixture["risk_rationale"],
            "confidential_comment": first_fixture["confidential_comment"],
            "review_status": "IN_REVIEW",
        },
    )
    edd_record_id = _require_int(edd_record, "id")

    graph_summary = client.get_graph_entity(token, shared_entity_hint)
    _assert_graph_entity_public_only(graph_summary, expected_entity_hint=shared_entity_hint, min_customer_count=2, min_case_count=2)
    graph_related = client.list_graph_related_cases(token, shared_entity_hint)
    for related in graph_related:
        _assert_graph_related_case_public_only(related, expected_entity_hint=shared_entity_hint)

    created_export = client.create_case_export(
        token,
        first["case_id"],
        {
            "purpose": "case_review",
            "allowed_scopes": ["root_case", "linked_cases", "audit_summary", "edd_summary", "item_metadata"],
        },
    )
    export_id = _require_int(created_export, "id")
    _assert_export_public_only(created_export, first["case_id"], private_sentinels=(first_fixture["note_body"], first_fixture["confidential_comment"]))

    network_room_id = 0
    try:
        rooms = client.list_network_rooms(token)
    except HTTPStatusError as exc:
        if exc.status not in (404, 405):
            raise
    else:
        for room in rooms:
            if room.get("entity_hint") == shared_entity_hint:
                _assert_network_room_summary_public_only(room, expected_entity_hint=shared_entity_hint, min_case_count=2)
                network_room_id = _require_int(room, "id")
                break
        if network_room_id:
            dossier = client.get_network_room_dossier(token, network_room_id)
            _assert_network_dossier_public_only(dossier, expected_entity_hint=shared_entity_hint, expected_case_ids={first["case_id"], second["case_id"]})

    state = NoisePrivateState(
        schema_version=1,
        service=SERVICE_NAME,
        kind="noise",
        username=first_fixture["username"],
        password=first_fixture["password"],
        token=token,
        seed=seed or "default",
        customer_ids=[first["customer_id"], second["customer_id"]],
        case_ids=[first["case_id"], second["case_id"]],
        transaction_ids=[first["transaction_id"], second["transaction_id"]],
        edd_record_id=edd_record_id,
        export_id=export_id,
        graph_hint=shared_entity_hint,
        network_room_id=network_room_id,
        idempotency_key=idempotency_key,
    )
    public_data = public_noise_data_for_state(state)
    return NoisePutResult(encode_noise_state(state, secret), public_data)


def get_noise(host: str, noise_state: str, secret: str | None = None, timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS) -> None:
    secret = secret or checker_secret()
    state = decode_noise_state(noise_state, secret)
    client = SentinelAMLClient(host, timeout=timeout)
    token = state.token
    try:
        _verify_noise_objects(client, token, state)
    except HTTPStatusError as exc:
        if exc.status not in (401, 403):
            raise
        token = _login_for_token(client, state.username, state.password)
        _verify_noise_objects(client, token, state)


def derive_noise_idempotency_key(base_url: str, seed: str | None = None, secret: str | None = None) -> str:
    material = f"noise\x00{SERVICE_NAME}\x00{base_url}\x00{seed or 'default'}"
    return hmac_hex(secret or checker_secret(), material)


def retention_smoke_check(repo_root: Path | str | None = None) -> list[str]:
    root = Path(repo_root) if repo_root is not None else Path(__file__).resolve().parents[2]
    issues: list[str] = []
    delete_pattern = re.compile(
        r"\b(delete\s+from|truncate(?:\s+table)?|drop\s+table(?:\s+if\s+exists)?)\s+([a-z_][a-z0-9_]*)",
        re.IGNORECASE,
    )
    for dirname in RETENTION_SCAN_DIRS:
        base = root / dirname
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".sql", ".go", ".py", ".ps1"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for match in delete_pattern.finditer(text):
                table = match.group(2).lower()
                if table in RETENTION_SENSITIVE_TABLES:
                    issues.append(f"{path.relative_to(root)} deletes retention-sensitive table {table}")
    return issues


def _verify_noise_objects(client: SentinelAMLClient, token: str, state: NoisePrivateState) -> None:
    for customer_id in state.customer_ids:
        customer = client.get_customer(token, customer_id)
        if _require_int(customer, "id") != customer_id:
            raise ServiceMumbleError("noise customer readback mismatch")
    export = client.get_export(token, state.export_id)
    if _require_int(export, "id") != state.export_id:
        raise ServiceMumbleError("noise export readback mismatch")
    _assert_export_public_only(export, state.case_ids[0], private_sentinels=())
    graph_summary = client.get_graph_entity(token, state.graph_hint)
    _assert_graph_entity_public_only(graph_summary, expected_entity_hint=state.graph_hint, min_customer_count=2, min_case_count=2)
    graph_related = client.list_graph_related_cases(token, state.graph_hint)
    for related in graph_related:
        _assert_graph_related_case_public_only(related, expected_entity_hint=state.graph_hint)
    if state.network_room_id > 0:
        dossier = client.get_network_room_dossier(token, state.network_room_id)
        _assert_network_dossier_public_only(dossier, expected_entity_hint=state.graph_hint, expected_case_ids=set(state.case_ids))


def _register_or_login(client: SentinelAMLClient, username: str, password: str) -> str:
    try:
        client.register(username, password)
    except HTTPStatusError as exc:
        if exc.status != 409:
            raise
    return _login_for_token(client, username, password)


def _login_for_token(client: SentinelAMLClient, username: str, password: str) -> str:
    return _extract_token(client.login(username, password))


def _extract_token(response: dict[str, Any]) -> str:
    session = response.get("session")
    if not isinstance(session, dict):
        raise ServiceMumbleError("auth response is missing session")
    token = session.get("token")
    if not isinstance(token, str) or not token:
        raise ServiceMumbleError("auth response is missing token")
    return token


def _find_alert_for_transaction(alerts: list[dict[str, Any]], transaction_id: int) -> dict[str, Any]:
    for alert in alerts:
        if alert.get("transaction_id") == transaction_id:
            return alert
    raise ServiceMumbleError("transaction did not produce a retrievable alert")


def _require_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or value <= 0:
        raise ServiceMumbleError(f"response field {key} must be a positive integer")
    return value


def _require_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ServiceMumbleError(f"response field {key} must be a non-empty string")
    return value


def _require_list(payload: dict[str, Any], key: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ServiceMumbleError(f"response field {key} must be a list")
    return value


def _check_customer_payload(fixture: dict[str, str], risk_level: str) -> dict[str, str]:
    return {
        "display_name": fixture["customer_name"],
        "customer_type": "organization",
        "country": "US",
        "registration_number": fixture["registration_number"],
        "risk_level": risk_level,
        "entity_hint": fixture["entity_hint"],
    }


def _assert_dedup_candidate_public_only(candidate: dict[str, Any], expected_case_id: int) -> None:
    allowed = {"case_id", "public_summary", "risk_tags", "overlap_score", "match_explanation"}
    if set(candidate) != allowed:
        raise ServiceMumbleError("CHECK dedup candidate shape is not public-only")
    if candidate.get("case_id") != expected_case_id:
        raise ServiceMumbleError("CHECK dedup candidate case mismatch")
    if not isinstance(candidate.get("public_summary"), str) or not candidate["public_summary"]:
        raise ServiceMumbleError("CHECK dedup candidate public summary missing")
    _require_list(candidate, "risk_tags")
    overlap = candidate.get("overlap_score")
    if not isinstance(overlap, int) or overlap <= 0:
        raise ServiceMumbleError("CHECK dedup candidate overlap score missing")
    if not isinstance(candidate.get("match_explanation"), str) or not candidate["match_explanation"]:
        raise ServiceMumbleError("CHECK dedup candidate explanation missing")
    serialized = canonical_json(candidate).lower()
    forbidden = (
        "body",
        "confidential_comment",
        "private_notes",
        "audit",
        "diff",
        "password",
        "token",
        "session",
        "owner_user_id",
        "checker_private",
        "private_state",
        "flag",
    )
    leaked = [marker for marker in forbidden if marker in serialized]
    if leaked:
        raise ServiceMumbleError("CHECK dedup candidate includes private fields")


def _assert_audit_event_public_only(event: dict[str, Any], private_sentinel: str) -> None:
    allowed = {"id", "object_type", "object_id", "event_type", "public_message", "changes", "created_at", "visibility_scope"}
    if set(event) != allowed:
        raise ServiceMumbleError("CHECK audit event shape is not public-only")
    _require_int(event, "id")
    _require_str(event, "object_type")
    _require_int(event, "object_id")
    _require_str(event, "event_type")
    _require_str(event, "public_message")
    _require_str(event, "created_at")
    if event.get("visibility_scope") != "owner":
        raise ServiceMumbleError("CHECK audit event visibility scope mismatch")
    changes = _require_list(event, "changes")
    for change in changes:
        if not isinstance(change, dict):
            raise ServiceMumbleError("CHECK audit change shape is invalid")
        if set(change) - {"field", "old", "new", "redacted"}:
            raise ServiceMumbleError("CHECK audit change shape is not public-only")
        _require_str(change, "field")
        if not isinstance(change.get("redacted"), bool):
            raise ServiceMumbleError("CHECK audit change redaction marker missing")
        if "old" in change and not isinstance(change["old"], str):
            raise ServiceMumbleError("CHECK audit change old value must be a string")
        if "new" in change and not isinstance(change["new"], str):
            raise ServiceMumbleError("CHECK audit change new value must be a string")
    _assert_serialized_public_side_view("CHECK audit timeline", event, extra_forbidden=(private_sentinel,))


def _event_has_redacted_change(event: dict[str, Any]) -> bool:
    changes = event.get("changes")
    if not isinstance(changes, list):
        return False
    for change in changes:
        if isinstance(change, dict) and change.get("field") == "restricted_field" and change.get("redacted") is True:
            return True
    return False


def _assert_graph_entity_public_only(
    summary: dict[str, Any],
    expected_entity_hint: str,
    min_customer_count: int,
    min_case_count: int,
) -> None:
    allowed = {"entity_hint", "relation_type", "customer_count", "case_count", "highest_risk", "risk_tags", "updated_at"}
    if set(summary) != allowed:
        raise ServiceMumbleError("CHECK graph entity shape is not public-only")
    if summary.get("entity_hint") != expected_entity_hint:
        raise ServiceMumbleError("CHECK graph entity hint mismatch")
    if summary.get("relation_type") != "shared_entity_hint":
        raise ServiceMumbleError("CHECK graph relation type mismatch")
    customer_count = summary.get("customer_count")
    case_count = summary.get("case_count")
    highest_risk = summary.get("highest_risk")
    if not isinstance(customer_count, int) or customer_count < min_customer_count:
        raise ServiceMumbleError("CHECK graph customer count missing")
    if not isinstance(case_count, int) or case_count < min_case_count:
        raise ServiceMumbleError("CHECK graph case count missing")
    if not isinstance(highest_risk, int) or highest_risk <= 0:
        raise ServiceMumbleError("CHECK graph highest risk missing")
    _require_list(summary, "risk_tags")
    _require_str(summary, "updated_at")
    _assert_serialized_public_side_view("CHECK graph entity", summary)


def _assert_graph_related_case_public_only(case: dict[str, Any], expected_entity_hint: str) -> None:
    allowed = {
        "case_id",
        "customer_id",
        "entity_hint",
        "display_name",
        "country",
        "status",
        "public_summary",
        "risk_score",
        "typology_hint",
        "created_at",
        "updated_at",
    }
    if set(case) != allowed:
        raise ServiceMumbleError("CHECK graph related-case shape is not public-only")
    _require_int(case, "case_id")
    _require_int(case, "customer_id")
    if case.get("entity_hint") != expected_entity_hint:
        raise ServiceMumbleError("CHECK graph related-case entity mismatch")
    for key in ("display_name", "country", "status", "public_summary", "typology_hint", "created_at", "updated_at"):
        _require_str(case, key)
    risk_score = case.get("risk_score")
    if not isinstance(risk_score, int) or risk_score <= 0:
        raise ServiceMumbleError("CHECK graph related-case risk score missing")
    _assert_serialized_public_side_view("CHECK graph related-case", case)


def _assert_export_public_only(export: dict[str, Any], expected_case_id: int, private_sentinels: Iterable[str]) -> None:
    required = {"id", "root_case_id", "purpose", "status", "redaction_policy", "bundle", "created_at", "updated_at", "expires_at"}
    allowed = required | {"dispute_id"}
    if not required.issubset(export) or set(export) - allowed:
        raise ServiceMumbleError("CHECK export response shape is not public-only")
    _require_int(export, "id")
    if export.get("root_case_id") != expected_case_id:
        raise ServiceMumbleError("CHECK export root case mismatch")
    if export.get("purpose") != "case_review" or export.get("status") != "GENERATED":
        raise ServiceMumbleError("CHECK export status mismatch")
    if export.get("redaction_policy") != "public_redacted":
        raise ServiceMumbleError("CHECK export redaction policy mismatch")
    for key in ("created_at", "updated_at", "expires_at"):
        _require_str(export, key)
    bundle = export.get("bundle")
    if not isinstance(bundle, dict):
        raise ServiceMumbleError("CHECK export bundle missing")
    _assert_export_bundle_public_only(bundle, expected_case_id)
    _assert_serialized_public_side_view("CHECK export response", export, extra_forbidden=private_sentinels)


def _assert_export_bundle_public_only(bundle: dict[str, Any], expected_case_id: int) -> None:
    allowed = {"purpose", "redaction_policy", "generated_at", "root_case", "linked_cases", "audit_summaries", "edd_summaries", "items"}
    if set(bundle) != allowed:
        raise ServiceMumbleError("CHECK export bundle shape is not public-only")
    if bundle.get("purpose") != "case_review" or bundle.get("redaction_policy") != "public_redacted":
        raise ServiceMumbleError("CHECK export bundle policy mismatch")
    _require_str(bundle, "generated_at")
    root_case = bundle.get("root_case")
    if not isinstance(root_case, dict):
        raise ServiceMumbleError("CHECK export root case missing")
    _assert_export_case_shell_public_only(root_case, expected_case_id)
    for key in ("linked_cases", "audit_summaries", "edd_summaries", "items"):
        _require_list(bundle, key)
    for shell in bundle["linked_cases"]:
        if not isinstance(shell, dict):
            raise ServiceMumbleError("CHECK export linked case shape is invalid")
        _assert_export_case_shell_public_only(shell)
    for audit in bundle["audit_summaries"]:
        if not isinstance(audit, dict):
            raise ServiceMumbleError("CHECK export audit summary shape is invalid")
        _assert_export_audit_summary_public_only(audit)
    for edd_summary in bundle["edd_summaries"]:
        if not isinstance(edd_summary, dict):
            raise ServiceMumbleError("CHECK export EDD summary shape is invalid")
        _assert_export_edd_summary_public_only(edd_summary)
    if not bundle["items"]:
        raise ServiceMumbleError("CHECK export item metadata missing")
    for item in bundle["items"]:
        if not isinstance(item, dict):
            raise ServiceMumbleError("CHECK export item metadata shape is invalid")
        _assert_export_item_public_only(item)


def _assert_export_case_shell_public_only(shell: dict[str, Any], expected_case_id: int | None = None) -> None:
    allowed = {"case_id", "customer_id", "status", "public_summary", "risk_score", "typology_hint", "created_at", "updated_at"}
    if set(shell) != allowed:
        raise ServiceMumbleError("CHECK export case shell shape is not public-only")
    case_id = _require_int(shell, "case_id")
    if expected_case_id is not None and case_id != expected_case_id:
        raise ServiceMumbleError("CHECK export case shell mismatch")
    _require_int(shell, "customer_id")
    for key in ("status", "public_summary", "typology_hint", "created_at", "updated_at"):
        _require_str(shell, key)
    risk_score = shell.get("risk_score")
    if not isinstance(risk_score, int) or risk_score <= 0:
        raise ServiceMumbleError("CHECK export risk score missing")


def _assert_export_audit_summary_public_only(summary: dict[str, Any]) -> None:
    allowed = {"event_id", "object_type", "object_id", "event_type", "public_message", "changed_fields", "created_at"}
    if set(summary) != allowed:
        raise ServiceMumbleError("CHECK export audit summary shape is not public-only")
    _require_int(summary, "event_id")
    _require_int(summary, "object_id")
    for key in ("object_type", "event_type", "public_message", "created_at"):
        _require_str(summary, key)
    _require_list(summary, "changed_fields")


def _assert_export_edd_summary_public_only(summary: dict[str, Any]) -> None:
    allowed = {"record_id", "customer_id", "review_status", "risk_tags", "created_at", "updated_at"}
    if set(summary) != allowed:
        raise ServiceMumbleError("CHECK export EDD summary shape is not public-only")
    _require_int(summary, "record_id")
    _require_int(summary, "customer_id")
    for key in ("review_status", "created_at", "updated_at"):
        _require_str(summary, key)
    _require_list(summary, "risk_tags")


def _assert_export_item_public_only(item: dict[str, Any]) -> None:
    allowed = {"item_type", "object_type", "object_id", "relation", "redaction_policy"}
    if set(item) != allowed:
        raise ServiceMumbleError("CHECK export item metadata shape is not public-only")
    _require_int(item, "object_id")
    for key in ("item_type", "object_type", "relation", "redaction_policy"):
        _require_str(item, key)
    if item.get("redaction_policy") != "public_redacted":
        raise ServiceMumbleError("CHECK export item redaction policy mismatch")


def _assert_network_room_summary_public_only(room: dict[str, Any], expected_entity_hint: str, min_case_count: int) -> None:
    allowed = {
        "id",
        "room_key",
        "entity_hint",
        "typology_hint",
        "status",
        "public_summary",
        "public_risk_tags",
        "case_count",
        "participant_count",
        "created_at",
        "updated_at",
    }
    if set(room) != allowed:
        raise ServiceMumbleError("CHECK network-room summary shape is not public-only")
    _require_int(room, "id")
    for key in ("room_key", "typology_hint", "status", "public_summary", "created_at", "updated_at"):
        _require_str(room, key)
    if room.get("entity_hint") != expected_entity_hint:
        raise ServiceMumbleError("CHECK network-room entity mismatch")
    if room.get("typology_hint") != "counterparty-watchlist":
        raise ServiceMumbleError("CHECK network-room typology mismatch")
    case_count = room.get("case_count")
    participant_count = room.get("participant_count")
    if not isinstance(case_count, int) or case_count < min_case_count:
        raise ServiceMumbleError("CHECK network-room case count missing")
    if not isinstance(participant_count, int) or participant_count <= 0:
        raise ServiceMumbleError("CHECK network-room participant count missing")
    _require_list(room, "public_risk_tags")
    _assert_serialized_public_side_view("CHECK network-room summary", room)


def _assert_network_dossier_public_only(dossier: dict[str, Any], expected_entity_hint: str, expected_case_ids: set[int]) -> None:
    allowed = {"room", "cases", "scope_policy", "coverage_policy"}
    if set(dossier) != allowed:
        raise ServiceMumbleError("CHECK network-room dossier shape is not public-only")
    secure_policy = (
        dossier.get("scope_policy") == "case_reference_scope" and dossier.get("coverage_policy") == "summary_coverage"
    )
    detail_policy = (
        dossier.get("scope_policy") in {"network_room_collaboration_detail", "collaboration_context_detail", "participant_room_context"}
        and dossier.get("coverage_policy") in {"source_scope_materialized", "shared_case_context"}
    )
    if not secure_policy and not detail_policy:
        raise ServiceMumbleError("CHECK network-room dossier policy mismatch")
    room = dossier.get("room")
    if not isinstance(room, dict):
        raise ServiceMumbleError("CHECK network-room dossier room missing")
    _assert_network_room_summary_public_only(room, expected_entity_hint, min_case_count=len(expected_case_ids))
    cases = dossier.get("cases")
    if not isinstance(cases, list):
        raise ServiceMumbleError("CHECK network-room dossier cases missing")
    seen_case_ids: set[int] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ServiceMumbleError("CHECK network-room dossier case shape is invalid")
        if secure_policy:
            _assert_network_case_public_only(case)
        else:
            _assert_network_case_profile_compatible(case)
        seen_case_ids.add(case["case_id"])
    if not expected_case_ids.issubset(seen_case_ids):
        raise ServiceMumbleError("CHECK network-room dossier missing created case references")
    if secure_policy:
        _assert_serialized_public_side_view("CHECK network-room dossier", dossier)
    else:
        _assert_competition_network_dossier_safe(dossier)


def _assert_network_case_public_only(case: dict[str, Any]) -> None:
    allowed = {
        "case_id",
        "customer_id",
        "owned_by_requester",
        "status",
        "public_summary",
        "risk_score",
        "typology_hint",
        "public_risk_tags",
        "scope_coverage_complete",
        "created_at",
        "updated_at",
    }
    if set(case) != allowed:
        raise ServiceMumbleError("CHECK network-room case shape is not public-only")
    _require_int(case, "case_id")
    _require_int(case, "customer_id")
    for key in ("status", "public_summary", "typology_hint", "created_at", "updated_at"):
        _require_str(case, key)
    if not isinstance(case.get("owned_by_requester"), bool):
        raise ServiceMumbleError("CHECK network-room ownership marker missing")
    if case.get("scope_coverage_complete") is not True:
        raise ServiceMumbleError("CHECK network-room privacy marker missing")
    risk_score = case.get("risk_score")
    if not isinstance(risk_score, int) or risk_score <= 0:
        raise ServiceMumbleError("CHECK network-room risk score missing")
    _require_list(case, "public_risk_tags")


def _assert_network_case_profile_compatible(case: dict[str, Any]) -> None:
    base_allowed = {
        "case_id",
        "customer_id",
        "owned_by_requester",
        "status",
        "public_summary",
        "risk_score",
        "typology_hint",
        "public_risk_tags",
        "scope_coverage_complete",
        "created_at",
        "updated_at",
    }
    detail_allowed = {
        "foreign_private_notes",
        "foreign_edd_comments",
        "context_blocks",
        "assessment_blocks",
    }
    if not base_allowed.issubset(set(case)) or not set(case).issubset(base_allowed | detail_allowed):
        raise ServiceMumbleError("CHECK network-room competition case shape is invalid")
    _require_int(case, "case_id")
    _require_int(case, "customer_id")
    for key in ("status", "public_summary", "typology_hint", "created_at", "updated_at"):
        _require_str(case, key)
    if not isinstance(case.get("owned_by_requester"), bool):
        raise ServiceMumbleError("CHECK network-room competition ownership marker missing")
    if not isinstance(case.get("scope_coverage_complete"), bool):
        raise ServiceMumbleError("CHECK network-room competition privacy marker missing")
    risk_score = case.get("risk_score")
    if not isinstance(risk_score, int) or risk_score <= 0:
        raise ServiceMumbleError("CHECK network-room competition risk score missing")
    _require_list(case, "public_risk_tags")
    for key in detail_allowed:
        if key in case and not isinstance(case[key], list):
            raise ServiceMumbleError("CHECK network-room competition detail list is invalid")


def _assert_competition_network_dossier_safe(dossier: dict[str, Any]) -> None:
    serialized = canonical_json(dossier).lower()
    forbidden = (
        "password",
        "token",
        "session",
        "owner_user_id",
        "actor_user_id",
        "author_user_id",
        "assigned_to",
        "counterparty_fingerprint",
        "trace_id",
        "checker_private",
        "private_state",
        "flag",
    )
    if any(marker in serialized for marker in forbidden):
        raise ServiceMumbleError("CHECK network-room competition dossier includes private fields")


def _assert_serialized_public_side_view(name: str, payload: dict[str, Any], extra_forbidden: Iterable[str] = ()) -> None:
    serialized = canonical_json(payload).lower()
    forbidden = (
        "body",
        "confidential_comment",
        "private_notes",
        "diff_json",
        "old_hash",
        "new_hash",
        "password",
        "token",
        "session",
        "owner_user_id",
        "actor_user_id",
        "author_user_id",
        "assigned_to",
        "counterparty_fingerprint",
        "trace_id",
        "checker_private",
        "private_state",
        "flag",
    )
    leaked = [marker for marker in forbidden if marker in serialized]
    leaked.extend(marker for marker in extra_forbidden if marker and marker.lower() in serialized)
    if leaked:
        raise ServiceMumbleError(f"{name} includes private fields")


def _verify_place2_edd_record(record: dict[str, Any], state: Place2PrivateState, flag: str) -> None:
    record_id = record.get("id")
    if not isinstance(record_id, int) or record_id <= 0:
        raise ServiceCorruptError("place 2 EDD record id is missing")
    customer_id = record.get("customer_id")
    if not isinstance(customer_id, int) or customer_id <= 0:
        raise ServiceCorruptError("place 2 EDD customer id is missing")
    confidential_comment = record.get("confidential_comment")
    if not isinstance(confidential_comment, str):
        raise ServiceCorruptError("place 2 confidential comment is missing")

    if record_id != state.edd_record_id or customer_id != state.customer_id:
        raise ServiceCorruptError("place 2 EDD owner view does not match private state")
    if confidential_comment != flag:
        raise ServiceCorruptError("place 2 flag was not found in EDD confidential comment")


def _place1_fixture_values(idempotency_key: str, secret: str | None = None) -> dict[str, str]:
    short = idempotency_key[:16]
    secret = secret or checker_secret()
    return {
        "username": f"checker_p1_{short}",
        "password": hmac_hex(secret, "password:" + idempotency_key)[:32],
        "customer_name": f"Checker P1 {short}",
        "registration_number": f"SAML-CHECKER-P1-{short}",
        "entity_hint": f"checker-p1-{short}",
        "iban_like": f"SAML{short.upper()}",
        "counterparty_fingerprint": f"checker-p1-{short}-shell",
        "trace_id": f"checker-p1-{short}",
        "dedup_hint": f"checker-p1-{short}",
        "public_summary": f"Checker case p1 {short}",
    }


def _place2_fixture_values(idempotency_key: str, secret: str | None = None) -> dict[str, str]:
    short = idempotency_key[:16]
    secret = secret or checker_secret()
    return {
        "username": f"checker_p2_{short}",
        "password": hmac_hex(secret, "password:" + idempotency_key)[:32],
        "customer_name": f"Checker P2 {short}",
        "registration_number": f"SAML-CHECKER-P2-{short}",
        "entity_hint": f"checker-p2-{short}",
        "iban_like": f"SAMLP2{short.upper()[:12]}",
        "counterparty_fingerprint": f"checker-p2-{short}-enhanced-review",
        "trace_id": f"checker-p2-{short}",
        "dedup_hint": f"checker-p2-dedup-{short}",
        "public_summary": f"Checker case p2 {short}",
        "source_of_funds": f"documented operating revenue {short}",
        "risk_rationale": f"enhanced diligence typology {short}",
        "typology_hint": "high-risk-country",
    }


def _check_fixture_values(
    base_url: str,
    label: str,
    secret: str | None = None,
    context: CheckRunContext | None = None,
) -> dict[str, str]:
    secret = secret or checker_secret()
    run_id = context.run_id if context is not None else new_check_run_context("check").run_id
    check_key = hmac_hex(secret, "check:" + SERVICE_NAME + ":" + base_url + ":" + run_id + ":" + label)
    short = check_key[:16]
    fingerprint_marker = "watchlist-counterparty" if label in ("network-source", "network-related") else "counterparty"
    return {
        "username": f"checker_check_{label.replace('-', '_')}_{short}",
        "password": hmac_hex(secret, "password:" + check_key)[:32],
        "customer_name": f"Checker CHECK {label} {short}",
        "registration_number": f"SAML-CHECK-{label.upper()}-{short}",
        "entity_hint": f"checker-check-{label}-{short}",
        "iban_like": f"SAMLCHK{short.upper()[:12]}",
        "counterparty_fingerprint": f"checker-check-{label}-{short}-{fingerprint_marker}",
        "trace_id": f"checker-check-{label}-{short}",
        "dedup_hint": f"checker-check-dedup-{short}",
        "public_summary": f"Checker CHECK {label} public case {short}",
        "note_body": f"checker check nonsecret note {short}",
        "source_of_funds": f"checker documented revenue {short}",
        "risk_rationale": f"checker export diligence rationale {short}",
        "confidential_comment": f"checker check nonsecret confidential comment {short}",
    }


def _noise_fixture_values(idempotency_key: str, label: str, secret: str | None = None) -> dict[str, str]:
    secret = secret or checker_secret()
    material = hmac_hex(secret, "noise-fixture:" + idempotency_key + ":" + label)
    short = material[:16]
    return {
        "username": f"checker_noise_{idempotency_key[:10]}",
        "password": hmac_hex(secret, "noise-password:" + idempotency_key)[:32],
        "customer_name": f"Checker Noise {label} {short}",
        "registration_number": f"SAML-NOISE-{label.upper()}-{short}",
        "entity_hint": f"checker-noise-entity-{idempotency_key[:16]}",
        "iban_like": f"SAMLNOISE{short.upper()[:10]}",
        "counterparty_fingerprint": f"checker-noise-{label}-{short}-counterparty",
        "trace_id": f"checker-noise-{label}-{short}",
        "dedup_hint": f"checker-noise-dedup-{short}",
        "public_summary": f"Checker noise {label} public case {short}",
        "note_body": f"checker noise nonsecret note {short}",
        "source_of_funds": f"checker noise documented revenue {short}",
        "risk_rationale": f"checker noise diligence rationale {short}",
        "confidential_comment": f"checker noise nonsecret confidential comment {short}",
    }
