import base64
import contextlib
import hashlib
import hmac
import importlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER_DIR = ROOT / "checkers" / "sentinel_aml"
sys.path.insert(0, str(CHECKER_DIR))

import checker  # noqa: E402
import checker_lib  # noqa: E402


SECRET = "unit-test-checker-secret"


def sample_state() -> checker_lib.Place1PrivateState:
    return checker_lib.Place1PrivateState(
        schema_version=checker_lib.PRIVATE_STATE_SCHEMA_VERSION,
        service=checker_lib.SERVICE_NAME,
        store=checker_lib.PLACE_1_STORE,
        place=checker_lib.PLACE_1,
        customer_id=123,
        case_id=456,
        note_id=789,
        entity_hint="checker-p1-entity",
        dedup_hint="checker-p1-dedup",
        typology_hint="large-value-transfer",
        idempotency_key=checker_lib.derive_idempotency_key("FLAG{unit}", checker_lib.PLACE_1, SECRET),
    )


def sample_place2_state() -> checker_lib.Place2PrivateState:
    return checker_lib.Place2PrivateState(
        schema_version=checker_lib.PRIVATE_STATE_SCHEMA_VERSION,
        service=checker_lib.SERVICE_NAME,
        store=checker_lib.PLACE_2_STORE,
        place=checker_lib.PLACE_2,
        customer_id=321,
        edd_record_id=654,
        entity_hint="checker-p2-entity",
        typology_hint="enhanced-due-diligence",
        idempotency_key=checker_lib.derive_idempotency_key("FLAG{unit-p2}", checker_lib.PLACE_2, SECRET),
    )


def sample_noise_state() -> checker_lib.NoisePrivateState:
    return checker_lib.NoisePrivateState(
        schema_version=1,
        service=checker_lib.SERVICE_NAME,
        kind="noise",
        username="checker_noise_owner",
        password="noise-password",
        token="noise-token",
        seed="noise-seed",
        customer_ids=[101, 102],
        case_ids=[201, 202],
        transaction_ids=[301, 302],
        edd_record_id=401,
        export_id=501,
        graph_hint="checker-noise-entity",
        network_room_id=601,
        idempotency_key=checker_lib.derive_noise_idempotency_key("http://example.test", "noise-seed", SECRET),
    )


class CheckerFoundationTest(unittest.TestCase):
    def test_private_state_round_trip(self):
        state = sample_state()
        encoded = checker_lib.encode_private_state(state, SECRET)
        decoded = checker_lib.decode_private_state(encoded, SECRET)

        self.assertEqual(decoded, state)
        payload = decode_payload(encoded)
        self.assertFalse({"username", "password", "token"} & set(payload))

    def test_place2_private_state_round_trip(self):
        state = sample_place2_state()
        encoded = checker_lib.encode_private_state(state, SECRET)
        decoded = checker_lib.decode_private_state(encoded, SECRET, expected_place=checker_lib.PLACE_2)

        self.assertEqual(decoded, state)
        payload = decode_payload(encoded)
        self.assertFalse({"username", "password", "token"} & set(payload))

    def test_private_state_tamper_rejected(self):
        encoded = checker_lib.encode_private_state(sample_state(), SECRET)
        envelope = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8"))
        envelope["payload"]["case_id"] = 457
        tampered = base64.urlsafe_b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")

        with self.assertRaises(checker_lib.StateIntegrityError):
            checker_lib.decode_private_state(tampered, SECRET)

    def test_place2_private_state_tamper_rejected(self):
        encoded = checker_lib.encode_private_state(sample_place2_state(), SECRET)
        envelope = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8"))
        envelope["payload"]["edd_record_id"] = 655
        tampered = base64.urlsafe_b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")

        with self.assertRaises(checker_lib.StateIntegrityError):
            checker_lib.decode_private_state(tampered, SECRET)

    def test_noise_state_round_trip(self):
        state = sample_noise_state()
        encoded = checker_lib.encode_noise_state(state, SECRET)
        decoded = checker_lib.decode_noise_state(encoded, SECRET)

        self.assertEqual(decoded, state)
        self.assertNotIn("noise-password", encoded)
        self.assertNotIn("noise-token", encoded)

    def test_noise_state_tamper_rejected(self):
        encoded = checker_lib.encode_noise_state(sample_noise_state(), SECRET)
        envelope = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8"))
        envelope["payload"]["export_id"] = 502
        tampered = base64.urlsafe_b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")

        with self.assertRaises(checker_lib.StateIntegrityError):
            checker_lib.decode_noise_state(tampered, SECRET)

    def test_place_store_mismatch_rejected(self):
        state = sample_place2_state()
        payload = dataclass_payload(state)
        payload["store"] = checker_lib.PLACE_1_STORE
        mac = checker_lib.hmac_hex(SECRET, checker_lib.canonical_json(payload))
        encoded = encode_envelope(payload, mac)

        with self.assertRaises(checker_lib.StateIntegrityError):
            checker_lib.decode_private_state(encoded, SECRET)

    def test_place1_state_passed_to_place2_is_rejected(self):
        encoded = checker_lib.encode_private_state(sample_state(), SECRET)

        with self.assertRaises(checker_lib.StateIntegrityError):
            checker_lib.decode_private_state(encoded, SECRET, expected_place=checker_lib.PLACE_2)

    def test_place2_state_passed_to_place1_is_rejected(self):
        encoded = checker_lib.encode_private_state(sample_place2_state(), SECRET)

        with self.assertRaises(checker_lib.StateIntegrityError):
            checker_lib.decode_private_state(encoded, SECRET, expected_place=checker_lib.PLACE_1)

    def test_malformed_place2_private_state_rejected(self):
        payload = dataclass_payload(sample_place2_state())
        payload.pop("edd_record_id")
        mac = checker_lib.hmac_hex(SECRET, checker_lib.canonical_json(payload))

        with self.assertRaises(checker_lib.StateIntegrityError):
            checker_lib.decode_private_state(encode_envelope(payload, mac), SECRET)

    def test_public_attack_data_excludes_credentials_and_private_material(self):
        for state, public, expected_fields, flag in (
            (
                sample_state(),
                checker_lib.public_attack_data_for_place1(sample_state()),
                {
                    "service",
                    "store",
                    "case_ref",
                    "case_id",
                    "customer_ref",
                    "customer_id",
                    "entity_hint",
                    "entity_ref",
                    "party_ref",
                    "dedup_hint",
                    "typology_hint",
                    "matching_reference",
                },
                "FLAG{unit}",
            ),
            (
                sample_place2_state(),
                checker_lib.public_attack_data_for_place2(sample_place2_state()),
                {"service", "store", "customer_ref", "customer_id", "entity_hint", "entity_ref", "party_ref", "typology_hint"},
                "FLAG{unit-p2}",
            ),
        ):
            with self.subTest(place=state.place):
                checker_lib.assert_public_attack_data_safe(public)
                serialized = checker_lib.canonical_json(public).lower()

                for forbidden in (
                    "username",
                    "password",
                    "token",
                    "session",
                    "flag",
                    SECRET.lower(),
                    "private_state",
                    flag.lower(),
                ):
                    self.assertNotIn(forbidden, serialized)
                self.assertEqual(set(public), expected_fields)

    def test_shared_public_attack_data_builder_preserves_place1_behavior(self):
        state = sample_state()
        self.assertEqual(
            checker_lib.public_attack_data_for_state(state),
            {
                "service": checker_lib.SERVICE_NAME,
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
                "store": "case_note",
            },
        )

    def test_shared_public_attack_data_builder_supports_place2(self):
        state = sample_place2_state()
        self.assertEqual(
            checker_lib.public_attack_data_for_state(state),
            {
                "service": checker_lib.SERVICE_NAME,
                "store": "edd",
                "customer_ref": f"customer-{state.customer_id}",
                "customer_id": state.customer_id,
                "entity_hint": state.entity_hint,
                "entity_ref": state.entity_hint,
                "party_ref": state.entity_hint,
                "typology_hint": state.typology_hint,
            },
        )

    def test_public_attack_data_rejects_secret_markers(self):
        for public in (
            {"service": checker_lib.SERVICE_NAME, "username": "checker_owner"},
            {"service": checker_lib.SERVICE_NAME, "password": "owner-password"},
            {"service": checker_lib.SERVICE_NAME, "token": "owner-token"},
            {"service": checker_lib.SERVICE_NAME, "session": {"token": "owner-token"}},
            {"service": checker_lib.SERVICE_NAME, "private_state": "encoded-state"},
            {"service": checker_lib.SERVICE_NAME, "locator": "FLAG{leak}"},
        ):
            with self.subTest(public=public):
                with self.assertRaises(ValueError):
                    checker_lib.assert_public_attack_data_safe(public)

    def test_noise_public_data_excludes_credentials_flags_and_private_material(self):
        state = sample_noise_state()
        public = checker_lib.public_noise_data_for_state(state)

        serialized = checker_lib.canonical_json(public).lower()
        for forbidden in (
            "username",
            "password",
            "token",
            "session",
            "flag",
            "private_state",
            "confidential_comment",
            "body",
            state.username.lower(),
            state.password.lower(),
            state.token.lower(),
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(
            set(public),
            {"service", "kind", "customer_ids", "case_ids", "transaction_ids", "edd_record_id", "export_id", "graph_hint", "network_room_id"},
        )

    def test_place1_public_attack_data_shape_is_unchanged(self):
        state = sample_state()
        public = checker_lib.public_attack_data_for_place1(state)
        checker_lib.assert_public_attack_data_safe(public)
        self.assertEqual(
            set(public),
            {
                "service",
                "case_ref",
                "case_id",
                "customer_ref",
                "customer_id",
                "entity_hint",
                "entity_ref",
                "party_ref",
                "dedup_hint",
                "typology_hint",
                "matching_reference",
                "store",
            },
        )

    def test_place2_checker_args_dispatch_to_supported_place(self):
        parsed_put = checker_lib.parse_checker_args(["checker.py", "put", "127.0.0.1", "FLAG{unit}", "2"])
        parsed_get = checker_lib.parse_checker_args(["checker.py", "get", "127.0.0.1", "state", "FLAG{unit}", "2"])

        self.assertEqual(parsed_put.place, checker_lib.PLACE_2)
        self.assertEqual(parsed_get.place, checker_lib.PLACE_2)

    def test_noise_checker_args_dispatch(self):
        parsed_put = checker_lib.parse_checker_args(["checker.py", "putnoise", "127.0.0.1", "round-7"])
        parsed_get = checker_lib.parse_checker_args(["checker.py", "getnoise", "127.0.0.1", "noise-state"])

        self.assertEqual(parsed_put.action, "putnoise")
        self.assertEqual(parsed_put.seed, "round-7")
        self.assertEqual(parsed_get.action, "getnoise")
        self.assertEqual(parsed_get.private_state, "noise-state")

    def test_unsupported_place_values_fail_closed_before_http(self):
        with self.assertRaises(checker_lib.UnsupportedPlaceError):
            checker_lib.parse_checker_args(["checker.py", "get", "127.0.0.1", "state", "FLAG{unit}", "3"])

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(
                checker.main(["checker.py", "put", "127.0.0.1", "FLAG{unit}", "3"]),
                checker_lib.EXIT_MUMBLE,
            )
        self.assertIn("unsupported checker place", stderr.getvalue())

    def test_idempotency_key_matches_documented_hmac(self):
        expected = hmac.new(
            SECRET.encode("utf-8"),
            f"FLAG{{unit}}\x00{checker_lib.PLACE_1}\x00{checker_lib.SERVICE_NAME}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        self.assertEqual(
            checker_lib.derive_idempotency_key("FLAG{unit}", checker_lib.PLACE_1, SECRET),
            expected,
        )

    def test_checker_imports_do_not_pull_db_or_go_internals(self):
        importlib.reload(checker_lib)
        importlib.reload(checker)

        forbidden_modules = ("psycopg", "psycopg2", "asyncpg", "sqlalchemy")
        loaded = set(sys.modules)
        for module_name in forbidden_modules:
            self.assertFalse(
                any(name == module_name or name.startswith(module_name + ".") for name in loaded),
                module_name,
            )

        checker_sources = [
            (CHECKER_DIR / "checker.py").read_text(encoding="utf-8"),
            (CHECKER_DIR / "checker_lib.py").read_text(encoding="utf-8"),
        ]
        forbidden_source_markers = ("sentinel-aml/internal", "internal/", "postgresql://", "psycopg", "asyncpg")
        for source in checker_sources:
            lowered = source.lower()
            for marker in forbidden_source_markers:
                self.assertNotIn(marker, lowered)

    def test_timeout_and_url_defaults_are_deterministic(self):
        client = checker_lib.SentinelAMLClient("10.10.10.10")

        self.assertEqual(client.timeout, checker_lib.DEFAULT_HTTP_TIMEOUT_SECONDS)
        self.assertEqual(checker_lib.DEFAULT_HTTP_TIMEOUT_SECONDS, 5.0)
        self.assertEqual(checker_lib.CHECKER_TIMEOUT_SECONDS, 30)
        self.assertEqual(client.base_url, "http://10.10.10.10:8081")
        self.assertEqual(checker_lib.normalize_base_url("https://example.test/"), "https://example.test")

    def test_request_json_passes_deterministic_timeout_to_urlopen(self):
        calls = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def getcode(self):
                return 200

            def read(self):
                return b'{"status":"ok"}'

        def fake_urlopen(request, timeout):
            calls.append((request.full_url, timeout))
            return FakeResponse()

        original = checker_lib._url_request.urlopen
        checker_lib._url_request.urlopen = fake_urlopen
        try:
            client = checker_lib.SentinelAMLClient("example.test", timeout=1.25)
            self.assertEqual(client.request_json("GET", "/healthz"), {"status": "ok"})
            self.assertEqual(client.request_json("GET", "/healthz", timeout=0.75), {"status": "ok"})
        finally:
            checker_lib._url_request.urlopen = original

        self.assertEqual(calls, [("http://example.test:8081/healthz", 1.25), ("http://example.test:8081/healthz", 0.75)])

    def test_request_timeout_maps_to_service_down(self):
        def fake_urlopen(_request, timeout):
            raise TimeoutError(f"timed out after {timeout}")

        original = checker_lib._url_request.urlopen
        checker_lib._url_request.urlopen = fake_urlopen
        try:
            client = checker_lib.SentinelAMLClient("example.test", timeout=0.25)
            with self.assertRaises(checker_lib.ServiceDownError):
                client.request_json("GET", "/healthz")
        finally:
            checker_lib._url_request.urlopen = original

    def test_retention_sensitive_table_list_matches_architecture(self):
        self.assertEqual(checker_lib.RETENTION_SENSITIVE_TABLES, ("case_notes", "edd_records"))

    def test_retention_smoke_rejects_premature_physical_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "migrations").mkdir()
            (root / "migrations" / "cleanup.sql").write_text("DELETE FROM case_notes WHERE created_at < now();\n", encoding="utf-8")

            issues = checker_lib.retention_smoke_check(root)

        self.assertEqual(len(issues), 1)
        self.assertIn("case_notes", issues[0])


def dataclass_payload(state):
    return {field: getattr(state, field) for field in state.__dataclass_fields__}


def encode_envelope(payload, mac):
    return base64.urlsafe_b64encode(
        json.dumps({"payload": payload, "mac": mac}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")


def decode_payload(encoded):
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8"))["payload"]


if __name__ == "__main__":
    unittest.main()
