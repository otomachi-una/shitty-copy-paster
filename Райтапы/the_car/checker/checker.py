#!/usr/bin/env python3
"""ForcAD PFR checker for the_car.

The checker uses only normal product routes.  It deliberately knows nothing
about the traversal, diagnostic-ring, authentication, native-parser, crypto,
or JWT weaknesses present in the vulnerable build, so its CHECK/PUT/GET paths
also work against ``src_fix``.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import io
import json
import os
import re
import secrets
import socket
import sys
import tarfile
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from checklib import *  # type: ignore # ForcAD's documented checker surface.

try:
    from .checker_protocol import CHALLENGE_TTL_SECONDS, MAX_CHALLENGE_LENGTH, Challenge, validate_identifier
except ImportError:
    from checker_protocol import CHALLENGE_TTL_SECONDS, MAX_CHALLENGE_LENGTH, Challenge, validate_identifier


GRAY_PIXEL_PNG = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGP4"
    "DwABAQEAWk1v8QAAAABJRU5ErkJggg=="
)

HTTP_TIMEOUT = 8
CLI_PORT = 31337
MAIN_PORT = 8080
AUTOPILOT_PORT = 8888


class NetworkFault(RuntimeError):
    """A host was unreachable or timed out."""


class ProtocolFault(RuntimeError):
    """A reachable host returned an invalid service response."""


class CLIError(ProtocolFault):
    """A well-formed diagnostic error reply."""


class FlagUnavailable(RuntimeError):
    """A valid GET cannot recover the previously stored flag."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


def _status(name: str):
    """Resolve checklib status names across its compatible releases."""

    container = globals().get("Status") or globals().get("TaskStatus")
    if container is None:
        raise RuntimeError("checklib did not expose a status enum")
    for candidate in (name, "ERROR" if name == "CHECKER_ERROR" else name):
        value = getattr(container, candidate, None)
        if value is not None:
            return value
    raise RuntimeError(f"checklib status unavailable: {name}")


def _checker_private_key(encoded: str) -> Ed25519PrivateKey:
    """Decode an explicitly configured seed without accepting loose base64."""

    if not isinstance(encoded, str) or not encoded or encoded != encoded.strip():
        raise RuntimeError("checker private key must be a 32-byte seed")
    try:
        if re.fullmatch(r"[0-9a-fA-F]{64}", encoded):
            raw = bytes.fromhex(encoded)
        else:
            if re.fullmatch(r"[A-Za-z0-9_+/\-]{43}=?", encoded) is None:
                raise ValueError("invalid seed encoding")
            raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
            if canonical != encoded.translate(str.maketrans("+/", "-_")).rstrip("="):
                raise ValueError("noncanonical seed encoding")
    except (ValueError, UnicodeError, binascii.Error):
        raise RuntimeError("checker private key must be a 32-byte seed") from None
    if len(raw) != 32:
        raise RuntimeError("checker private key must be a 32-byte seed")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration field")
        result[key] = value
    return result


def _checker_credentials(host: str) -> tuple[str, Ed25519PrivateKey]:
    """Select team identity and signer exclusively from organizer configuration."""

    keys_file = os.environ.get("CHECKER_KEYS_FILE")
    if keys_file is not None:
        if not keys_file:
            raise RuntimeError("CHECKER_KEYS_FILE must name a trusted keys file")
        try:
            with open(os.path.expanduser(keys_file), encoding="utf-8") as source:
                configured = json.load(source, object_pairs_hook=_unique_json_object)
        except (OSError, ValueError, UnicodeError):
            raise RuntimeError("CHECKER_KEYS_FILE could not be read as a valid keys object") from None
        if not isinstance(configured, dict):
            raise RuntimeError("CHECKER_KEYS_FILE must contain a host-to-key object")
        entry = configured.get(host)
        if not isinstance(entry, dict) or set(entry) != {"team_id", "private_key"}:
            raise RuntimeError("checker target has no valid trusted team/key entry")
        team_id, encoded = entry["team_id"], entry["private_key"]
    else:
        configured_host = os.environ.get("CHECKER_HOST")
        team_id = os.environ.get("CHECKER_TEAM_ID")
        encoded = os.environ.get("CHECKER_PRIVKEY")
        if not configured_host or team_id is None or encoded is None:
            raise RuntimeError("set CHECKER_KEYS_FILE or CHECKER_HOST, CHECKER_TEAM_ID and CHECKER_PRIVKEY")
        if configured_host != host:
            raise RuntimeError("checker target does not match CHECKER_HOST")
    try:
        validate_identifier(team_id)
    except (TypeError, ValueError):
        raise RuntimeError("checker team identity is invalid") from None
    return team_id, _checker_private_key(encoded)


def _random_credentials() -> tuple[str, str]:
    """Use checklib randomness for fresh per-flag credentials."""

    username = str(rnd_username())
    password = str(rnd_password())
    # The service requires at least twelve password characters.  checklib's
    # generator normally exceeds it; append entropy when a local stub does not.
    if len(password) < 12:
        password += secrets.token_urlsafe(18)
    return username[:64], password[:128]


def _route_key() -> str:
    return "r_" + secrets.token_urlsafe(18).replace("-", "_")


def _id3_with_comment(flag: str) -> bytes:
    """Create a benign ID3v2.3 COMM frame without a shipped media asset."""

    payload = b"\x00eng\x00" + flag.encode("utf-8")
    frame = b"COMM" + len(payload).to_bytes(4, "big") + b"\x00\x00" + payload
    size = len(frame)
    synchsafe = bytes(((size >> 21) & 0x7F, (size >> 14) & 0x7F, (size >> 7) & 0x7F, size & 0x7F))
    return b"ID3\x03\x00\x00" + synchsafe + frame


def _benign_media_pack() -> tuple[bytes, str]:
    """Build a one-file tar whose extraction result is fully predictable."""

    name = "cover-" + secrets.token_hex(6) + ".txt"
    payload = secrets.token_hex(8).encode("ascii")
    header = tarfile.TarInfo(name)
    header.size = len(payload)
    header.mtime = int(time.time())
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        archive.addfile(header, io.BytesIO(payload))
    return buffer.getvalue(), name


class CLIClient:
    """Small deterministic client for the line-text diagnostic endpoint."""

    def __init__(self, host: str) -> None:
        self.host = host
        self.sock: socket.socket | None = None
        self.reader = None

    def __enter__(self) -> "CLIClient":
        try:
            self.sock = socket.create_connection((self.host, CLI_PORT), timeout=HTTP_TIMEOUT)
            self.sock.settimeout(HTTP_TIMEOUT)
            self.reader = self.sock.makefile("rb")
            banner = self._readline()
        except (OSError, TimeoutError) as exc:
            self.close()
            raise NetworkFault("diagnostic connection failed") from exc
        if banner != "CarHack diagnostic ready":
            self.close()
            raise ProtocolFault("unexpected diagnostic banner")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self.reader is not None:
            self.reader.close()
            self.reader = None
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def _readline(self) -> str:
        if self.reader is None:
            raise NetworkFault("diagnostic socket is closed")
        try:
            raw = self.reader.readline(8192)
        except (OSError, TimeoutError) as exc:
            raise NetworkFault("diagnostic read failed") from exc
        if not raw:
            raise NetworkFault("diagnostic connection closed")
        try:
            return raw.rstrip(b"\r\n").decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProtocolFault("non-ascii diagnostic reply") from exc

    def command(self, text: str, *, multiline: bool = False) -> list[str]:
        if self.sock is None:
            raise NetworkFault("diagnostic socket is closed")
        try:
            self.sock.sendall(text.encode("ascii") + b"\n")
        except OSError as exc:
            raise NetworkFault("diagnostic write failed") from exc
        first = self._readline()
        if first.startswith("ERR "):
            raise CLIError(first)
        if not multiline:
            return [first]
        if first == "EMPTY":
            return []
        if first == "END":
            return []
        lines = [first]
        while True:
            line = self._readline()
            if line == "END":
                return lines
            if line.startswith("ERR "):
                raise CLIError(line)
            lines.append(line)
            if len(lines) > 1024:
                raise ProtocolFault("too many diagnostic frames")


class Checker(BaseChecker):
    vulns = 6
    timeout = 20
    uses_attack_data = True

    def __init__(self, host: str) -> None:
        super().__init__(host)
        self.host = host
        self.team_id, self.signer = _checker_credentials(host)

    def action(self, action: str, *args: str, **kwargs: Any) -> Any:
        try:
            return super().action(action, *args, **kwargs)
        except (socket.timeout, TimeoutError, ConnectionError, OSError):
            self._finish(_status("DOWN"), "connection failed", "network error")

    def _finish(self, status: Any, public: str = "", private: str | None = None) -> None:
        # Current checklib exposes BaseChecker.cquit.  The documented global
        # function is retained for compatibility with older ForcAD images.
        if private is None:
            private = public
        method = getattr(self, "cquit", None)
        if callable(method):
            method(status, public, private)
        cquit(status, public, private)

    def _http(self, port: int, method: str, path: str, payload: Any | None = None, headers: dict[str, str] | None = None, raw: bytes | None = None) -> Response:
        body: bytes | None = raw
        request_headers = {"Accept": "application/json"}
        if headers:
            request_headers.update(headers)
        if raw is None and payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection(self.host, port, timeout=HTTP_TIMEOUT)
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            content = response.read(1_100_000)
            if len(content) > 1_048_576:
                raise ProtocolFault("oversized HTTP response")
            return Response(response.status, {key.lower(): value for key, value in response.getheaders()}, content)
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            raise NetworkFault(f"HTTP {port} unavailable") from exc
        finally:
            connection.close()

    @staticmethod
    def _json(response: Response) -> dict[str, Any]:
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolFault("expected JSON response") from exc
        if not isinstance(value, dict):
            raise ProtocolFault("expected JSON object")
        return value

    @staticmethod
    def _text(response: Response) -> str:
        try:
            return response.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolFault("expected UTF-8 text") from exc

    @staticmethod
    def _require(response: Response, *statuses: int) -> Response:
        if response.status not in statuses:
            raise ProtocolFault(f"unexpected HTTP status {response.status}")
        return response

    def _register(self, port: int, path: str, username: str, password: str) -> None:
        self._require(self._http(port, "POST", path, {"u": username, "p": password}), 200, 201)

    def _login_autopilot(self, username: str, password: str, *, flag_lookup: bool = False) -> str:
        response = self._http(AUTOPILOT_PORT, "POST", "/login", {"u": username, "p": password})
        if flag_lookup and response.status in (401, 403, 404):
            raise FlagUnavailable("stored account unavailable")
        self._require(response, 200)
        token = self._json(response).get("access_token")
        if not isinstance(token, str) or not token:
            raise ProtocolFault("login did not return token")
        return token

    @staticmethod
    def _bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def _sign_challenge(self, wire: str, action: str, subject: str | None = None) -> bytes:
        """Sign only a bounded, intended action for the trusted target team."""

        try:
            if not isinstance(wire, str) or not wire.isascii() or len(wire) > MAX_CHALLENGE_LENGTH:
                raise ValueError("invalid wire challenge")
            challenge = Challenge.from_wire(wire)
        except (TypeError, ValueError, UnicodeError):
            raise ProtocolFault("malformed checker challenge") from None
        if challenge.team_id != self.team_id or challenge.action != action:
            raise ProtocolFault("checker challenge context mismatch")
        if action == "admin_provision" and (subject is None or challenge.subject != subject):
            raise ProtocolFault("checker challenge subject mismatch")
        if subject is not None and challenge.subject != subject:
            raise ProtocolFault("checker challenge subject mismatch")
        now = time.time()
        if not now < challenge.expires_at <= now + CHALLENGE_TTL_SECONDS + 5:
            raise ProtocolFault("checker challenge expiry invalid")
        intended = Challenge(
            team_id=self.team_id,
            action=action,
            subject=subject if subject is not None else challenge.subject,
            expires_at=challenge.expires_at,
            nonce=challenge.nonce,
        )
        return self.signer.sign(intended.message())

    def _diag_authorize(self, client: CLIClient) -> None:
        response = client.command("challenge")
        if len(response) != 1:
            raise ProtocolFault("bad diagnostic challenge")
        fields = response[0].split()
        if len(fields) != 2 or fields[0] != "CHALLENGE":
            raise ProtocolFault("bad diagnostic challenge")
        signature = self._sign_challenge(fields[1], "diag")
        result = client.command("diag_auth " + signature.hex())
        if result != ["OK diag"]:
            raise ProtocolFault("diagnostic auth rejected")

    @staticmethod
    def _reassemble_diag(lines: list[str], base_seq: int, chunk_count: int) -> str:
        chunks: dict[int, bytes] = {}
        for line in lines:
            parts = line.split()
            if len(parts) != 3 or parts[0] != "FRAME" or parts[1].upper() != "7DF":
                raise ProtocolFault("diagnostic frame format invalid")
            try:
                data = bytes.fromhex(parts[2])
            except ValueError as exc:
                raise ProtocolFault("diagnostic frame hex invalid") from exc
            if len(data) != 8:
                raise ProtocolFault("diagnostic frame size invalid")
            chunks[data[0]] = data[1:]
        expected = [(base_seq + index) % 256 for index in range(chunk_count)]
        if any(sequence not in chunks for sequence in expected):
            raise FlagUnavailable("diagnostic flag frames missing")
        try:
            return b"".join(chunks[sequence] for sequence in expected).rstrip(b"\0").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FlagUnavailable("diagnostic flag encoding invalid") from exc

    def _check_trust(self, client: "CLIClient") -> None:
        """Exercise the Ed25519 proof path and its rejection of a bad proof."""

        self._diag_authorize(client)
        response = client.command("challenge")
        fields = response[0].split()
        if len(fields) != 2 or fields[0] != "CHALLENGE":
            raise ProtocolFault("bad diagnostic challenge")
        forged = self._sign_challenge(fields[1], "diag")
        tampered = bytearray(forged)
        tampered[0] ^= 0xFF
        try:
            client.command("diag_auth " + tampered.hex())
        except CLIError:
            return
        raise ProtocolFault("diagnostic auth accepted an invalid signature")

    def _check_abs_authorization(self, client: "CLIClient") -> None:
        """A nonblank wrong ABS token must never return data."""

        probe = secrets.token_hex(8).encode("utf-8")
        fields = client.command("store_abs " + probe.hex())[0].split()
        if len(fields) != 3 or fields[0] != "ABS":
            raise ProtocolFault("ABS write token missing")
        address, token = fields[1], fields[2]
        wrong = "x" + token[1:] if token[0] != "x" else "y" + token[1:]
        try:
            client.command(f"read_abs {address} {len(probe):x} {wrong}")
        except CLIError:
            pass
        else:
            raise ProtocolFault("ABS read accepted a wrong token")
        reply = client.command(f"read_abs {address} {len(probe):x} {token}")[0]
        parts = reply.split(maxsplit=1)
        if len(parts) != 2 or parts[0] != "DATA" or not parts[1].startswith(probe.hex()):
            raise ProtocolFault("ABS read did not return the stored bytes")

    def _check_can_history(self, client: "CLIClient") -> None:
        """An unauthorized session must still observe ordinary CAN traffic.

        ``can_sniff`` is called without a delay argument: the bounded history is
        already populated, and a server-side sleep inside the timed diagnostic
        session would only add avoidable timeout exposure.  Telemetry beacons are
        confirmed through their own identifier rather than by scanning the shared
        window, which ordinary traffic can fill.
        """

        if not any(line.startswith("FRAME ") for line in client.command("can_sniff", multiline=True)):
            raise ProtocolFault("CAN history is empty")
        beacons = client.command("can_recv 400 14", multiline=True)
        if not any(line.startswith("FRAME 400") for line in beacons):
            raise ProtocolFault("telemetry beacons missing")

    def _check_album_art(self) -> None:
        """The default album-art evaluation must describe the uploaded image."""

        response = self._require(self._http(MAIN_PORT, "POST", "/api/media/albumart", {
            "image_b64": GRAY_PIXEL_PNG, "values": {},
        }), 200)
        result = self._json(response)
        if result.get("status") != "ok" or result.get("mode") != "L" or result.get("size") != [1, 1]:
            raise ProtocolFault("album-art metadata invalid")

    def _check_media_pack(self) -> None:
        """A benign one-file pack must extract to exactly that file."""

        archive, name = _benign_media_pack()
        response = self._require(self._http(MAIN_PORT, "POST", "/api/media/pack", {
            "tar_b64": base64.b64encode(archive).decode("ascii"),
        }), 200)
        if self._json(response).get("files") != [name]:
            raise ProtocolFault("media pack listing invalid")

    def _check_mission(self) -> None:
        """A benign mission document must be accepted."""

        document = "waypoints:\n  - [%d, %d]\n  - [%d, %d]\n" % (
            secrets.randbelow(40), secrets.randbelow(40),
            secrets.randbelow(40), secrets.randbelow(40),
        )
        response = self._http(AUTOPILOT_PORT, "POST", "/api/mission",
                              headers={"Content-Type": "text/plain"},
                              raw=document.encode("utf-8"))
        self._require(response, 200)
        if self._json(response).get("accepted") is not True:
            raise ProtocolFault("mission rejected")

    def _check_blackbox_raw(self) -> None:
        """The raw black-box view must return a well-formed AES-GCM envelope."""

        username, password = _random_credentials()
        self._register(MAIN_PORT, "/api/blackbox/register", username, password)
        probe = secrets.token_hex(12)
        response = self._require(self._http(MAIN_PORT, "POST", "/api/blackbox/store", {
            "u": username, "p": password, "flag": probe,
        }), 200)
        record_id = self._json(response).get("record_id")
        if not isinstance(record_id, str) or not record_id:
            raise ProtocolFault("black-box record id missing")
        response = self._require(self._http(MAIN_PORT, "GET", f"/api/blackbox/raw/{record_id}"), 200)
        encoded = self._json(response).get("ct_b64")
        if not isinstance(encoded, str):
            raise ProtocolFault("raw black-box envelope missing")
        try:
            envelope = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ProtocolFault("raw black-box envelope is not base64") from exc
        if len(envelope) != 12 + len(probe.encode("utf-8")) + 16:
            raise ProtocolFault("raw black-box envelope has the wrong length")
        if probe.encode("utf-8") in envelope:
            raise ProtocolFault("black-box record is not encrypted")

    def _check_route_export(self) -> None:
        """Saving, exporting and reading a route back must round-trip."""

        username, password = _random_credentials()
        key = _route_key()
        secret = secrets.token_hex(16)
        self._register(AUTOPILOT_PORT, "/register", username, password)
        token = self._login_autopilot(username, password)
        self._require(self._http(AUTOPILOT_PORT, "POST", "/api/route/save",
                                 {"key": key, "secret": secret}, self._bearer(token)), 200)
        response = self._require(self._http(AUTOPILOT_PORT, "POST", "/api/route/export",
                                            {"key": key}, self._bearer(token)), 200)
        name = self._json(response).get("name")
        if not isinstance(name, str) or not name:
            raise ProtocolFault("route export name missing")
        response = self._require(self._http(AUTOPILOT_PORT, "GET",
                                            "/api/route/export?" + urlencode({"path": name})), 200)
        exported = self._text(response)
        if f"key={key}" not in exported or f"bytes={len(secret.encode('utf-8'))}" not in exported:
            raise ProtocolFault("route export content invalid")
        if secret in exported:
            raise ProtocolFault("route export leaked the stored secret")

    def check(self) -> None:
        try:
            for port in (MAIN_PORT, AUTOPILOT_PORT):
                health = self._require(self._http(port, "GET", "/api/health"), 200)
                if self._json(health).get("status") != "ok":
                    raise ProtocolFault("unhealthy service")
            with CLIClient(self.host) as client:
                for ecu in ("engine", "abs", "autopilot", "telemetry", "infotainment"):
                    if client.command(f"ping {ecu}") != [f"PONG {ecu}"]:
                        raise ProtocolFault("ECU ping mismatch")
                if client.command("can_send 201 01") != ["OK"]:
                    raise ProtocolFault("turn signal command rejected")
                self._check_can_history(client)
                self._check_abs_authorization(client)
                self._check_trust(client)
            deadline = time.monotonic() + 2.0
            snapshot: dict[str, Any] = {}
            while time.monotonic() < deadline:
                response = self._require(self._http(MAIN_PORT, "GET", "/api/state"), 200)
                snapshot = self._json(response)
                if snapshot.get("turn_signal") == 1:
                    break
                time.sleep(0.1)
            if snapshot.get("turn_signal") != 1 or not snapshot.get("on_track") or float(snapshot.get("speed", 0)) <= 0:
                raise ProtocolFault("vehicle SLA state invalid")
            self._check_album_art()
            self._check_media_pack()
            self._check_mission()
            self._check_blackbox_raw()
            self._check_route_export()
        except NetworkFault as exc:
            self._finish(_status("DOWN"), "service unavailable", str(exc))
        except ProtocolFault as exc:
            self._finish(_status("MUMBLE"), "invalid service behavior", str(exc))
        self._finish(_status("OK"))

    def put(self, flag_id: str, flag: str, vuln: str) -> None:
        try:
            public, private = self._put(int(vuln), flag)
        except NetworkFault as exc:
            self._finish(_status("DOWN"), "service unavailable", str(exc))
            return
        except ProtocolFault as exc:
            self._finish(_status("MUMBLE"), "invalid service behavior", str(exc))
            return
        except Exception as exc:
            self._finish(_status("CHECKER_ERROR"), "checker put error", repr(exc))
            return
        self._finish(_status("OK"), public, private)

    def get(self, flag_id: str, flag: str, vuln: str) -> None:
        try:
            info = json.loads(flag_id)
            if not isinstance(info, dict):
                raise ValueError("private flag data is not an object")
            got = self._get(int(vuln), info)
        except FlagUnavailable as exc:
            self._finish(_status("CORRUPT"), "flag unavailable", str(exc))
            return
        except NetworkFault as exc:
            self._finish(_status("DOWN"), "service unavailable", str(exc))
            return
        except ProtocolFault as exc:
            self._finish(_status("MUMBLE"), "invalid service behavior", str(exc))
            return
        except Exception as exc:
            self._finish(_status("CHECKER_ERROR"), "checker get error", repr(exc))
            return
        if got is None or got != flag:
            self._finish(_status("CORRUPT"), "flag mismatch", "stored flag absent or altered")
            return
        self._finish(_status("OK"))

    def _put(self, vuln: int, flag: str) -> tuple[str, str]:
        if vuln == 1:
            username, password, key = *_random_credentials(), _route_key()
            self._register(AUTOPILOT_PORT, "/register", username, password)
            token = self._login_autopilot(username, password)
            self._require(self._http(AUTOPILOT_PORT, "POST", "/api/route/save", {"key": key, "secret": flag}, self._bearer(token)), 200)
            return key, json.dumps({"u": username, "p": password, "key": key})
        if vuln == 2:
            with CLIClient(self.host) as client:
                self._diag_authorize(client)
                response = client.command("diag_store " + flag.encode("utf-8").hex())
            fields = response[0].split()
            if len(fields) != 4 or fields[0] != "DIAG":
                raise ProtocolFault("diagnostic store response invalid")
            try:
                base_seq, chunk_count = int(fields[1], 16), int(fields[2], 16)
            except ValueError as exc:
                raise ProtocolFault("diagnostic metadata invalid") from exc
            if not 0 <= base_seq < 256 or not 1 <= chunk_count <= 64 or chunk_count != (len(flag.encode("utf-8")) + 6) // 7:
                raise ProtocolFault("diagnostic sequence or chunk count invalid")
            if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", fields[3]) is None:
                raise ProtocolFault("diagnostic record id invalid")
            data = {"base_seq": base_seq, "chunk_count": chunk_count, "record_id": fields[3]}
            return f"{base_seq:02x}:{chunk_count:x}", json.dumps(data)
        if vuln == 3:
            encoded = flag.encode("utf-8")
            with CLIClient(self.host) as client:
                response = client.command(f"store_abs {encoded.hex()}")
            fields = response[0].split()
            if len(fields) != 3 or fields[0] != "ABS" or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", fields[2]) is None:
                raise ProtocolFault("ABS write token missing")
            try:
                address = int(fields[1], 16)
            except ValueError as exc:
                raise ProtocolFault("ABS address invalid") from exc
            if not 0x2000 <= address < address + len(encoded) <= 0x4000:
                raise ProtocolFault("ABS allocation outside flag region")
            return f"{address:x}", json.dumps({"addr": address, "wtok": fields[2], "length": len(encoded)})
        if vuln == 4:
            username, password = _random_credentials()
            self._register(MAIN_PORT, "/api/media/register", username, password)
            response = self._require(self._http(MAIN_PORT, "POST", "/api/media/upload", {"u": username, "p": password, "mp3_b64": base64.b64encode(_id3_with_comment(flag)).decode("ascii")}), 200)
            track_id = self._json(response).get("track_id")
            if not isinstance(track_id, str) or not track_id:
                raise ProtocolFault("media track id missing")
            return track_id, json.dumps({"u": username, "p": password, "track_id": track_id})
        if vuln == 5:
            username, password = _random_credentials()
            self._register(MAIN_PORT, "/api/blackbox/register", username, password)
            response = self._require(self._http(MAIN_PORT, "POST", "/api/blackbox/store", {"u": username, "p": password, "flag": flag}), 200)
            record_id = self._json(response).get("record_id")
            if not isinstance(record_id, str) or not record_id:
                raise ProtocolFault("black-box record id missing")
            return record_id, json.dumps({"u": username, "p": password, "record_id": record_id})
        if vuln == 6:
            username, password = _random_credentials()
            self._register(AUTOPILOT_PORT, "/register", username, password)
            challenge_response = self._require(self._http(AUTOPILOT_PORT, "POST", "/api/checker/challenge", {"action": "admin_provision", "username": username}), 200)
            challenge = self._json(challenge_response).get("challenge")
            if not isinstance(challenge, str):
                raise ProtocolFault("provision challenge missing")
            signature = self._sign_challenge(challenge, "admin_provision", username)
            self._require(self._http(AUTOPILOT_PORT, "POST", "/api/checker/admin/provision", {"username": username, "challenge": challenge, "signature": signature.hex()}), 200)
            token = self._login_autopilot(username, password)
            self._require(self._http(AUTOPILOT_PORT, "POST", "/api/adminsecret", {"flag": flag}, self._bearer(token)), 200)
            return username, json.dumps({"u": username, "p": password})
        raise ValueError("unknown vulnerability")

    def _get(self, vuln: int, info: dict[str, Any]) -> str | None:
        if vuln == 1:
            token = self._login_autopilot(str(info["u"]), str(info["p"]), flag_lookup=True)
            path = "/api/route/load?" + urlencode({"key": str(info["key"])})
            response = self._http(AUTOPILOT_PORT, "GET", path, headers=self._bearer(token))
            if response.status in (401, 403, 404):
                return None
            return self._json(self._require(response, 200)).get("secret")
        if vuln == 2:
            base_seq, chunk_count = int(info["base_seq"]), int(info["chunk_count"])
            if not 0 <= base_seq < 256 or not 1 <= chunk_count <= 64:
                raise ValueError("invalid private diagnostic metadata")
            record_id = info.get("record_id")
            if record_id is not None and (not isinstance(record_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", record_id) is None):
                raise ValueError("invalid private diagnostic id")
            with CLIClient(self.host) as client:
                self._diag_authorize(client)
                try:
                    command = f"diag_fetch {record_id}" if record_id is not None else "can_recv 7df 200"
                    lines = client.command(command, multiline=True)
                except CLIError as exc:
                    if str(exc) == "ERR not found":
                        raise FlagUnavailable("diagnostic record missing") from exc
                    raise
            return self._reassemble_diag(lines, base_seq, chunk_count)
        if vuln == 3:
            address, length, token = int(info["addr"]), int(info["length"]), str(info["wtok"])
            if not 0x2000 <= address < address + length <= 0x4000 or not 1 <= length <= 512 or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", token) is None:
                raise ValueError("invalid private ABS metadata")
            with CLIClient(self.host) as client:
                try:
                    response = client.command(f"read_abs {address:x} {length:x} {token}")
                except CLIError as exc:
                    if str(exc) in ("ERR unauthorized", "ERR not found"):
                        raise FlagUnavailable("ABS record unavailable") from exc
                    raise
            fields = response[0].split(maxsplit=1)
            if len(fields) != 2 or fields[0] != "DATA":
                raise ProtocolFault("ABS read response invalid")
            try:
                return bytes.fromhex(fields[1]).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FlagUnavailable("ABS flag encoding invalid") from exc
            except ValueError as exc:
                raise ProtocolFault("ABS flag bytes invalid") from exc
        if vuln == 4:
            path = "/api/media/flag/" + str(info["track_id"]) + "?" + urlencode({"u": str(info["u"]), "p": str(info["p"])})
            response = self._http(MAIN_PORT, "GET", path)
            if response.status in (401, 403, 404):
                return None
            return self._text(self._require(response, 200))
        if vuln == 5:
            path = "/api/blackbox/get/" + str(info["record_id"]) + "?" + urlencode({"u": str(info["u"]), "p": str(info["p"])})
            response = self._http(MAIN_PORT, "GET", path)
            if response.status in (401, 403, 404):
                return None
            return self._text(self._require(response, 200))
        if vuln == 6:
            token = self._login_autopilot(str(info["u"]), str(info["p"]), flag_lookup=True)
            response = self._http(AUTOPILOT_PORT, "GET", "/api/adminsecret", headers=self._bearer(token))
            if response.status in (401, 403, 404):
                return None
            value = self._json(self._require(response, 200)).get("secret")
            return value if isinstance(value, str) else None
        raise ValueError("unknown vulnerability")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    expected = {"check": (3,), "put": (6,), "get": (6,), "info": (2, 3)}
    if action not in expected or len(sys.argv) not in expected[action]:
        cquit(_status("CHECKER_ERROR"), "checker error", "usage: checker.py <check|put|get|info> <host> [flag_id flag vuln]")
    if action == "info":
        # ForcAD can ask for metadata before choosing any target or loading keys.
        cquit(_status("OK"), json.dumps({
            "vulns": Checker.vulns,
            "timeout": Checker.timeout,
            "attack_data": Checker.uses_attack_data,
        }))
    try:
        checker = Checker(sys.argv[2] if len(sys.argv) > 2 else "localhost")
    except Exception as exc:
        cquit(_status("CHECKER_ERROR"), "checker configuration error", str(exc))
    try:
        checker.action(sys.argv[1], *sys.argv[3:])
    except checker.get_check_finished_exception():
        # checklib stores the finished verdict as its raw enum value; wrap it
        # back into the Status enum cquit() requires (older images keep a name).
        status = checker.status
        if isinstance(status, str):
            status = _status(status)
        else:
            container = globals().get("Status") or globals().get("TaskStatus")
            if container is not None and not isinstance(status, container):
                status = container(status)
        cquit(status, checker.public, checker.private)
