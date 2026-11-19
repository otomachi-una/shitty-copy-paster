import json, socket, sys, urllib.error, urllib.request

TIMEOUT = 8


def args(n=1):
    if len(sys.argv) != 2 + n:
        sys.exit("usage: %s <host> %s" % (sys.argv[0], " ".join("<a%d>" % (i + 1) for i in range(n))))
    return tuple(sys.argv[1:])


def emit(flag):
    print(flag)
    sys.exit(0)


def fail(msg):
    sys.exit("FAIL: %s" % msg)


def http(host, port, method, path, payload=None, headers=None, raw=None):
    if raw is not None:
        data, head = raw, {"Content-Type": "text/plain"}
    elif payload is not None:
        data, head = json.dumps(payload).encode(), {"Content-Type": "application/json"}
    else:
        data, head = None, {}
    head.update(headers or {})
    req = urllib.request.Request("http://%s:%d%s" % (host, port, path), data=data, headers=head, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except OSError as e:
        fail("host unreachable: %r" % (e,))


class CLI:
    def __enter__(self):
        return self

    def __init__(self, host):
        try:
            self.s = socket.create_connection((host, 31337), timeout=TIMEOUT)
        except OSError as e:
            fail("CLI 31337 unreachable: %r" % (e,))
        self.f = self.s.makefile("rb")
        if self._line() != "CarHack diagnostic ready":
            fail("bad banner")

    def __exit__(self, *_):
        self.f.close()
        self.s.close()

    def _line(self):
        try:
            raw = self.f.readline(8192)
        except OSError as e:
            fail("CLI read failed: %r" % (e,))
        if not raw:
            fail("CLI closed")
        return raw.rstrip(b"\r\n").decode("ascii", "replace")

    def cmd(self, text, multi=False):
        try:
            self.s.sendall(text.encode("ascii") + b"\n")
        except OSError as e:
            fail("CLI write failed: %r" % (e,))
        first = self._line()
        if not multi or first.startswith("ERR") or first in ("EMPTY", "END"):
            return [first]
        out = [first]
        while True:
            line = self._line()
            if line == "END" or line.startswith("ERR"):
                return out
            out.append(line)
            if len(out) > 2048:
                return out


PNG = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGP4"
       "DwABAQEAWk1v8QAAAABJRU5ErkJggg==")
