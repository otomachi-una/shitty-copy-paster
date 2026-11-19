#!/usr/bin/env python3
"""Wave 13 checker entrypoint for Sentinel AML.

Place 1 and place 2 PUT/GET use normal owner HTTP APIs. CHECK/HAVOC and optional
noise actions exercise normal business flows without hidden checker endpoints.
"""

from __future__ import annotations

import json
import sys

from checker_lib import (
    EXIT_CHECKER_ERROR,
    EXIT_DOWN,
    EXIT_OK,
    CheckerError,
    ServiceCorruptError,
    ServiceDownError,
    ServiceMumbleError,
    parse_checker_args,
    place1_get,
    place1_put,
    place2_get,
    place2_put,
    forcad_cquit,
    get_noise,
    put_noise,
    run_check,
    run_havoc,
    safe_error_message,
)

# Legacy Wave 01 validators looked for the literal text "return 2" in the
# placeholder checker. Wave 11 uses explicit Hackerdom-compatible exit codes.


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv if argv is None else argv
    try:
        parsed = parse_checker_args(argv)
        if parsed.action == "check":
            run_check(parsed.host)
            return forcad_cquit(EXIT_OK, "OK", "OK")
        if parsed.action == "havoc":
            run_havoc(parsed.host)
            return forcad_cquit(EXIT_OK, "OK", "OK")
        if parsed.action == "put":
            if parsed.flag is None or parsed.place is None:
                raise ServiceMumbleError("PUT flag is missing")
            if parsed.place == 1:
                result = place1_put(parsed.host, parsed.flag)
            elif parsed.place == 2:
                result = place2_put(parsed.host, parsed.flag)
            else:
                raise ServiceMumbleError("unsupported checker place")
            return forcad_cquit(
                EXIT_OK,
                json.dumps(result.public_attack_data, sort_keys=True),
                result.private_state,
            )
        if parsed.action == "get":
            if parsed.private_state is None or parsed.flag is None or parsed.place is None:
                raise ServiceMumbleError("GET private state or flag is missing")
            if parsed.place == 1:
                place1_get(parsed.host, parsed.private_state, parsed.flag)
            elif parsed.place == 2:
                place2_get(parsed.host, parsed.private_state, parsed.flag)
            else:
                raise ServiceMumbleError("unsupported checker place")
            return forcad_cquit(EXIT_OK)
        if parsed.action == "putnoise":
            result = put_noise(parsed.host, seed=parsed.seed)
            return forcad_cquit(
                EXIT_OK,
                json.dumps(result.public_attack_data, sort_keys=True),
                result.private_state,
            )
        if parsed.action == "getnoise":
            if parsed.private_state is None:
                raise ServiceMumbleError("GETNOISE noise state is missing")
            get_noise(parsed.host, parsed.private_state)
            return forcad_cquit(EXIT_OK)
        return forcad_cquit(EXIT_CHECKER_ERROR, "unsupported checker action", "unsupported checker action")
    except ServiceCorruptError as exc:
        return forcad_cquit(exc.exit_code, _safe_error(exc), _safe_error(exc))
    except ServiceDownError as exc:
        return forcad_cquit(EXIT_DOWN, _safe_error(exc), _safe_error(exc))
    except CheckerError as exc:
        return forcad_cquit(exc.exit_code, _safe_error(exc), _safe_error(exc))
    except Exception as exc:
        return forcad_cquit(EXIT_CHECKER_ERROR, _safe_error(exc), _safe_error(exc))


def _safe_error(exc: Exception) -> str:
    return safe_error_message(exc)


if __name__ == "__main__":
    raise SystemExit(main())
