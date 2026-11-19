# Wave 32 Runtime Smoke

W32-T04 adds an archive-free runtime smoke command:

```sh
python -B scripts/runtime_smoke.py
```

The command validates the live runtime path without release packaging. It:

- verifies Docker Compose configuration and starts PostgreSQL;
- waits for PostgreSQL health;
- applies migrations with `go run ./scripts/migrate`;
- starts the API on `http://127.0.0.1:18080`;
- runs `go run ./cmd/aml-worker` twice to prove deterministic no-job restart
  safety;
- checks `/healthz`;
- executes normal analyst HTTP flows for register/login/me, customer, account,
  transaction, alert queue/claim/case creation, case-note PUT/GET, EDD PUT/GET,
  timeline, graph EDD summaries, and network-room listing.

The smoke does not use checker-private credentials, direct database writes,
debug routes, hidden admin helpers, external APIs, nondeterministic ML, or
random timing. `docker-compose.yml` exposes PostgreSQL through
`${SENTINEL_AML_POSTGRES_PORT:-54329}:5432`, so environments with a reserved
default port can run with a matching `DATABASE_URL` and
`SENTINEL_AML_POSTGRES_PORT` override. If Docker/PostgreSQL is unavailable,
`--skip-if-docker-unavailable` returns exit code `77`; that skip mode is
diagnostic only and does not count as full acceptance.

Worker restart safety is pinned in `cmd/aml-worker/main_test.go`. The tests
run the current no-job worker twice and with a cancelled context, confirming
that the placeholder remains deterministic and context-aware until future queue
work is introduced.

## Agent Validation

On 2026-09-08 in the target Windows environment, default host port `54329` was
reserved by the OS, so the full acceptance run used the documented equivalent
port override:

```powershell
$env:DATABASE_URL = "postgres://sentinel:sentinel@localhost:55432/sentinel_aml_test?sslmode=disable"
$env:SENTINEL_AML_POSTGRES_PORT = "55432"
python -B scripts/runtime_smoke.py
```

Result: exit `0`, `runtime-smoke: pass elapsed=16.906s`.

The same run recorded PostgreSQL healthy, migrations applied with count `9`,
two worker restarts exiting `0`, API `/healthz` green, and the representative
HTTP workflow green. API cleanup logged `aml-api stopped`; on Windows the
`go run` wrapper still reported signal exit `1` after CTRL-BREAK, with
`runtime-smoke: api-stop exit=1 graceful=true`. That occurs after the smoke has
completed and does not affect workflow acceptance.
