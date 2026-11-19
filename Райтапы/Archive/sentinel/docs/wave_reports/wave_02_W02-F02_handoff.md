# Wave 02 W02-F02 Handoff — Live PostgreSQL Migration/Auth Integration Gate

## 1. Summary

Added a repeatable live PostgreSQL integration gate for Wave 02. The default unit test path remains database-free, while the opt-in gate applies migrations to a clean PostgreSQL database and exercises register, login, and `/api/auth/me` through the real repository, service, and HTTP handler stack.

## 2. Implementation Details

- Added `docker-compose.yml` with a dedicated local `postgres` service for `sentinel_aml_test`.
- Added `TestLivePostgresMigrationAuthIntegration` under `internal/httpapi`.
- The live test skips with a clear message when `SENTINEL_AML_INTEGRATION_DATABASE_URL` is unset.
- When the integration URL is set, the live test resets the target database schema, applies migrations from `migrations/`, creates an analyst through `POST /api/auth/register`, logs in through `POST /api/auth/login`, calls `GET /api/auth/me` with a bearer token, verifies unauthenticated `/api/auth/me` fails closed, and verifies sensitive hash fields are absent from responses.
- Added `make postgres-up` and `make live-auth-integration`.
- Extended `scripts/check_wave02_gate.py` to require the live integration test, Docker Compose postgres service, Makefile target, and F01/F02 handoff reports.

## 3. Files Changed

- `docker-compose.yml`
- `Makefile`
- `scripts/check_wave02_gate.py`
- `tests/test_wave02_gate.py`
- `internal/httpapi/live_postgres_integration_test.go`
- `docs/11_deployment.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_02_W02-F02_handoff.md`

## 4. Tests Added

- `TestLivePostgresMigrationAuthIntegration`
- `Wave02GateTest.test_live_postgres_gate_is_present`
- `Wave02GateTest.test_missing_live_integration_target_fails`

## 5. Tests Run

- `docker compose up -d postgres` completed successfully; the postgres service became healthy on `localhost:54329`.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test ./internal/httpapi -run TestLivePostgresMigrationAuthIntegration -count=1 -v` completed successfully.
- `GOTOOLCHAIN=local go test ./...` was attempted in PowerShell form and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go test ./...` successfully.
- `GOTOOLCHAIN=local go vet ./...` was attempted in PowerShell form and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go vet ./...` successfully.
- `python -B scripts/check_wave02_gate.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 23 tests.
- `docker compose down` completed successfully after validation.

## 6. Documentation Updated

- Deployment docs now include local PostgreSQL startup and live auth integration commands.
- Testing strategy now separates DB-free unit/static gates from the opt-in live PostgreSQL integration gate.
- Risk register now marks the live DB integration environment gap as mitigated by the compose/env-driven gate.
- Agent execution log updated.

## 7. CTF Invariants Checked

- Future checker path remains normal HTTP auth endpoint usage only.
- No direct DB checker path was added.
- No hidden debug/admin endpoint was added.
- No flag stores or public attack data were added.
- No planned vulnerabilities, exploits, or reference fixes were added.

## 8. Security Invariants Checked

- Auth DTOs remain explicit.
- Password hash and token hash fields are checked as absent from live HTTP responses.
- Auth middleware fail-closed behavior is verified for unauthenticated `/api/auth/me`.
- DB models are not directly serialized.

## 9. Self-Review

The live integration path proves the production repository/service/HTTP stack against PostgreSQL without forcing a live database into default unit tests. The database reset is intentionally limited to the database named by `SENTINEL_AML_INTEGRATION_DATABASE_URL`; docs and Makefile point to the dedicated compose-provided test database.

## 10. Risks / Open Questions

- The live gate requires Docker or another reachable PostgreSQL database.
- The local `make live-auth-integration` target uses POSIX-style environment assignment; on PowerShell, use the documented explicit `$env:` commands.

## 11. Ready for Orchestrator Review

Yes.
