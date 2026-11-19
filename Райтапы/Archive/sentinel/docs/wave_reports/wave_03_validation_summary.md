# Wave 03 Validation Summary

## Status

Wave 03 validation status: pass with documented historical-gate caveats.

## Scope Validated

- Domain persistence for `customers`, `accounts`, and `transactions`.
- Owner-scoped customer/account/transaction APIs.
- Retained Wave 01 ForcAD and checker/sploit layout invariants.
- Retained Wave 02 auth/session behavior and sensitive-response guardrails.
- Absence of checker behavior, exploits, planned vulnerabilities, public attack data, flag storage, side views, and later AML subsystems.

## Gate Results

- `scripts/check_wave03_gate.py` validates the current Wave 03 branch and is the authoritative gate for W03-T03.
- `scripts/check_wave02_gate.py` remains a historical Wave 02 branch gate. On Wave 03 branches it fails only where expected: the Wave 02-only migration/table whitelist and route whitelist reject intentional Wave 03 domain additions. Its auth, response visibility, log, sploit, live-gate presence, docs, and ForcAD checks still pass.

## Commands Run

- `GOTOOLCHAIN=local go test ./...` was attempted and failed on the current Windows host because the default Go build cache returned access denied errors before package tests ran.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go test ./...` successfully.
- `GOTOOLCHAIN=local go vet ./...` was attempted and failed on the current Windows host because the default Go build cache returned access denied errors before diagnostics ran.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go vet ./...` successfully.
- `python -B scripts/check_docs_tree.py` completed successfully and reported `pass`.
- `python -B scripts/check_wave02_gate.py` ran and failed only on the expected historical Wave 02 table/route whitelist checks.
- `python -B scripts/check_wave03_gate.py` completed successfully and reported `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 32 tests.
- `make wave03-gate` could not run on this Windows host because `make` is not installed.

## Live Integration

The live PostgreSQL path is available through:

```sh
docker compose up -d postgres
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test ./internal/httpapi -run TestLivePostgresWave03OwnerAPIIntegration -count=1
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test ./tests -run TestWave03LivePostgresDomainRepositories -count=1
```

For a live-enabled full package sweep with the shared local database, run:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test -p 1 ./...
```

Local live results:

- `docker compose up -d postgres` started a healthy PostgreSQL service on `localhost:54329`.
- `TestLivePostgresWave03OwnerAPIIntegration` passed.
- `TestWave03LivePostgresDomainRepositories` passed.
- Live-enabled `go test -p 1 ./...` passed.
- `docker compose down` stopped and removed the local service after validation.

## Known Environment Notes

- On the current Windows host, `python3` resolves to a launcher stub that only prints `Python`; `python` is the working interpreter.
- On the current Windows host, the default Go build cache can return access denied errors. Point `GOCACHE` at a writable temporary directory when running local-toolchain tests there.
- Live tests reset the configured PostgreSQL schema. Run named live gates separately or serialize packages with `go test -p 1`.

## Ready For Review

Ready for orchestrator review: yes.
