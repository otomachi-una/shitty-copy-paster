# W05-T03 Handoff — EDD Integration, Visibility Regression, and Documentation

## 1. Summary

Added Wave 05 EDD integration and visibility regression coverage. The new live PostgreSQL test exercises the real migration, auth, customer, EDD repository, and HTTP stack when `SENTINEL_AML_INTEGRATION_DATABASE_URL` is set; docs now distinguish owner EDD visibility from public, side, worker, export, audit, and future checker surfaces.

## 2. Implementation Details

- Added `TestLivePostgresWave05EDDAPIIntegration`.
- The live test applies all migrations to a clean schema and uses the real repositories for:
  - auth/session registration;
  - owner customer creation;
  - EDD owner create/get/patch;
  - duplicate current EDD conflict;
  - cross-owner get/patch/create fail-closed behavior.
- Strengthened visibility checks so EDD confidential comments do not appear in:
  - unauthenticated responses;
  - duplicate/cross-owner errors;
  - customer/account/transaction responses;
  - alert queue or absent investigation routes;
  - checker, public attack-data, graph, export, network, EDD public, or EDD audit route probes.
- Added docs regression coverage for:
  - EDD owner route documentation;
  - `confidential_comment` visibility matrix;
  - future checker place 2 deferral;
  - Wave 05 EDD worker no-op boundary;
  - live EDD integration command documentation.

## 3. Files Changed

- `internal/httpapi/live_postgres_integration_test.go`
- `tests/test_docs_tree.py`
- `docs/02_domain_model.md`
- `docs/04_database_model.md`
- `docs/06_visibility_and_projections.md`
- `docs/10_workers_and_async_flows.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_05_W05-T03_handoff.md`

## 4. Tests Added

- Opt-in live PostgreSQL EDD owner API integration test.
- Python docs regression for Wave 05 EDD visibility and worker/checker documentation.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` - passed with 41 tests.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresWave05EDDAPIIntegration -count=1 -v` - passed.

Docker/PostgreSQL was available locally; `docker compose up -d postgres` started a healthy PostgreSQL service before the live EDD integration command. The Go commands were run with `GOTELEMETRY=off` and a writable local `GOCACHE`; dependency resolution used the committed vendor tree.

## 6. Documentation Updated

- `docs/02_domain_model.md` now describes the owner EDD user journey and removes stale EDD HTTP deferral.
- `docs/04_database_model.md` now aligns EDD delete behavior with the migration and clarifies explicit EDD DTO serialization.
- `docs/06_visibility_and_projections.md` now includes a `confidential_comment` visibility matrix.
- `docs/10_workers_and_async_flows.md` states workers remain no-op for EDD in Wave 05.
- `docs/12_testing_strategy.md` documents the live EDD integration gate and visibility regression coverage.
- `docs/14_agent_execution_log.md` records W05-T03.
- `docs/15_risk_register.md` records EDD live integration drift mitigation.

## 7. CTF Invariants Checked

- No checker or flag placement behavior was added.
- No public attack data was added.
- No side-view leak was added.
- No exploit or reference-fix script was added.
- `EDDRecord.confidential_comment` remains durable private business data for future flag lifetime work.

## 8. Security Invariants Checked

- Confidential comments are not present in non-EDD response bodies.
- Confidential comments are not present in logs; no logging of EDD request bodies was added.
- EDD responses use explicit DTOs rather than broad DB model serialization.
- Cross-owner EDD failures remain fail-closed.

## 9. Self-Review

- The implementation is test and documentation focused and does not add new product behavior beyond exercising already-merged EDD APIs.
- The live EDD test is opt-in and skips clearly when `SENTINEL_AML_INTEGRATION_DATABASE_URL` is unset.
- The visibility matrix separates owner EDD view from public, side, worker, export, audit, graph/network, and checker surfaces.
- Historical Wave 03/Wave 04 gates remain branch-specific and may reject later Wave 05 EDD artifacts by design.

## 10. Risks / Open Questions

- Live PostgreSQL execution depends on a reachable database URL; skip behavior is explicit and does not mask offline unit/static failures.
- Future checker Wave 12 must use normal owner APIs and must not add direct DB or debug shortcuts.
- Future export/audit/projection waves must continue excluding `confidential_comment` unless an explicit source-of-truth contract allows it.

## 11. Ready for Orchestrator Review

yes.
