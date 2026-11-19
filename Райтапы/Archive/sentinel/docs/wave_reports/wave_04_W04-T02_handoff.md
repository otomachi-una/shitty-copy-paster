# W04-T02 Handoff — Deterministic Risk Scoring and Alert Generation Baseline

## 1. Summary

Implemented a synchronous, in-process deterministic risk scoring and alert generation baseline. Transaction creation can now flow through normal service code that computes a server-owned risk score, updates the transaction, and creates one owner-scoped alert for suspicious transactions.

## 2. Implementation Details

- Added `internal/risk.Service` with `ScoreTransaction`.
- Added pure deterministic `risk.Score` over:
  - `amount_bucket`;
  - `country`;
  - `counterparty_fingerprint`;
  - `typology_hint`.
- Added `transaction.Repository.UpdateRiskScoreByOwner` so risk scores remain server-owned and owner-scoped.
- Alert generation uses `DETERMINISTIC_RISK_THRESHOLD` when `risk_score >= 70`.
- Alert creation is idempotent through the existing unique `(transaction_id, rule_code)` constraint and service handling of `alert.ErrDuplicate`.
- Wired `cmd/aml-api` with the risk service so transaction create can run scoring synchronously.
- Kept `cmd/aml-worker` as a deterministic no-op placeholder.

Deterministic scoring definition:

- amount bucket weights:
  - `small` `< 1000.00`: 5;
  - `medium` `1000.00` through `9999.99`: 20;
  - `large` `10000.00` through `49999.99`: 45;
  - `very_large` `>= 50000.00`: 65.
- country weight:
  - `IR`, `KP`, `SY`: 20;
  - all other countries: 0.
- counterparty fingerprint weight:
  - contains `sanction`, `watchlist`, `shell`, or `mule`: 20;
  - otherwise `(rune sum % 3) * 5`.
- typology derivation:
  - high-risk country -> `high-risk-country`;
  - suspicious fingerprint keyword -> `counterparty-watchlist`;
  - large or very large amount -> `large-value-transfer`;
  - otherwise `standard-transaction`.
- typology weights:
  - `high-risk-country`: 10;
  - `counterparty-watchlist`: 20;
  - `large-value-transfer`: 15;
  - `standard-transaction`: 0;
  - unknown internal typology: 5.
- scores are clamped to 100.

This definition is documented as an Architecture Decision Candidate in `docs/10_workers_and_async_flows.md` because no prior source document specified exact Wave 04 weights or threshold.

## 3. Files Changed

- `cmd/aml-api/main.go`
- `internal/httpapi/server.go`
- `internal/httpapi/domain_server_test.go`
- `internal/risk/scoring.go`
- `internal/risk/scoring_test.go`
- `internal/transaction/repository.go`
- `internal/transaction/repository_test.go`
- `tests/migration_sql_test.go`
- `tests/wave03_live_postgres_test.go`
- `docs/10_workers_and_async_flows.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_04_W04-T02_handoff.md`

## 4. Tests Added

- Deterministic same-input same-output scoring test.
- Amount bucket boundary tests.
- Country and counterparty fingerprint impact tests.
- Non-suspicious transaction test proving no alert creation.
- Suspicious transaction test proving owner-scoped alert creation.
- Idempotent repeated scoring test proving no duplicate alert records.
- Cross-owner scoring denial test.
- Transaction repository risk-score update tests.
- HTTP transaction-create hook test for configured risk service.
- Migration guard against future worker queue tables.
- Opt-in live PostgreSQL risk/alert generation test.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.
- `python -B scripts/check_wave01_scope.py` - passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` - passed, 35 tests.
- `docker compose up -d postgres` - started the local PostgreSQL service for live integration.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./tests -run TestWave04LivePostgresRiskAlertGeneration -count=1 -v` - passed.
- `docker compose down` - stopped and removed the live integration database container/network.

`GOTELEMETRY=off` and a writable local `GOCACHE` under `%TEMP%` were set for Go commands on this Windows host.

## 6. Documentation Updated

- `docs/10_workers_and_async_flows.md` documents the synchronous Wave 04 baseline, exact score formula, alert threshold, idempotence, and future worker deferral.
- `docs/12_testing_strategy.md` documents risk/alert package, HTTP hook, migration guard, and live PostgreSQL coverage.
- `docs/14_agent_execution_log.md` records W04-T02 work.
- `docs/15_risk_register.md` records mitigations for deterministic scoring and alert repeatability.

## 7. CTF Invariants Checked

- Risk and alert behavior is stable across repeated runs.
- No checker behavior added.
- No public attack data added.
- No planned vulnerability added.
- Future checker can rely on deterministic suspicious transaction creation.

## 8. Security Invariants Checked

- Risk scoring does not use user-supplied `risk_score`.
- Alert generation preserves owner boundaries through transaction and alert repositories.
- Logs do not contain future flag-bearing or note body fields.
- No private case-note or EDD content is exposed.

## 9. Self-Review

- The workflow is synchronous and in-process by design; no queue or worker locking behavior was introduced.
- Repeated scoring updates the transaction to the same score and safely ignores duplicate alert creation.
- The risk formula uses only persisted transaction fields plus deterministic typology derivation.
- The country list and threshold are intentionally small and documented as an Architecture Decision Candidate for later ADR review.

## 10. Risks / Open Questions

- The exact scoring weights are a Wave 04 baseline and may need a formal ADR before later vulnerability/checker waves.
- The HTTP API returns the scored transaction when the service is configured, but it does not expose alert/case/note endpoints in this wave.
- Future async workers must preserve the same deterministic semantics.

## 11. Ready for Orchestrator Review

yes.
