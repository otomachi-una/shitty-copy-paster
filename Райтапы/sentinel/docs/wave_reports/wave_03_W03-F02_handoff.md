# W03-F02 Handoff — Transaction Input Contract Hardening

## 1. Summary

Hardened transaction creation so `risk_score` is server-owned and amount input fails at the API/domain boundary before PostgreSQL can return unstable numeric errors.

## 2. Implementation Details

- Removed `risk_score` from `CreateTransactionRequest`.
- Removed `RiskScore` from `transaction.CreateParams`.
- Updated transaction inserts to omit `risk_score` and read back the PostgreSQL default `0`.
- Added shared `transaction.ValidateAmount` validation for positive decimal strings compatible with `numeric(18,2)`.
- Chosen contract: client-supplied `risk_score` is rejected by the existing strict JSON decoder as `400 {"error":"invalid_json"}` because it is no longer in the create DTO.
- Amount rules: required, digits only with optional decimal point, one or two fractional digits when present, no sign, no exponent, non-zero, and no more than 16 integer digits.

## 3. Files Changed

- `internal/transaction/repository.go`
- `internal/transaction/repository_test.go`
- `internal/httpapi/server.go`
- `internal/httpapi/domain_server_test.go`
- `docs/03_api_contract.md`
- `docs/04_database_model.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_03_W03-F02_handoff.md`

## 4. Tests Added

- HTTP test rejecting client-supplied `risk_score`.
- HTTP test rejecting malformed, zero, negative, and excessive-scale amounts with `invalid_request`.
- HTTP read assertion that a created transaction still exposes server-owned `risk_score: 0`.
- Repository tests rejecting invalid amounts before database work.
- Repository tests accepting valid `numeric(18,2)` amount shapes.
- Repository assertion that create inserts rely on the database `risk_score` default.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` initially hit Windows host cache/telemetry access denied paths under the user profile before package compilation.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=%TEMP%\sentinel-aml-go-cache go test ./...` passed. Go printed the host telemetry-token warning, but exited 0.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=%TEMP%\sentinel-aml-go-cache go vet ./...` passed. Go printed the host telemetry-token warning, but exited 0.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOPROXY=off` with fresh `GOCACHE` and fresh `GOMODCACHE` ran `go test ./...` successfully, proving vendor mode does not need network or a warm module cache.
- `python -B scripts/check_wave03_gate.py` passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` passed, 34 tests.
- `python -B scripts/check_docs_tree.py` passed.
- `python -B scripts/validate_forcad_config.py` passed.
- `python -B scripts/check_wave01_scope.py` passed.

## 6. Documentation Updated

- API contract now omits `risk_score` from `POST /api/transactions` requests and documents read-only server ownership.
- Database model now documents DB-defaulted server-owned `risk_score` and pre-insert amount validation.
- Authz and visibility docs now state transaction risk score is not client-settable.
- Testing strategy and risk register record the new transaction input contract guard.
- Execution log records W03-F02 completion.

## 7. CTF Invariants Checked

- No checker PUT/GET behavior added.
- No public attack data added.
- No planned vulnerability added.
- No exploit or reference fix scripts added.
- Future alert generation can rely on server-owned deterministic risk inputs.

## 8. Security Invariants Checked

- Owner scoping remains fail-closed.
- DTOs still omit auth/session internals and future sensitive fields.
- Invalid amount input returns stable JSON errors without database internals.
- DB models are not serialized directly.

## 9. Self-Review

- The risk score create path is no longer client-controlled at either HTTP DTO or repository params.
- Valid amount handling remains string-based to match the current schema and avoid floating-point parsing.
- Validation is intentionally conservative and rejects signs, exponent notation, empty fractional parts, zero values, and more than two decimal places.
- Cross-owner transaction denial tests remain in place and were not weakened.

## 10. Risks / Open Questions

- Live PostgreSQL gates depend on Docker/PostgreSQL availability on the reviewer host.
- Later risk-engine waves must replace the default `0` placeholder with deterministic server-side scoring without reopening client control.

## 11. Ready for Orchestrator Review

yes.
