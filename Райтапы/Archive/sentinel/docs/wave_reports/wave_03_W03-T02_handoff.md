# W03-T02 Handoff — Owner-Scoped Customer, Account, and Transaction APIs

## 1. Summary

Wave 03 now exposes authenticated owner-only APIs for customers, accounts, and transactions. The endpoints are normal product workflows over the W03-T01 repositories and do not introduce side views, checker-only APIs, planned vulnerabilities, or later investigation features.

## 2. Implementation Details

- Added explicit DTOs for customer, account, and transaction create/read/list responses.
- Added product routes only for the W03-T02 API contour:
  - `POST /api/customers`
  - `GET /api/customers/{customer_id}`
  - `POST /api/customers/{customer_id}/accounts`
  - `GET /api/accounts/{account_id}`
  - `GET /api/customers/{customer_id}/accounts`
  - `POST /api/transactions`
  - `GET /api/transactions/{transaction_id}`
  - `GET /api/customers/{customer_id}/transactions`
- Updated authentication middleware to authenticate all protected methods and leave method validation to each handler.
- Added owner authorization through repository method signatures and joins:
  - customer reads use `owner_user_id`;
  - account reads/creates/lists resolve through owned customers;
  - transaction reads/creates/lists resolve through owned accounts and customers.
- Mapped cross-owner access and missing records to stable `404 {"error":"not_found"}` responses.
- Mapped malformed path IDs to stable `400 {"error":"invalid_path"}` responses.
- Wired `cmd/aml-api` to instantiate real auth, customer, account, and transaction repositories.
- Added an opt-in live PostgreSQL owner API integration test.

## 3. Files Changed

- `cmd/aml-api/main.go`
- `internal/account/repository.go`
- `internal/httpapi/server.go`
- `internal/httpapi/domain_server_test.go`
- `internal/httpapi/live_postgres_integration_test.go`
- `internal/transaction/repository.go`
- `tests/test_wave02_gate.py`
- `docs/03_api_contract.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_03_W03-T02_handoff.md`

## 4. Tests Added

- HTTP tests for unauthenticated product endpoint rejection.
- HTTP tests for authenticated customer create/read and cross-owner customer denial.
- HTTP tests for account creation/listing under an owned customer and cross-owner account denial.
- HTTP tests for transaction creation/listing under an owned account/customer and cross-owner transaction denial.
- HTTP tests for malformed path IDs and stable JSON error responses.
- HTTP tests that response DTOs omit internal owner/auth/checker-private markers.
- HTTP tests that side-view/profile/risk/alert/case/EDD/graph/export/network endpoints remain absent.
- Opt-in live PostgreSQL owner API integration through real auth, repository, and HTTP layers.
- Wave 02 gate unittest remains strict for Wave 02 branches while accepting only the known historical whitelist failures on Wave 03 branches.

## 5. Tests Run

- `gofmt -w internal\httpapi\server.go internal\httpapi\domain_server_test.go internal\httpapi\live_postgres_integration_test.go internal\account\repository.go internal\transaction\repository.go cmd\aml-api\main.go` completed successfully.
- `GOTOOLCHAIN=local go test ./...` was attempted and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go test ./...` successfully.
- `GOTOOLCHAIN=local go vet ./...` was attempted and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go vet ./...` successfully.
- `python -B scripts/check_docs_tree.py` completed successfully and reported status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported status `pass`.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 27 tests.
- `python -B scripts/check_wave02_gate.py` was run and failed only on historical Wave 02 table/route whitelist checks because Wave 03 intentionally adds domain migrations and API routes. Auth route, auth response visibility, logs, sploit absence, live-gate presence, Wave 02 handoff, docs-tree, and ForcAD checks passed.
- `docker compose up -d postgres` started the local PostgreSQL service and reported it healthy on `localhost:54329`.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test ./internal/httpapi -run TestLivePostgresWave03OwnerAPIIntegration -count=1 -v` completed successfully.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test ./tests -run TestWave03LivePostgresDomainRepositories -count=1 -v` completed successfully when run separately.
- An accidental parallel run of the two named live gates reproduced the known shared-schema race; rerunning them separately passed.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test -p 1 ./...` completed successfully.
- `docker compose down` completed successfully after live validation.

## 6. Documentation Updated

- `docs/03_api_contract.md` now documents Wave 03 endpoints, requests, responses, and errors.
- `docs/05_authentication_authorization.md` now documents product owner authorization rules.
- `docs/06_visibility_and_projections.md` now documents Wave 03 owner-only projections.
- `docs/12_testing_strategy.md` now documents Wave 03 API and live owner API tests.
- `docs/15_risk_register.md` now tracks API projection drift.
- `docs/14_agent_execution_log.md` now records W03-T02.

## 7. CTF Invariants Checked

- Future checker can use normal APIs only.
- No direct DB checker path was added.
- No public attack data or checker storage was added.
- No planned vulnerability or side-view leak was added.
- No exploit or reference-fix script was added.

## 8. Security Invariants Checked

- All product endpoints require bearer authentication.
- Owner visibility is enforced by repository calls.
- Cross-owner access fails closed.
- DB models are not directly serialized to HTTP responses.
- Password hashes, stored token hashes, and future checker-private markers are not exposed.

## 9. Self-Review

The implementation stays inside the Wave 03 owner API boundary and keeps future gameplay surfaces absent. DTOs are explicit, path parsing is narrow, and negative tests cover the most important owner-isolation failures.

Known limitations:

- There is no product update/delete surface in Wave 03.
- There are no profile/risk convenience endpoints; the optional endpoints were intentionally left absent.
- Live integration tests still share the configured schema and should be run as named gates or with serialized package execution.

## 10. Risks / Open Questions

- `scripts/check_wave02_gate.py` remains a historical Wave 02-only gate and will fail on Wave 03 routes and migrations. Current Wave 03 tests cover the expanded contract.
- Future waves should decide whether to add a versioned multi-wave gate instead of reusing the Wave 02-only gate.

## 11. Ready for Orchestrator Review: yes
