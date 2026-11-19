# W05-T01 Handoff — EDD Persistence and Repository

## 1. Summary

Added Wave 05 EDD persistence and an owner-scoped EDD repository. `EDDRecord.confidential_comment` now exists as normal private business data in repository persistence only; checker place 2, public attack data, EDD HTTP APIs, vulnerabilities, exploits, and reference fixes remain deferred.

## 2. Implementation Details

- Added `migrations/000004_create_edd_records.sql`.
- Added `internal/edd.Repository`.
- Added repository methods:
  - `Create`;
  - `GetByOwnerCustomer`;
  - `UpdateByOwnerCustomer`.
- Added stable domain errors:
  - `ErrEDDRecordNotFound`;
  - `ErrDuplicate`;
  - `ErrInvalidInput`.
- Enforced owner scope through `customers.owner_user_id` joins/selects.
- Enforced one current EDD record per customer with `UNIQUE (customer_id)`.
- Restricted customer deletion while an EDD record exists so future flag-bearing EDD records are not removed through parent cleanup.
- Constrained `review_status` to `DRAFT`, `IN_REVIEW`, `APPROVED`, or `REJECTED`.
- Required `analyst_user_id` to match the owning analyst in Wave 05 because collaborator authorization is deferred.
- Did not add delete, cleanup, or retention behavior for EDD records.

## 3. Files Changed

- `migrations/000004_create_edd_records.sql`
- `internal/edd/repository.go`
- `internal/edd/repository_test.go`
- `tests/migration_sql_test.go`
- `docs/02_domain_model.md`
- `docs/04_database_model.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/07_flag_stores.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_05_W05-T01_handoff.md`

## 4. Tests Added

- EDD repository create happy path.
- Confidential-comment persistence argument test.
- Duplicate current-record conflict mapping test.
- Cross-owner get fail-closed test.
- Owner-scoped update happy path.
- Invalid review-status rejection test.
- Cross-analyst rejection test.
- Missing confidential-comment rejection test.
- Canceled context test.
- Wave 05 migration ordering and EDD schema assertions.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/edd -count=1` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./tests -run Test.*Migration -count=1` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.

The Go commands were run with `GOTELEMETRY=off` and a writable local `GOCACHE`; dependency resolution used the committed vendor tree.

## 6. Documentation Updated

- `docs/02_domain_model.md` documents EDD fields, owner rules, one-current-record behavior, and checker deferral.
- `docs/04_database_model.md` documents the `edd_records` table, constraints, indexes, and no-retention-delete behavior.
- `docs/05_authentication_authorization.md` documents EDD repository owner scope through customers.
- `docs/06_visibility_and_projections.md` documents that EDD has no HTTP projection in Wave 05.
- `docs/07_flag_stores.md` documents `EDDRecord.confidential_comment` as private business data only.
- `docs/12_testing_strategy.md` documents Wave 05 EDD persistence coverage.
- `docs/14_agent_execution_log.md` records W05-T01.
- `docs/15_risk_register.md` records EDD confidentiality mitigation.

## 7. CTF Invariants Checked

- No checker PUT/GET for place 2.
- No public attack data.
- No private checker state.
- No artificial `flag_value` field.
- No exploit or reference-fix script.
- ForcAD config unchanged.

## 8. Security Invariants Checked

- Cross-owner EDD access fails closed through owner/customer repository methods.
- `confidential_comment` is not exposed through HTTP DTOs or public projections.
- Repository errors map duplicate/not-found cases without leaking raw SQL details.
- No logs include EDD confidential comments.

## 9. Self-Review

- The implementation is persistence-only and does not wire EDD into HTTP routes.
- One current EDD record per customer is encoded at the database layer and repository duplicate mapping.
- Wave 05 uses owning analyst semantics for `analyst_user_id`; collaborator assignment remains future work.
- No cleanup or retention delete path was added, and customer deletion is restricted while EDD records exist, preserving future flag-bearing records.

## 10. Risks / Open Questions

- Future EDD HTTP APIs must add explicit DTOs and visibility tests before exposing `confidential_comment`.
- Future checker place 2 must use normal owner-authenticated APIs once those APIs exist, not direct DB access.
- Historical Wave 04 gate scripts may reject the new EDD migration because EDD is a Wave 05 expansion.

## 11. Ready for Orchestrator Review

yes.
