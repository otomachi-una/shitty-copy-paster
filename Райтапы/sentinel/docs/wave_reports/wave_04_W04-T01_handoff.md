# W04-T01 Handoff — Alert, Case, and Case-Note Persistence Foundation

## 1. Summary

Added Wave 04 persistence for secure normal investigation objects: alerts, cases, and case notes. The implementation is repository-only and owner-scoped; it does not add checker behavior, public attack data, vulnerabilities, side views, or alert/case/note HTTP endpoints.

## 2. Implementation Details

- Added `000003_create_alerts_cases_notes.sql` after the Wave 03 migration.
- Added `internal/alert` repository with create, get-by-owner, list-by-owner, claim, and triage methods.
- Added `internal/casework` repository with create-from-alert, get-by-owner, list-by-owner, status update, create note, and list notes by owner methods.
- Encoded alert owner scope through transaction/account/customer joins.
- Encoded case owner scope through `cases.owner_user_id`.
- Encoded case-note owner scope through owned case lookups and joins.
- Added explicit alert statuses: `NEW`, `TRIAGED`, `CASE_OPENED`, `ESCALATED`, `CLOSED`.
- Added explicit case statuses: `OPEN`, `UNDER_REVIEW`, `ESCALATED`, `REPORTED`, `CLOSED`.
- Added conservative forward-only status transition checks for alerts and cases.
- Kept note visibility explicit as `private` or `internal`.
- Treated `CaseNote.body` as normal private analyst data only.

## 3. Files Changed

- `migrations/000003_create_alerts_cases_notes.sql`
- `internal/alert/repository.go`
- `internal/alert/repository_test.go`
- `internal/casework/repository.go`
- `internal/casework/repository_test.go`
- `tests/migration_sql_test.go`
- `tests/wave03_live_postgres_test.go`
- `docs/02_domain_model.md`
- `docs/04_database_model.md`
- `docs/05_authentication_authorization.md`
- `docs/07_flag_stores.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_04_W04-T01_handoff.md`

## 4. Tests Added

- Migration ordering and Wave 04 table/field/constraint/index tests.
- Alert repository tests for create/get/list/claim/triage, duplicate mapping, cross-owner denial, invalid transitions, and canceled contexts.
- Casework repository tests for create-from-alert/get/list/status update, duplicate mapping, private note create/list, cross-owner note denial, invalid transitions, and canceled contexts.
- Opt-in live PostgreSQL Wave 04 investigation repository integration test.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=%TEMP%\sentinel-aml-go-cache go test ./...` passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=%TEMP%\sentinel-aml-go-cache go vet ./...` passed.
- `python -B scripts/check_docs_tree.py` passed.
- `python -B scripts/validate_forcad_config.py` passed.
- `python -B scripts/check_wave01_scope.py` passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` passed, 35 tests.
- `docker compose up -d postgres` started the local PostgreSQL service.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=%TEMP%\sentinel-aml-go-cache go test ./tests -run TestWave04LivePostgresInvestigationRepositories -count=1 -v` passed.
- `docker compose down` stopped and removed the local PostgreSQL service.
- `python -B scripts/check_wave03_gate.py` was run for historical-gate visibility and failed only on the expected Wave 03 scope checks: the new Wave 04 migration order and allowed Wave 04 tables `alerts`, `cases`, and `case_notes`.

## 6. Documentation Updated

- Domain model documents alert, case, and case-note entities and owner boundaries.
- Database model documents Wave 04 tables, constraints, indexes, and exclusions.
- Authentication/authorization docs document repository owner-scope rules and current lack of collaborator assignment.
- Flag-store docs clarify `CaseNote.body` exists as normal private business data only.
- Testing strategy documents Wave 04 migration, repository, and live integration coverage.
- Execution log and risk register record Wave 04 persistence work and remaining checker-store confusion risk.

## 7. CTF Invariants Checked

- No checker PUT/GET path added.
- No public attack data added.
- No exploit/fix scripts added.
- `CaseNote.body` is a normal private business field, not an artificial flag field.
- Future checker can use a normal HTTP owner path only after a later API/checker wave adds it.

## 8. Security Invariants Checked

- DB models are not serialized directly.
- Private note bodies are exposed only through owner-authorized repository methods.
- Alert/case/note ownership fails closed across analysts.
- No sensitive fields or SQL internals are exposed in repository errors.

## 9. Self-Review

- Architecture fields for alerts, cases, and case notes are present in the migration and repositories.
- Repository methods accept `context.Context` and check cancellation before database work.
- Status transitions are intentionally conservative and forward-only.
- Assignment and note authorship are limited to the owning analyst until collaborator authorization exists.
- No `dedup_hint` placement, EDD, graph, export, network-room, vulnerability, exploit, fix, or checker behavior was added.

## 10. Risks / Open Questions

- Wave 04 does not add alert/case/note HTTP APIs; those remain for the next vertical-slice wave.
- `CaseNote.body` is now present and must remain private business data until checker PUT/GET is explicitly added later.
- A dedicated Wave 04 gate script is not yet present; current coverage is Go migration/repository tests plus retained docs/ForcAD/Wave 01 gates.

## 11. Ready for Orchestrator Review

yes.
