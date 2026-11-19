# W04-T03 Handoff — Owner Alert, Case, and Private-Note APIs

## 1. Summary

Implemented authenticated owner-scoped investigation APIs for alerts, cases, and private case notes. The normal analyst workflow now supports alert queue/read/claim/triage, creating a case from an owned alert, reading/updating an owned case, and creating/listing private owner-only notes.

## 2. Implementation Details

- Added explicit HTTP DTOs for alert, case, and case-note requests/responses.
- Added `AlertRepository` and `CaseworkRepository` interfaces to the HTTP layer.
- Added `WithInvestigationRepositories` for wiring investigation repositories into `NewServer`.
- Registered only these Wave 04 investigation routes:
  - `GET /api/alerts/queue`
  - `GET /api/alerts/{alert_id}`
  - `POST /api/alerts/{alert_id}/claim`
  - `POST /api/alerts/{alert_id}/triage`
  - `POST /api/alerts/{alert_id}/case`
  - `GET /api/cases/{case_id}`
  - `PATCH /api/cases/{case_id}/status`
  - `GET /api/cases/{case_id}/notes`
  - `POST /api/cases/{case_id}/notes`
- Wired `cmd/aml-api` with real alert and casework repositories.
- Kept owner authorization in repository boundaries:
  - alerts resolve through linked customer ownership;
  - cases resolve through `cases.owner_user_id`;
  - notes resolve through owned cases.
- Mapped invalid alert/case transitions to `409 {"error":"invalid_transition"}`.
- Mapped duplicate case creation to `409 {"error":"duplicate_case"}`.
- Kept note bodies available only through owner-authorized note endpoints.

## 3. Files Changed

- `cmd/aml-api/main.go`
- `internal/httpapi/server.go`
- `internal/httpapi/domain_server_test.go`
- `internal/httpapi/live_postgres_integration_test.go`
- `tests/test_wave03_gate.py`
- `docs/03_api_contract.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/07_flag_stores.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_04_W04-T03_handoff.md`

## 4. Tests Added

- Unauthenticated rejection coverage for all Wave 04 investigation API contours.
- Alert queue owner-only listing test.
- Alert read/claim/triage owner workflow test.
- Invalid alert transition test.
- Case creation from owned alert test.
- Case read and status update owner workflow test.
- Invalid case transition test.
- Private case-note create/list owner workflow test.
- Cross-owner alert, case, and note fail-closed tests.
- Private note body non-leakage assertions for cross-owner and absent side-view paths.
- Malformed investigation path and invalid request tests.
- Forbidden checker/public/side-view route probes.
- Opt-in live PostgreSQL owner investigation API workflow test.
- Historical Wave 03 gate test expectation updated to recognize W04-T03 route expansion as intentional on the current branch.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.
- `python -B scripts/check_wave01_scope.py` - passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` - passed, 35 tests.
- `docker compose up -d postgres` - started the local PostgreSQL service for live integration.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresWave04InvestigationAPIIntegration -count=1 -v` - passed.
- `docker compose down` - stopped and removed the live integration database container/network.

`GOTELEMETRY=off` and a writable local `GOCACHE` under `%TEMP%` were set for Go commands on this Windows host.

## 6. Documentation Updated

- `docs/03_api_contract.md` now documents Wave 04 investigation routes, schemas, and stable errors.
- `docs/05_authentication_authorization.md` now lists Wave 04 routes and owner/claim/private-note rules.
- `docs/06_visibility_and_projections.md` now documents alert, case, and case-note projections.
- `docs/07_flag_stores.md` clarifies that `CaseNote.body` is owner-authenticated private business data and checker remains deferred.
- `docs/12_testing_strategy.md` now includes Wave 04 API and live integration coverage.
- `docs/14_agent_execution_log.md` records W04-T03.
- `docs/15_risk_register.md` updates note-body and investigation API visibility risks.

## 7. CTF Invariants Checked

- Future checker place 1 can follow the product-normal path: create customer, create account, create suspicious transaction, receive/claim alert, create case, add private note.
- Checker itself remains unimplemented.
- No public attack data was added.
- No planned side-view leak was added.
- No exploit or reference-fix script was added.

## 8. Security Invariants Checked

- Private note body is owner-only.
- Cross-owner alert, case, and note access fails closed.
- DB models are not serialized directly.
- Auth/session hashes and owner-only persistence fields are not exposed in DTOs.
- Logs do not include note bodies.

## 9. Self-Review

- The API layer is intentionally thin and delegates owner enforcement to the repositories already added in W04-T01.
- Route registration is limited to the requested owner workflow contours.
- `CaseNote.body` is exposed only to the owning analyst through the normal private-note endpoint.
- Broad case/alert root collections, public views, audit timelines, graph/export/network-room paths, checker-only paths, and EDD paths remain absent.

## 10. Risks / Open Questions

- `ServeMux` redirects slashless `/api/alerts` and `/api/cases` to slash-prefixed subtree handlers because slash subtree routes are registered; no data is returned by those roots.
- Collaborator assignment is still deferred; alert claim and note authorship target the authenticated owning analyst.
- Future checker work must preserve these same owner-authenticated routes rather than adding direct DB or checker-only shortcuts.

## 11. Ready for Orchestrator Review

yes.
