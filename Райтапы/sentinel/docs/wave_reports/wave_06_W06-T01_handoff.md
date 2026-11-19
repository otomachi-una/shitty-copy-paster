# W06-T01 Handoff — Projection Allowlists and Presenter Boundaries

## 1. Summary

Added an explicit projection contract package for current owner views and future safe side-view placeholders. The implementation is additive and validation-focused: it does not register routes or change existing HTTP behavior.

## 2. Implementation Details

- Added `internal/projection` with named allowlisted DTO contracts.
- Current owner contracts cover customer, account, transaction, alert, case, case-note, and EDD owner views.
- Future safe contracts cover public case shell, duplicate preview, audit summary, export summary, graph summary, and network summary placeholders.
- Added reflection tests to compare JSON tags to explicit allowlists.
- Added negative tests to keep `body` limited to owner case-note and `confidential_comment` limited to owner EDD.
- Added future-safe checks for auth/session, checker-private, raw DB, owner-only, trace, and fingerprint fields.
- Added HTTP source guardrails to catch direct domain-model writes to `writeJSON`.

## 3. Files Changed

- `internal/projection/contracts.go`
- `internal/projection/contracts_test.go`
- `tests/projection_visibility_test.go`
- `docs/03_api_contract.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_06_W06-T01_handoff.md`

## 4. Tests Added

- Projection contract allowlist/tag matching.
- Sensitive-field exclusion across all projection contracts.
- Owner-only containment for `body` and `confidential_comment`.
- Future safe side-view exclusion for private, auth/session, checker-private, trace, and raw DB model-only fields.
- HTTP handler source guard against direct domain-model JSON writes.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` was attempted first and failed before compilation because the default Windows Go build cache under `C:\Users\2005g\AppData\Local\go-build` returned access denied errors.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` with `GOCACHE` pointed at a writable temp directory completed `go test ./...` successfully.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` with `GOCACHE` pointed at a writable temp directory completed `go vet ./...` successfully.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` with `GOCACHE` pointed at a writable temp directory completed `go test ./internal/projection ./tests` successfully.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_wave05_gate.py` completed successfully and reported overall status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 47 tests.

## 6. Documentation Updated

- `docs/06_visibility_and_projections.md` is updated as the authoritative projection allowlist matrix.
- `docs/03_api_contract.md` documents that Wave 06 adds projection contracts without new routes.
- `docs/05_authentication_authorization.md` ties owner authorization to projection boundaries.
- `docs/12_testing_strategy.md` documents Wave 06 projection tests.
- `docs/14_agent_execution_log.md` records W06-T01.
- `docs/15_risk_register.md` records projection drift mitigation.

## 7. CTF Invariants Checked

- No checker PUT/GET behavior was added.
- No public attack data was added.
- No planned vulnerability was added.
- Future place 1 and place 2 owner GET paths remain possible.
- No hidden debug endpoint or direct DB checker shortcut was added.

## 8. Security Invariants Checked

- Owner-only fields remain owner-only in projection contracts.
- Future side-view DTO contracts are deny-by-default allowlists.
- Projection contracts are explicit structs and not reflection-based field dumps.
- Tests reject private note bodies and EDD confidential comments in future safe contracts.

## 9. Self-Review

- The change is additive and scoped to projection contracts, tests, and docs.
- Existing owner API behavior is unchanged.
- `CaseNote.body` remains only in owner note projection contracts.
- `EDDRecord.confidential_comment` remains only in owner EDD projection contracts.
- Future safe placeholders do not expose auth/session hashes, checker-private fields, raw DB markers, trace IDs, or counterparty fingerprints.

## 10. Risks / Open Questions

- Future W06 tasks that implement public or side-view routes must wire handlers through these allowlist contracts or update the source-of-truth docs and tests first.
- The current HTTP handlers still define their local response DTOs in `internal/httpapi/server.go`; Wave 06 formalizes parallel contracts without refactoring runtime responses.

## 11. Ready for Orchestrator Review

yes.
