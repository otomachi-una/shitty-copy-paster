# W06-T03 Handoff — Cross-Owner Fail-Closed Authorization Matrix

## 1. Summary

Added a consolidated owner-scope authorization matrix for current HTTP resources and documented it as the secure Wave 06 baseline for future side-view work.

## 2. Implementation Details

- Added `internal/authz` owner-scope contract metadata for customer, account, transaction, alert, case, case-note, and EDD resources.
- Added a table-driven HTTP cross-owner matrix using the existing in-memory handler stack.
- Matrix setup creates owner and other analysts plus customer, account, transaction, alert, case, private note, and EDD resources.
- Object-scoped cross-owner operations are expected to return `404 {"error":"not_found"}`.
- Alert queue remains available but owner-filtered and must not include another analyst's alerts.
- Boundary tests cover unauthenticated protected resources and malformed owner-resource IDs.
- Fail-closed assertions check that private case-note and EDD sentinel strings do not appear in error responses.

## 3. Files Changed

- `internal/authz/scope_contract.go`
- `internal/authz/scope_contract_test.go`
- `internal/httpapi/authz_matrix_test.go`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_06_W06-T03_handoff.md`

## 4. Tests Added

- `TestCurrentOwnerScopeContractsRemainFailClosed`
- `TestCrossOwnerFailClosedAuthorizationMatrix`
- `TestAuthorizationBoundaryRejectsUnauthenticatedAndMalformedRequests`

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` was attempted first and failed before compilation because the default Windows Go build cache under `C:\Users\2005g\AppData\Local\go-build` returned access denied errors.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` with `GOCACHE` pointed at a writable temp directory completed `go test ./...` successfully.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` was attempted first and failed before analysis because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` with `GOCACHE` pointed at a writable temp directory completed `go vet ./...` successfully.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` with `GOCACHE` pointed at a writable temp directory completed `go test ./internal/authz ./internal/httpapi -run "OwnerScope|Authorization|CrossOwner" -count=1 -v` successfully.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_wave05_gate.py` completed successfully and reported overall status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 47 tests.

## 6. Documentation Updated

- `docs/05_authentication_authorization.md` now includes the current cross-owner authorization matrix.
- `docs/06_visibility_and_projections.md` documents cross-owner visibility behavior.
- `docs/12_testing_strategy.md` documents the focused authorization matrix command.
- `docs/14_agent_execution_log.md` records W06-T03.
- `docs/15_risk_register.md` records cross-owner authorization drift mitigation.

## 7. CTF Invariants Checked

- Checker remains future-only and must later use normal owner APIs.
- No hidden admin bypass was added.
- No direct DB checker access path was added.
- No public attack data was added.

## 8. Security Invariants Checked

- Cross-owner checks do not expose existence or private field values.
- No new role names or privilege behavior were added.
- Error responses remain stable and non-sensitive.
- Visibility to future related graph/entity shapes remains explicitly separate from private case/EDD access.

## 9. Self-Review

- The implementation is test/authz-contract/documentation only.
- Runtime authorization behavior is unchanged.
- Matrix coverage includes customer get; account get/list/create; transaction get/list/create; alert queue/detail/claim/triage; case get/status; case notes get/post; and EDD get/post/patch.
- The tests use normal HTTP handlers and existing test repositories, not checker-style direct DB access.

## 10. Risks / Open Questions

- Future supervisor, auditor, collaborator, graph, entity, or side-view behavior must be introduced by explicit source-of-truth updates and tests; no such escalation behavior exists in Wave 06.
- Later vulnerability waves must avoid weakening the owner GET paths needed by future checker flows.

## 11. Ready for Orchestrator Review

yes.
