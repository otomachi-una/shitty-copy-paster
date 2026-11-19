# W06-T02 Handoff — HTTP Visibility and Leak Regression Suite

## 1. Summary

Added a consolidated HTTP visibility regression suite that plants private case-note and EDD confidential-comment sentinels, then verifies they appear only in their allowed owner-only read endpoints.

## 2. Implementation Details

- Added `internal/httpapi/visibility_leak_test.go`.
- The test creates an owner user, another user, customer, account, transaction, alert, case, private note, and EDD record through current HTTP/domain test helpers.
- The private note sentinel is allowed only in owner `GET /api/cases/{case_id}/notes`.
- The EDD confidential-comment sentinel is allowed only in owner `GET /api/customers/{customer_id}/edd`.
- Disallowed probes cover unauthenticated routes, cross-owner routes, auth/me, unsupported profile/risk routes, customer/account/transaction responses, alert queue/detail responses, case shell responses, method-not-allowed errors, invalid-path errors, and absent graph/export/network/entities/checker/attack-data/duplicates/timeline routes.
- Leak helpers fail with the endpoint name and leaked sentinel.

## 3. Files Changed

- `internal/httpapi/visibility_leak_test.go`
- `docs/03_api_contract.md`
- `docs/06_visibility_and_projections.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_06_W06-T02_handoff.md`

## 4. Tests Added

- `TestVisibilitySentinelStringsStayOnOwnerOnlyEndpoints`

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` was attempted first and failed before compilation because the default Windows Go build cache under `C:\Users\2005g\AppData\Local\go-build` returned access denied errors.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` with `GOCACHE` pointed at a writable temp directory completed `go test ./...` successfully.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` was attempted first and failed before analysis because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` with `GOCACHE` pointed at a writable temp directory completed `go vet ./...` successfully.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` with `GOCACHE` pointed at a writable temp directory completed `go test ./internal/httpapi -run Visibility -count=1 -v` successfully.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_wave05_gate.py` completed successfully and reported overall status `pass`.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 47 tests.

## 6. Documentation Updated

- `docs/03_api_contract.md` documents the Wave 06 HTTP visibility sentinel rule.
- `docs/06_visibility_and_projections.md` documents the allowed/disallowed leak matrix.
- `docs/12_testing_strategy.md` documents the focused visibility command.
- `docs/14_agent_execution_log.md` records W06-T02.
- `docs/15_risk_register.md` records HTTP private-data leak regression mitigation.

## 7. CTF Invariants Checked

- No checker place 1 or place 2 behavior was added.
- No public attack data was added.
- No side-view leak was added.
- No exploit or reference fix was added.
- Future planned vulnerabilities remain locked.

## 8. Security Invariants Checked

- Private note bodies remain owner-only.
- EDD confidential comments remain owner-only.
- Unauthenticated and cross-owner responses do not disclose private sentinels.
- Unsupported future route probes return stable errors without private sentinels.

## 9. Self-Review

- The change is test and documentation only.
- No business behavior or route surface changed.
- The sentinel values are high-entropy test constants and are only used inside the regression suite.
- The suite intentionally ignores create responses used for planting because current owner create endpoints return the newly created owner resource by design; the enforced read-only allowed surfaces are owner note list and owner EDD get.

## 10. Risks / Open Questions

- Future vulnerability waves that intentionally add controlled leaks must update the source-of-truth docs and gate expectations before changing these secure baseline tests.
- Future public or side-view routes should add comparable sentinel probes before release.

## 11. Ready for Orchestrator Review

yes.
