# W03-F03 Handoff — Roadmap, Wave Ledger, and Duplicate-Error Debt Alignment

## 1. Summary

Aligned the roadmap and wave ledger with current orchestrator review state, narrowed Wave 03 documentation to the delivered customer/account/transaction slice, defined Wave 04 as the conditional risk scoring/alerts/owner case workflow wave, and implemented stable duplicate-domain error handling.

## 2. Implementation Details

- Updated `docs/13_roadmap.md` so Wave 02 is complete and Wave 03 is `needs fixes` until W03-F01, W03-F02, and W03-F03 pass.
- Updated `docs/waves.md` so W03 no longer includes case/EDD/notes/audit scope and W04 is the conditional risk scoring, alerts, and owner case workflow wave.
- Updated `docs/source_of_truth_map.md` to state the status-ledger and wave-decomposition authority relationship.
- Added explicit duplicate repository errors:
  - customer duplicate registration number per owner;
  - account duplicate `iban_like` under a customer;
  - transaction duplicate `trace_id` under an account.
- Mapped duplicate domain errors to stable HTTP `409` responses:
  - `duplicate_customer_registration`;
  - `duplicate_account_iban`;
  - `duplicate_transaction_trace`.

## 3. Files Changed

- `internal/customer/repository.go`
- `internal/customer/repository_test.go`
- `internal/account/repository.go`
- `internal/account/repository_test.go`
- `internal/transaction/repository.go`
- `internal/transaction/repository_test.go`
- `internal/httpapi/server.go`
- `internal/httpapi/domain_server_test.go`
- `tests/test_docs_tree.py`
- `docs/03_api_contract.md`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/source_of_truth_map.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_03_W03-F03_handoff.md`

## 4. Tests Added

- Repository tests for mapping SQL unique violations to customer/account/transaction duplicate errors.
- HTTP tests for duplicate customer registration, account `iban_like`, and transaction `trace_id` returning stable `409` JSON bodies.
- Docs-tree regression test for Wave 02 complete, Wave 03 needs fixes, and Wave 04 conditional scope wording.

## 5. Tests Run

- `python -B scripts/check_docs_tree.py` passed.
- `python -B scripts/check_wave03_gate.py` passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` passed, 35 tests.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=%TEMP%\sentinel-aml-go-cache go test ./...` passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=%TEMP%\sentinel-aml-go-cache go vet ./...` passed.

## 6. Documentation Updated

- Roadmap status ledger and dependency table.
- Wave list and W03/W04 wave detail sections.
- Source-of-truth map status/decomposition note.
- API contract duplicate conflict responses.
- Testing strategy duplicate and docs-ledger coverage.
- Execution log and risk register.

## 7. CTF Invariants Checked

- No checker behavior added.
- No public attack data added.
- No flag stores added.
- No planned vulnerabilities or exploit/fix scripts added.
- Future Wave 04 now starts from a clear risk/alert/case owner workflow scope.

## 8. Security Invariants Checked

- Duplicate and invalid input errors do not expose SQL internals.
- Owner scoping remains unchanged.
- No sensitive fields are exposed in docs or responses.
- DB models are not serialized directly.

## 9. Self-Review

- Source-of-truth updates made: Wave 02 complete, Wave 03 needs fixes through this fix packet, Wave 04 conditional risk scoring/alerts/owner case workflow.
- Duplicate domain handling was implemented rather than deferred.
- The HTTP error names are specific enough for stable clients but do not reveal SQL constraint names.
- The roadmap still preserves future checker, vulnerability, exploit, fix, regression, and final validation sequencing.
- No architecture contracts were changed without an ADR.

## 10. Risks / Open Questions

- Wave 03 should remain marked `needs fixes` until orchestrator accepts W03-F01, W03-F02, and W03-F03.
- Later Wave 04 must keep risk scoring, alerts, and case workflow secure before checker or vulnerability work begins.

## 11. Ready for Orchestrator Review

yes.
