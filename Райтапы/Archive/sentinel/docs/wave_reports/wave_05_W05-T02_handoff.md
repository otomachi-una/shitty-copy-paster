# W05-T02 Handoff — EDD Owner HTTP API and DTOs

## 1. Summary

Added the Wave 05 owner-authenticated EDD HTTP API. The API exposes normal owner EDD workflows only and keeps checker place 2, public attack data, side views, planned vulnerabilities, exploits, and reference fixes deferred.

## 2. Implementation Details

- Wired the EDD repository into `cmd/aml-api`.
- Added `httpapi.WithEDDRepository`.
- Added authenticated routes:
  - `POST /api/customers/{customer_id}/edd`
  - `GET /api/customers/{customer_id}/edd`
  - `PATCH /api/customers/{customer_id}/edd`
- Added strict JSON create/update request DTOs:
  - `source_of_funds`
  - `risk_rationale`
  - `confidential_comment`
  - `review_status`
- Added `EDDOwnerView` response DTO:
  - `id`
  - `customer_id`
  - `analyst_user_id`
  - `source_of_funds`
  - `risk_rationale`
  - `confidential_comment`
  - `review_status`
  - `created_at`
  - `updated_at`
- Mapped EDD errors to stable JSON:
  - invalid input: `400 {"error":"invalid_request"}`
  - duplicate current record: `409 {"error":"duplicate_edd_record"}`
  - not found or cross-owner: `404 {"error":"not_found"}`
  - malformed JSON or unknown fields: `400 {"error":"invalid_json"}`
  - unsupported methods: `405 {"error":"method_not_allowed"}`

## 3. Files Changed

- `internal/httpapi/server.go`
- `internal/httpapi/domain_server_test.go`
- `cmd/aml-api/main.go`
- `docs/03_api_contract.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/07_flag_stores.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_05_W05-T02_handoff.md`

## 4. Tests Added

- Unauthenticated rejection coverage for all EDD owner routes.
- Owner EDD create/get/patch happy path.
- Duplicate/current EDD conflict coverage.
- Cross-owner get/patch fail-closed coverage.
- Invalid status, missing required field, malformed body, malformed path, and unknown-field rejection coverage.
- Side-view route probes for graph/export/network/entity/checker/public attack-data and EDD public/audit paths.
- Response-body checks that EDD confidential comments do not appear in non-EDD owner endpoints.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed.
- `python -B scripts/check_docs_tree.py` - passed.

The Go commands were run with `GOTELEMETRY=off` and a writable local `GOCACHE`; dependency resolution used the committed vendor tree.

## 6. Documentation Updated

- `docs/03_api_contract.md` documents the EDD owner routes, DTOs, and stable errors.
- `docs/05_authentication_authorization.md` documents EDD owner authorization rules.
- `docs/06_visibility_and_projections.md` documents owner-only EDD confidential-comment visibility.
- `docs/07_flag_stores.md` clarifies that checker place 2 remains deferred.
- `docs/12_testing_strategy.md` documents Wave 05 EDD API test coverage.
- `docs/14_agent_execution_log.md` records W05-T02.
- `docs/15_risk_register.md` updates the EDD confidentiality mitigation.

## 7. CTF Invariants Checked

- Checker place 2 is not implemented.
- Public attack data is not implemented.
- No hidden checker shortcut was added.
- No exploit or reference-fix script was added.
- Future checker can use the normal owner API later.

## 8. Security Invariants Checked

- EDD confidential comments are visible only through owner EDD DTOs.
- Cross-owner EDD failures return `404` and do not distinguish object existence.
- Response DTOs do not expose password hashes, token hashes, raw DB rows, artificial flag fields, or checker-private fields.
- No logs include confidential comments.

## 9. Self-Review

- The implementation uses explicit DTO conversion rather than serializing repository models directly.
- Strict JSON decoding rejects unknown fields.
- The EDD API is mounted only under the authenticated customer subtree.
- Non-EDD endpoints are tested for absence of EDD confidential comments.
- The route surface remains limited to normal owner EDD workflows.

## 10. Risks / Open Questions

- Live PostgreSQL EDD HTTP coverage is not added in this task; unit HTTP tests cover routing and DTO behavior with memory repositories.
- Future checker place 2 must use the normal owner EDD API and must not add a direct DB shortcut.
- Historical Wave 04 gates may still reject EDD because EDD is a Wave 05 expansion.

## 11. Ready for Orchestrator Review

yes.
