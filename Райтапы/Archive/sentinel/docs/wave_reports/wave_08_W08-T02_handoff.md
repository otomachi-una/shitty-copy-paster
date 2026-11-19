# Wave 08 W08-T02 Handoff - Audit Instrumentation and Owner Timeline API

## 1. Summary

W08-T02 adds secure audit instrumentation and an owner-scoped case timeline API surface. Successful case creation, case status changes, private case-note creation, and EDD create/update operations now emit audit events through the W08-T01 redaction primitives when an audit repository is supplied to the HTTP server.

The new timeline endpoint is `GET /api/cases/{case_id}/timeline`. It requires authentication, verifies case ownership before reading audit events, and returns explicit redacted DTOs rather than raw `audit_events.diff_json`.

## 2. Implementation Details

- Added `AuditRepository` as an optional `httpapi.Server` dependency through `WithAuditRepository`.
- Added owner-only audit response DTOs:
  - `CaseTimelineResponse`
  - `CaseAuditView`
  - `CaseAuditChangeResponse`
- Added `GET /api/cases/{case_id}/timeline` under the existing authenticated case subtree.
- Timeline reads call `cases.GetByOwner` before audit listing, so unknown and cross-owner cases fail closed before event lookup.
- Timeline responses parse sanitized audit diffs and expose only redacted change records.
- Sensitive timeline field labels are collapsed to `sensitive_field`.
- Timeline responses omit raw `diff_json`, value hashes, `actor_user_id`, owner database fields, raw private note bodies, raw EDD confidential comments, credentials, session data, checker-private markers, and artificial flag fields.
- Instrumented successful owner workflows:
  - case creation;
  - case status changes;
  - private note creation;
  - EDD create;
  - EDD update.
- EDD audit events are persisted for future activity work, but no customer activity or entity activity endpoint was added.
- Added projection allowlist coverage for the owner audit timeline DTO and nested redacted change DTO.

## 3. Files Changed

- `internal/httpapi/server.go`
- `internal/httpapi/domain_server_test.go`
- `internal/httpapi/visibility_leak_test.go`
- `internal/httpapi/audit_timeline_test.go`
- `internal/projection/contracts.go`
- `internal/projection/contracts_test.go`
- `tests/projection_visibility_test.go`
- `docs/03_api_contract.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/audit_export_graph_invariants.md`
- `docs/10_workers_and_async_flows.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_08_W08-T02_handoff.md`

## 4. Tests Added

- `TestCaseTimelineOwnerHappyPathAndRedaction`
- `TestCaseTimelineResponseShapeIsAllowlisted`
- `TestAuditInstrumentationRedactsEDDUpdate`
- `TestAuditFutureRoutesRemainAbsent`
- Projection test coverage for `OwnerCaseAuditView` and `OwnerCaseAuditChangeView`.
- Existing visibility regression now probes the owner timeline and cross-owner timeline path for private sentinel non-leakage.
- Existing projection surface count now requires the new owner audit contract.

## 5. Tests Run

Passed:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/audit ./internal/projection -run "Audit|Timeline|Visibility|Projection" -count=1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
```

## 6. Documentation Updated

- `docs/03_api_contract.md` now documents `GET /api/cases/{case_id}/timeline`, the response schema, fail-closed behavior, AML-2 deferral, and absent activity/raw audit routes.
- `docs/05_authentication_authorization.md` now includes the owner case audit timeline in the authorization matrix.
- `docs/06_visibility_and_projections.md` now documents the owner audit timeline allowlist and sensitive-field redaction behavior.
- `docs/audit_export_graph_invariants.md` now distinguishes the secure W08 owner timeline from future audit/export/graph behavior.
- `docs/10_workers_and_async_flows.md` clarifies that audit remains synchronous and in-process; no worker timeline builder exists.
- `docs/12_testing_strategy.md` now includes W08 timeline and instrumentation coverage.
- `docs/15_risk_register.md` adds `R-037` for audit timeline leakage.
- `docs/14_agent_execution_log.md` records W08-T02.

## 7. CTF Invariants Checked

- No checker PUT/GET path was added.
- No public attack data was added.
- AML-2 remains future-only.
- No exploit or reference-fix script was added.
- Existing owner note and EDD GET paths remain unchanged.
- No graph, export, network, customer activity, entity activity, raw audit, debug, or admin endpoint was added.

## 8. Security Invariants Checked

- Timeline access is owner-scoped through `cases.owner_user_id`.
- Cross-owner timeline reads return `404 not_found`.
- Unauthenticated timeline reads return `401 unauthenticated`.
- Timeline responses do not include raw note bodies, EDD confidential comments, raw `diff_json`, value hashes, credentials, session data, owner-only DB fields, checker-private fields, or artificial flag fields.
- EDD update audit events persist redacted confidential-comment diffs.
- Error responses remain stable JSON and do not include private sentinels.

## 9. Self-Review

The implementation keeps audit capture in the HTTP workflow layer and uses the W08-T01 audit repository as the redaction boundary. The timeline response parses already-sanitized diffs and applies an additional HTTP projection boundary by suppressing hashes and sensitive field names.

The intentionally exposed route list for this task is:

- `GET /api/cases/{case_id}/timeline`

The intentionally absent route list includes:

- `GET /api/customers/{customer_id}/activity`
- `GET /api/entities/{entity_hint}/activity`
- raw audit/diff endpoints
- graph/export/network/checker/public attack-data/debug/admin endpoints

Scope caveat: `cmd/aml-api` was not changed because it is outside the W08-T02 file scope. The HTTP server supports audit wiring through `WithAuditRepository`, and tests exercise that path. If orchestrator requires the default binary composition to enable the timeline route in this same wave, a tiny follow-up should allow `cmd/aml-api/main.go` to pass `audit.NewRepository(database)`.

## 10. Risks / Open Questions

- `R-037` tracks audit timeline leakage risk and is mitigated by DTO allowlists plus HTTP sentinel tests.
- Customer activity and entity activity semantics remain deferred until a later wave defines safe owner/projection behavior.
- No W08 branch gate exists yet; earlier gates such as W07 may remain historical and reject intentional W08 audit route activation.
- Production binary composition may need an explicit follow-up if `cmd/aml-api` wiring is required by orchestrator despite the W08-T02 file scope.

## 11. Ready for Orchestrator Review

Yes, with the file-scope caveat above.
