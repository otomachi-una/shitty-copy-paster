# W09-T02 Handoff — Secure Graph HTTP Endpoints and DTOs

## 1. Summary

Implemented the secure Wave 09 graph HTTP side-view baseline. The API now exposes authenticated graph metadata endpoints under `/api/graph/entities/{entity_hint}` while keeping private case notes, EDD confidential comments, raw audit diffs, checker-private state, public attack data, export, network, debug, and admin surfaces out of scope.

## 2. Implementation Details

- Added `GraphRepository` injection to `internal/httpapi.Server`.
- Registered only:
  - `GET /api/graph/entities/{entity_hint}`
  - `GET /api/graph/entities/{entity_hint}/related-cases`
  - `GET /api/graph/entities/{entity_hint}/edd-summaries`
- Kept `/api/graph` and `/api/entities` absent.
- Enforced bearer authentication on all graph endpoints.
- Enforced owned-hint authorization with `HasEntityAccess` before graph reads.
- Added explicit graph HTTP DTOs:
  - `GraphEntityView`: `entity_hint`, `relation_type`, `customer_count`, `case_count`, `highest_risk`, `risk_tags`, `updated_at`
  - `GraphRelatedCaseView`: `case_id`, `customer_id`, `entity_hint`, `display_name`, `country`, `status`, `public_summary`, `risk_score`, `typology_hint`, `created_at`, `updated_at`
  - `EDDGraphSummaryView`: `customer_id`, `entity_hint`, `review_status`, `risk_tags`, `created_at`, `updated_at`
- Added graph presenters so repository structs are not serialized directly.
- Wired `cmd/aml-api` to use `graph.NewRepository`.
- Updated `internal/projection` so graph DTOs are current secure side-view contracts instead of future placeholders.

## 3. Files Changed

- `cmd/aml-api/main.go`
- `internal/httpapi/server.go`
- `internal/httpapi/graph_server_test.go`
- `internal/httpapi/visibility_leak_test.go`
- `internal/projection/contracts.go`
- `internal/projection/contracts_test.go`
- `tests/projection_visibility_test.go`
- `docs/03_api_contract.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/audit_export_graph_invariants.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_09_W09-T02_handoff.md`

## 4. Tests Added

- `TestGraphEndpointsRequireAuthentication`
- `TestGraphEntitySummaryOwnerAccessAndFailClosed`
- `TestGraphRelatedCasesAndEDDSummariesAreSafe`
- `TestGraphResponseShapesAreAllowlisted`
- `TestGraphHTTPDTOAndPresenterStayPublicOnly`
- Extended `TestVisibilitySentinelStringsStayOnOwnerOnlyEndpoints` to probe secure graph routes.
- Updated projection contract tests for the current graph side-view contracts.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/projection -run "Graph|Visibility|Projection" -count=1` — passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` — passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` — passed.
- `python -B scripts/check_docs_tree.py` — passed.
- `python -B scripts/validate_forcad_config.py` — passed.

Additional observation: `python -B -m unittest discover -s tests -p "test_*.py"` was run during development and currently fails on historical/current wave gate expectations that still treat Wave 09 graph expansion as drift. That broader gate alignment is outside W09-T02 scope and should be handled by the Wave 09 gate task.

## 6. Documentation Updated

- API contract now documents the three secure graph endpoints and their response fields.
- Authorization docs now define owned-hint graph access.
- Visibility/projection docs now list graph DTO allowlists and private-field exclusions.
- Audit/export/graph invariants now describe the W09 secure graph HTTP baseline.
- Testing strategy now records focused graph HTTP/projection commands.
- Risk register now tracks graph HTTP projection drift.
- Execution log records W09-T02 completion.

## 7. CTF Invariants Checked

- No checker PUT/GET path was added.
- No public attack data was added.
- No AML-3 vulnerable behavior was added.
- No exploit or reference-fix scripts were added.
- ForcAD config was unchanged and validated.
- Existing future flag-store candidate fields remain private owner data only.

## 8. Security Invariants Checked

- Graph routes require bearer authentication.
- Graph access fails closed when the user owns no customer for the requested normalized entity hint.
- Graph DTOs exclude `CaseNote.body`, `EDDRecord.confidential_comment`, raw `diff_json`, credential fields, session material, owner IDs, analyst/author/assignee IDs, transaction traces, counterparty fingerprints, checker-private markers, artificial flag fields, and raw DB rows.
- HTTP visibility tests plant private sentinels and verify graph responses do not disclose them.
- Repository outputs are projected through explicit DTOs before JSON encoding.

## 9. Self-Review

The implementation stayed within the secure graph side-view scope. It added only metadata endpoints and did not alter owner workflows, checker behavior, ForcAD layout, vulnerabilities, exports, network rooms, or public attack data. Response shapes are covered at both HTTP-test and projection-contract levels. The graph root remains absent to avoid route discovery drift.

Known gap: the Wave 09 branch gate has not yet been created or aligned, so broad Python gate tests that expect pre-Wave-09 route surfaces need a later W09 gate/update task.

## 10. Risks / Open Questions

- `R-041` tracks future graph HTTP projection drift.
- Live PostgreSQL graph HTTP integration was not required by W09-T02 and was not run.
- URL-encoded entity hints are not decoded in the HTTP handler; current test and docs use path-safe hints. This can be revisited if future API docs require arbitrary hint characters.

## 11. Ready for Orchestrator Review: yes

