# W10-T04 — Secure Network-Room HTTP APIs and DTOs Handoff

## 1. Summary

Implemented the secure network-room HTTP surface for room list, room detail, participant join, and references-only dossier reads. The routes require authentication, use explicit DTOs, and keep AML-5 private-data copying/leakage out of scope.

## 2. Implementation Details

- Added `NetworkRoomRepository` wiring to the HTTP server and `cmd/aml-api`.
- Registered only:
  - `GET /api/network/rooms`
  - `GET /api/network/rooms/{room_id}`
  - `POST /api/network/rooms/{room_id}/join`
  - `GET /api/network/rooms/{room_id}/dossier`
- Added explicit HTTP DTOs for network-room summaries, details, participants, dossier cases, and dossiers.
- Added repository primitives for participant-scoped room lookup and safe dossier case listing.
- Dossier construction still flows through `internal/networkroom.BuildSafeDossier`, keeping `private_data_omitted` and references-only policy markers.
- Cross-participant/non-participant access fails closed before dossier construction.

## 3. Files Changed

- `cmd/aml-api/main.go`
- `internal/httpapi/server.go`
- `internal/httpapi/domain_server_test.go`
- `internal/httpapi/export_server_test.go`
- `internal/httpapi/network_room_server_test.go`
- `internal/networkroom/repository.go`
- `internal/networkroom/repository_test.go`
- `docs/03_api_contract.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/network_room_model.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_10_W10-T04_handoff.md`

## 4. Tests Added

- `TestNetworkRoomAPIsRequireAuthentication`
- `TestNetworkRoomJoinListDetailAndDossier`
- `TestNetworkRoomAPIsRejectBadPathsAndOutOfScopeRoutes`
- `TestGetRoomAndDossierCasesUseParticipantScopeAndSafeFields`

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/networkroom ./internal/projection -run "Network|Projection" -count=1` — passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` — passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` — passed.
- `python -B scripts/check_docs_tree.py` — passed.
- `python -B scripts/validate_forcad_config.py` — passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` — failed only on `test_wave09_gate_current_branch_has_no_failures` because the historical Wave 09 gate rejects intentional Wave 10 migrations/routes (`000008_create_exports_disputes.sql`, `000009_create_network_rooms.sql`, export/network expansion). W10-T04 did not alter historical gate policy.

Go emitted a non-fatal telemetry token warning in this sandbox, but the Go commands exited successfully.

## 6. Documentation Updated

- API contract now documents the secure network-room route surface and DTO fields.
- Authz docs now describe participant-scoped room/dossier access and join behavior.
- Visibility docs now name the W10-T04 network-room leak regression boundary.
- Network-room model doc now reflects active secure HTTP routes.
- Testing strategy now includes the focused network-room HTTP test command and expected coverage.
- Risk register R-045 now includes HTTP dossier leak regression.
- Execution log records W10-T04 completion.

## 7. CTF Invariants Checked

- No checker PUT/GET path was added.
- No public attack data route was added.
- No exploit or reference-fix script was added.
- No planned AML-5 vulnerable copying or dossier leakage was added.
- Existing ForcAD config was not changed.

## 8. Security Invariants Checked

- Network routes require bearer authentication.
- Room detail and dossier reads require participant membership.
- Network-room dossier DTOs expose public case shells only.
- Private case-note bodies and EDD confidential comments are absent from network responses.
- Raw EDD narrative fields, raw audit diffs, value hashes, credentials, sessions, traces, checker-private markers, and raw DB rows are excluded from tests and DTOs.

## 9. Self-Review

- Scope stayed within secure W10-T04 route exposure and wiring.
- The implementation uses explicit DTOs rather than repository model serialization.
- The memory test repository mirrors the participant-scoped behavior of the production repository.
- The secure baseline intentionally permits public foreign case summaries in dossiers while marking ownership with `owned_by_requester` and privacy with `private_data_omitted`.
- Intentionally excluded: network-room creation HTTP route, raw/private dossier route, graph-root route, checker behavior, public attack data, exploits, fixes, and AML-5.

## 10. Risks / Open Questions

- Current room creation remains repository/internal only; no HTTP create route was requested in W10-T04.
- Historical Wave 09 Python tests are not a valid current-branch gate after Wave 10 migrations/routes; a later Wave 10 validation task should add or align the current Wave 10 gate.
- Live PostgreSQL network-room HTTP integration was not run in this task; coverage is DB-free HTTP tests plus repository tests.

## 11. Ready for Orchestrator Review

yes, with the historical Wave 09 gate caveat above.
