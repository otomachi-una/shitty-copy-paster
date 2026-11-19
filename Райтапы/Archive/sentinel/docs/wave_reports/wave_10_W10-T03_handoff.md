# Wave 10 W10-T03 Handoff

## 1. Summary

Added secure network-room persistence and safe dossier primitives for Wave 10. The implementation stores deterministic room metadata, case references, and participant metadata only; it does not add HTTP routes, workers, checker behavior, public attack data, exploit scripts, reference fixes, or AML-5 vulnerable dossier behavior.

## 2. Implementation Details

- Added `migrations/000009_create_network_rooms.sql` after the export/dispute migration.
- Added `network_rooms`, `network_room_cases`, and `network_room_participants` tables with constraints, uniqueness, and indexes.
- Added `internal/networkroom.Repository` primitives for:
  - creating or finding deterministic rooms from normalized entity and typology metadata;
  - attaching case references to rooms;
  - joining rooms as participants;
  - listing room participants;
  - listing rooms through participant membership.
- Added `BuildSafeDossier` to emit room metadata and public case summaries with `private_data_omitted` and `references_only` policy markers.
- Added projection allowlists for `network_room_summary`, `network_room_case`, and `network_room_dossier`.

## 3. Files Changed

- `migrations/000009_create_network_rooms.sql`
- `internal/networkroom/repository.go`
- `internal/networkroom/repository_test.go`
- `internal/projection/contracts.go`
- `internal/projection/contracts_test.go`
- `tests/migration_sql_test.go`
- `tests/projection_visibility_test.go`
- `docs/04_database_model.md`
- `docs/06_visibility_and_projections.md`
- `docs/10_workers_and_async_flows.md`
- `docs/audit_export_graph_invariants.md`
- `docs/network_room_model.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_10_W10-T03_handoff.md`

## 4. Tests Added

- Migration tests for ordered `000009_create_network_rooms.sql` and required table/constraint/index snippets.
- Migration negative checks for private note, EDD, audit, hash, raw case, checker-private, public attack-data, and artificial flag markers.
- Repository tests for deterministic room creation/finding, reference-only case links, participant joins, participant-scoped room listing, duplicate/not-found mapping, invalid inputs, and context cancellation.
- Safe dossier tests that plant private note, EDD, audit, and value-hash sentinels and assert they are absent from dossier JSON.
- Projection tests for network-room DTO allowlists and AML-5 forbidden fields.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/networkroom -count=1`: passed with a non-fatal Windows Go telemetry token warning.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/networkroom ./internal/projection ./tests -count=1`: passed with the same non-fatal telemetry warning.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: passed with `GOCACHE` set to a writable workspace cache and the same non-fatal telemetry warning.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: passed with `GOCACHE` set to a writable workspace cache and the same non-fatal telemetry warning.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.
- `python -B -m unittest discover -s tests -p "test_*.py"`: run, but the historical `test_wave09_gate.py` still fails because it expects post-Wave-09 export and network-room migrations/routes to be absent. This is expected Wave 10 drift and should be addressed by W10-T04's current-branch gate alignment.

## 6. Documentation Updated

- Database model documents the network-room tables, constraints, indexes, and reference-only storage rule.
- Visibility/projection docs document network-room safe-view contracts and AML-5 deferral.
- Worker docs state that W10-T03 adds no background room builder, copier, trigger, or worker.
- Network-room model now describes persistence, safe dossier fields, private-data exclusions, and future AML-5 boundary.
- Testing strategy documents W10-T03 coverage and commands.
- Risk register adds R-045 for network-room copy/leak drift.
- Execution log records W10-T03 actions and preserved scope.

## 7. CTF Invariants Checked

- No checker PUT/GET path added.
- No public attack data added.
- No exploit or reference-fix script added.
- No planned AML-5 vulnerable behavior added.
- No network-room HTTP route added.
- No worker added.
- ForcAD config unchanged.

## 8. Security Invariants Checked

- Room participation does not grant private case, note, EDD, audit, export, or checker visibility.
- Room case links store case references only.
- Safe dossier output omits planted private note, EDD confidential, audit diff, and value-hash sentinels.
- Network-room projection contracts omit private note bodies, EDD confidential comments, raw EDD narrative fields, raw audit diffs, value hashes, auth/session material, checker-private markers, artificial flag fields, and raw DB rows.
- Repository errors map to stable domain errors without raw SQL detail.

## 9. Self-Review

The implementation stays in persistence/domain boundaries and intentionally avoids route exposure. The repository uses deterministic room keys and reference-only links, while `BuildSafeDossier` keeps public summaries separate from any richer source data provided by future callers. Tests inspect both SQL and JSON output so accidental private-data copying should fail loudly.

## 10. Risks / Open Questions

- W10-T04 still needs a current Wave 10 gate that understands both export and network-room expansions.
- Historical Wave 09 Python gate tests remain strict for the Wave 09 branch and fail on the intentional Wave 10 migrations.
- Later network-room HTTP work must define route-level authorization before exposing dossier views.
- The local Windows Go profile prints a telemetry token access warning despite successful offline tests; using a writable workspace `GOCACHE` avoided build-cache access issues.

## 11. Ready for Orchestrator Review

Yes.
