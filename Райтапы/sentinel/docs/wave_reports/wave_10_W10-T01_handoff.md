# Wave 10 W10-T01 Handoff

## 1. Summary

Added secure export/dispute persistence and recursive export redaction primitives for Wave 10. The implementation introduces export tables and `internal/exporting` data-layer helpers only; it does not add HTTP routes, checker behavior, public attack data, exploit scripts, reference fixes, network-room tables, or AML-4 vulnerable behavior.

## 2. Implementation Details

- Added `migrations/000008_create_exports_disputes.sql` with `disputes`, `exports`, and `export_items`.
- Added `internal/exporting.Repository` methods for owner-scoped dispute, export, and export-item creation.
- Added `ExportContext` with requester user ID, root case ID, purpose, and allowed scopes.
- Added recursive `BuildBundle` redaction primitives for root case shell, linked case shells, audit summaries, EDD summaries, and export item metadata.
- Added current projection contracts for `export_bundle`, `export_case_shell`, `export_audit_summary`, `export_edd_summary`, and `export_item_metadata`.
- Kept export route exposure deferred to W10-T02.

## 3. Files Changed

- `migrations/000008_create_exports_disputes.sql`
- `internal/exporting/repository.go`
- `internal/exporting/redaction.go`
- `internal/exporting/repository_test.go`
- `internal/projection/contracts.go`
- `internal/projection/contracts_test.go`
- `tests/migration_sql_test.go`
- `tests/projection_visibility_test.go`
- `docs/03_api_contract.md`
- `docs/04_database_model.md`
- `docs/06_visibility_and_projections.md`
- `docs/audit_export_graph_invariants.md`
- `docs/12_testing_strategy.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_10_W10-T01_handoff.md`

## 4. Tests Added

- Export repository owner-scope tests for dispute, export, and export-item creation.
- Export non-owner root-case fail-closed test.
- Export invalid input and canceled context tests.
- Recursive redaction tests for root and linked private note/EDD/audit sentinels.
- Deterministic export bundle JSON test.
- Export output DB/internal field guard test.
- Wave 10 migration SQL tests for export/dispute/export-item tables and forbidden sensitive markers.
- Projection tests for export DTO allowlists and AML-4 forbidden fields.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/exporting ./internal/projection ./tests`: passed. The Windows host printed a non-fatal Go telemetry token access warning.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: passed with `GOCACHE` set to a writable workspace cache. The Windows host printed the same non-fatal Go telemetry token access warning.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: passed with `GOCACHE` set to a writable workspace cache. The Windows host printed the same non-fatal Go telemetry token access warning.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.

The historical Wave 09 branch gate was not run as a current-branch gate because `000008_create_exports_disputes.sql` is the intentional Wave 10 expansion that the Wave 09 gate is designed to reject.

## 6. Documentation Updated

- API contract now records the planned secure export DTO shape while stating no export routes exist in W10-T01.
- Database model documents `disputes`, `exports`, and `export_items`.
- Visibility/projection docs document current export projection allowlists.
- Audit/export/graph invariants document recursive export redaction and AML-4 deferral.
- Testing strategy documents Wave 10 export tests and commands.
- Risk register adds R-044 for export redaction drift.

## 7. CTF Invariants Checked

- No checker PUT/GET path added.
- No public attack data added.
- No exploit or reference-fix script added.
- No planned AML-4 behavior added.
- No ForcAD config change.
- Owner note and owner EDD checker-candidate fields remain normal private business fields.

## 8. Security Invariants Checked

- Export output is public/redacted by default.
- Root and linked `CaseNote.body` values are omitted.
- Root and linked `EDDRecord.confidential_comment` values are omitted.
- Raw EDD narrative fields, raw audit diffs, audit value hashes, credentials, session material, checker-private markers, artificial flag fields, and raw DB rows are omitted.
- Non-owner root-case export creation fails closed through owner-scoped SQL.

## 9. Self-Review

The implementation stays in data-layer and projection boundaries. The repository methods use owner-scoped `cases` and `exports` queries rather than checker or direct broad access paths. The redaction primitives deliberately consume richer snapshots than they emit so tests can prove private fields are ignored recursively.

## 10. Risks / Open Questions

- W10-T02 still needs to expose authenticated export HTTP APIs using these DTOs without widening visibility.
- W10-T04 should add the current Wave 10 branch gate and update historical gate expectations.
- The local Windows Go profile prints a telemetry token access warning despite successful offline tests; this did not affect exit status.

## 11. Ready for Orchestrator Review

Yes.
