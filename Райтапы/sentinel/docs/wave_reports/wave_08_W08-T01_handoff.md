# Wave 08 W08-T01 Handoff - Audit Persistence and Redaction Primitives

## 1. Summary

W08-T01 adds the secure audit persistence foundation for Sentinel AML. It introduces `audit_events`, an `internal/audit` repository, and redaction primitives that convert sensitive field changes into `[redacted]` records with deterministic `sha256:` hashes before `diff_json` is persisted.

Ready for orchestrator review: yes.

## 2. Implementation Details

- Added ordered migration `000006_create_audit_events.sql`.
- Added `internal/audit.Repository` with:
  - `Create(ctx, CreateParams)` for append-only audit event creation;
  - `ListCaseTimelineByOwner(ctx, ownerUserID, caseID)` as a safe owner-scoped timeline primitive for W08-T02;
  - validation for object type, event type, visibility scope, positive IDs, and public message presence;
  - context cancellation checks before database work.
- Added `FieldChange`, `RedactedFieldChange`, `RedactedDiffJSON`, `IsSensitiveField`, and `HashValue`.
- Sensitive diff fields such as `body`, `case_note.body`, `confidential_comment`, `edd_record.confidential_comment`, password/token/session fields, checker-private markers, and artificial flag fields are redacted before insert.
- Repository callers cannot pass raw `diff_json`; the public create helper builds sanitized JSON from structured field changes.

## 3. Files Changed

- `migrations/000006_create_audit_events.sql`
- `internal/audit/repository.go`
- `internal/audit/repository_test.go`
- `tests/migration_sql_test.go`
- `docs/04_database_model.md`
- `docs/06_visibility_and_projections.md`
- `docs/10_workers_and_async_flows.md`
- `docs/12_testing_strategy.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_08_W08-T01_handoff.md`

## 4. Tests Added

- Migration ordering updated through `000006_create_audit_events.sql`.
- Migration SQL coverage for `audit_events` fields, constraints, and indexes.
- Audit repository create/list happy-path tests.
- Redaction tests proving raw `CaseNote.body` and `EDDRecord.confidential_comment` sentinels are absent from persisted `diff_json`.
- Deterministic redaction/hash test.
- Invalid object type, event type, visibility scope, missing public message, invalid IDs, and malformed diff-field validation tests.
- Context cancellation tests for create and list operations.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/audit ./tests` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.

Go commands used vendor mode and a local writable `GOCACHE` under `%TEMP%`.

## 6. Documentation Updated

- `docs/04_database_model.md` documents `audit_events`, constraints, indexes, redaction format, and W08 exclusions.
- `docs/06_visibility_and_projections.md` documents audit persistence visibility, sensitive-field denylist, and AML-2 deferral.
- `docs/10_workers_and_async_flows.md` documents that workers do not process audit events in Wave 08.
- `docs/12_testing_strategy.md` documents Wave 08 audit persistence tests and commands.
- `docs/15_risk_register.md` adds audit diff private-value persistence risk mitigation.

## 7. CTF Invariants Checked

- No checker PUT/GET path was added.
- No public attack data was added.
- No vulnerability behavior was added.
- No exploit or reference-fix script was added.
- No direct DB checker dependency was added.
- `CaseNote.body` and `EDDRecord.confidential_comment` remain normal private business fields only.

## 8. Security Invariants Checked

- Raw private note bodies and EDD confidential comments are redacted before `diff_json` persistence.
- Redacted sensitive values include deterministic `sha256:` hashes for comparison without disclosure.
- Audit repository outputs do not introduce credentials, password hashes, token hashes, session data, raw DB rows, or checker-private fields.
- Case timeline listing is scoped through an owner-verified case query.

## 9. Self-Review

This implementation adds persistence and repository primitives only. It deliberately does not wire audit capture into existing product operations yet and does not register an HTTP audit timeline route. The public repository create path avoids raw `diff_json` inputs so normal callers use the shared redaction policy.

## 10. Risks / Open Questions

- W08-T02 still needs to decide the exact HTTP timeline projection shape and route-level authorization behavior.
- Audit event creation is available as a primitive but is not yet wired into existing customer/case/EDD workflows.
- Earlier current-branch gates, such as the Wave 07 gate, may become historical and reject the intentional Wave 08 audit migration until a W08 gate is added.

## 11. Ready for Orchestrator Review

yes
