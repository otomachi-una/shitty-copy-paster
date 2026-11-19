# Wave 07 W07-T01 Handoff

## 1. Summary

Added the secure dedup metadata persistence foundation. `dedup_hint` is now placed on `cases` as non-secret matching metadata, and `internal/casework` can discover duplicate case candidates after verifying the source case belongs to the requesting owner. No HTTP dedup route, checker behavior, public attack data, planned vulnerability, exploit, or fix was added.

## 2. Implementation Details

- Added `migrations/000005_add_case_dedup_hint.sql`.
- Added `cases.dedup_hint text NOT NULL DEFAULT ''`.
- Added `cases_dedup_hint_not_blank_when_set`.
- Added `cases_dedup_hint_idx` and `cases_owner_dedup_hint_idx`.
- Extended `casework.Case` and `CreateCaseParams` with normalized `DedupHint`.
- Added `casework.DuplicateCandidate` with only safe case/customer metadata.
- Added `FindDuplicateCandidatesByOwner(ctx, ownerUserID, sourceCaseID)`:
  - honors canceled contexts before database work;
  - validates positive owner and case IDs;
  - verifies the source case by `owner_user_id` and `id`;
  - returns an empty list for blank dedup hints;
  - returns same-hint candidates excluding the source case;
  - avoids note, EDD, audit, credential, and checker-private joins/fields.

## 3. Files Changed

- `migrations/000005_add_case_dedup_hint.sql`
- `internal/casework/repository.go`
- `internal/casework/repository_test.go`
- `tests/migration_sql_test.go`
- `docs/02_domain_model.md`
- `docs/04_database_model.md`
- `docs/06_visibility_and_projections.md`
- `docs/09_vulnerability_matrix.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_07_W07-T01_handoff.md`

## 4. Tests Added

- `TestCreateCaseFromAlertNormalizesDedupHint`
- `TestFindDuplicateCandidatesByOwnerReturnsSameHintCandidates`
- `TestFindDuplicateCandidatesByOwnerReturnsEmptyForMissingHint`
- `TestFindDuplicateCandidatesByOwnerFailsClosedForOtherOwner`
- `TestFindDuplicateCandidatesByOwnerHonorsCanceledContext`
- `TestWave07MigrationAddsCaseDedupHint`
- `TestWave07MigrationsDoNotIntroduceOutOfScopeTablesOrSensitiveFields`

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/casework ./tests`: passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: passed.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.

Go commands were run with `GOCACHE=%TEMP%\sentinel-aml-go-cache` on this Windows host to avoid the known default Go build-cache access-denied issue.

## 6. Documentation Updated

- Domain model documents canonical `cases.dedup_hint` placement and safe candidate behavior.
- Database model documents migration, constraint, indexes, and serialization boundary.
- Visibility/projection docs document dedup metadata visibility and W07 no-route status.
- Vulnerability matrix clarifies AML-1 remains future-only.
- Testing strategy documents Wave 07 dedup metadata coverage.
- Execution log and risk register updated.

## 7. CTF Invariants Checked

- No checker PUT/GET behavior added.
- No public attack data added.
- No exploit or reference-fix scripts added.
- No artificial flag fields added.
- `CaseNote.body` and `EDDRecord.confidential_comment` remain private business fields.

## 8. Security Invariants Checked

- Dedup candidate discovery first verifies source case ownership.
- Candidate discovery does not join or return case notes, EDD records, audit payloads, credentials, session material, or checker-private fields.
- Empty dedup hints do not trigger broad candidate scans.
- Repository methods accept `context.Context` and honor cancellation before DB work.
- No sensitive fields are logged.

## 9. Self-Review

The implementation follows the recommended placement of `cases.dedup_hint`, so no ADR was needed. The repository returns internal safe metadata only and does not create route surface. Existing HTTP DTOs and projection contracts were left unchanged because W07-T01 does not expose dedup candidates over HTTP.

## 10. Risks / Open Questions

- Future W07 HTTP work must define an explicit DTO before exposing candidate data.
- Future AML-1 vulnerability work must not reuse this secure repository path to leak private note or EDD fields.
- Historical Wave 06 gate scripts may reject the intentional Wave 07 migration expansion; Wave 07-specific validation should supersede them when added.

## 11. Ready for Orchestrator Review

Yes.
