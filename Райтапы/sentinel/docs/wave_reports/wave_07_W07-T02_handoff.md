# Wave 07 W07-T02 Handoff

## 1. Summary

Added secure authenticated dedup endpoints and projection wiring. Owners can list duplicate candidates for an owned source case and request a secure merge preview for a valid same-hint candidate. Dedup responses use explicit DTOs and expose only public overlap metadata. AML-1 vulnerable note leakage is not implemented.

## 2. Implementation Details

- Extended the HTTP casework repository interface with `FindDuplicateCandidatesByOwner`.
- Added optional `dedup_hint` input to case creation so normal owner workflows can seed non-secret matching metadata.
- Added `GET /api/cases/{case_id}/duplicates`.
- Added `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`.
- Added explicit DTOs:
  - `CaseDuplicatePreviewView`
  - `CaseDuplicateCandidatesResponse`
  - `CaseDuplicateMergePreviewResponse`
- Added projection allowlist entry `case_duplicate_preview` with fields:
  - `case_id`
  - `public_summary`
  - `risk_tags`
  - `overlap_score`
  - `match_explanation`
- Merge preview validates candidate membership by reusing repository same-hint candidate discovery and returns `404 not_found` for non-candidates.

## 3. Files Changed

- `internal/httpapi/server.go`
- `internal/httpapi/domain_server_test.go`
- `internal/httpapi/visibility_leak_test.go`
- `internal/projection/contracts.go`
- `internal/projection/contracts_test.go`
- `docs/03_api_contract.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_07_W07-T02_handoff.md`

## 4. Tests Added

- `TestSecureDedupEndpointsExposeOnlyPublicOverlap`
- Updated `TestVisibilitySentinelStringsStayOnOwnerOnlyEndpoints` to probe dedup list and merge-preview endpoints for private sentinel non-leakage.
- Updated projection contract tests for `case_duplicate_preview`.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/projection ./internal/casework -run "Dedup|Visibility|Projection|Duplicate" -count=1`: passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: passed.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.

Go commands were run with `GOCACHE=%TEMP%\sentinel-aml-go-cache` on this Windows host to avoid the known default Go build-cache access-denied issue.

## 6. Documentation Updated

- API contract documents dedup routes, response fields, optional case `dedup_hint`, and fail-closed behavior.
- Authz docs document source-case ownership and public-only candidate visibility.
- Visibility/projection docs document `CaseDuplicatePreviewView` and the secure baseline.
- Testing strategy documents Wave 07 secure dedup endpoint coverage.
- Execution log and risk register updated.

## 7. CTF Invariants Checked

- No checker PUT/GET behavior added.
- No public attack data added.
- No planned vulnerable AML-1 behavior added.
- No exploit or reference-fix scripts added.
- Secure merge-preview keeps future checker owner paths unaffected.

## 8. Security Invariants Checked

- Source cases must be owned by the authenticated analyst.
- Merge-preview candidates must be returned by same-hint repository discovery.
- Dedup responses omit private notes, note bodies, EDD confidential comments, internal evidence, audit diffs, credentials, session fields, checker-private markers, and raw DB rows.
- Cross-owner source requests fail closed.

## 9. Self-Review

The implementation adds route surface only for secure dedup list and merge-preview endpoints. It does not add graph, export, network, audit, checker, attack-data, exploit, or fix behavior. The future AML-1 leak remains intentionally absent.

## 10. Risks / Open Questions

- Future AML-1 work must introduce any vulnerable merge-preview behavior only in its scoped vulnerability wave and with exploit/fix evidence.
- Future Wave 07 gate work should update current-branch gate scripts so historical W06 route expectations do not act as the current authority.

## 11. Ready for Orchestrator Review

Yes.
