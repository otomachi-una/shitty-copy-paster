# Wave 08 W08-T03 Handoff - Anti-AML-2 Regression and Source Guards

## 1. Summary

W08-T03 adds test-only security guardrails for the secure audit baseline. The new coverage proves that audit timeline and deferred activity surfaces do not expose private case-note bodies, EDD confidential comments, raw audit diffs, value hashes, credentials, session material, checker-private markers, raw database rows, or artificial flag fields.

AML-2 remains locked until Wave 15. No production behavior, vulnerability toggle, exploit, or fix script was added.

## 2. Implementation Details

- Added named Anti-AML-2 HTTP regression coverage that plants high-entropy private note and EDD sentinels.
- Verified owner-only note and EDD endpoints still return their legitimate owner private business values.
- Verified owner case timeline responses omit planted private sentinels and raw audit internals.
- Verified cross-owner and unauthenticated timeline responses fail closed without private sentinels.
- Verified deferred customer activity and entity activity routes remain absent and body-safe.
- Added source-level guardrails around audit HTTP DTOs and presenters to reject obvious raw private-field or raw-diff exposure.
- Added projection tests that explicitly reject AML-2-forbidden fields in `OwnerCaseAuditView` and `OwnerCaseAuditChangeView`.

## 3. Files Changed

- `internal/httpapi/audit_timeline_test.go`
- `internal/projection/contracts_test.go`
- `tests/projection_visibility_test.go`
- `docs/06_visibility_and_projections.md`
- `docs/09_vulnerability_matrix.md`
- `docs/12_testing_strategy.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_08_W08-T03_handoff.md`

## 4. Tests Added

- `TestAntiAML2AuditTimelineDoesNotExposePrivateStores`
- `TestOwnerCaseAuditProjectionContractRejectsAML2Fields`
- `TestAuditHTTPDTOAndPresenterRejectAML2RawExposure`

The new source guard rejects audit DTO/presenter exposure of:

- raw `body`
- raw `confidential_comment`
- raw `diff_json`
- `old_hash` / `new_hash`
- `password_hash`
- `token_hash`
- session markers
- checker-private markers
- `flag_value`
- actor/owner/analyst/author database-only IDs
- direct audit event serialization shortcuts

## 5. Tests Run

Passed:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/projection ./tests -run "Audit|Timeline|AML2|Visibility|Projection" -count=1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
```

Blocked by historical gate expectations outside W08-T03 file scope:

```sh
python -B -m unittest discover -s tests -p 'test_*.py'
```

The Python unittest command fails only in historical Wave 05-07 gate tests:

- `test_wave05_gate_is_historical_after_wave07_expansion` now sees the intentional W08 `audit_events` table as an additional historical failure.
- `test_wave06_gate_is_historical_after_wave07_expansion` now sees the intentional W08 `audit_events` table as an additional historical failure.
- `test_wave07_gate_current_branch_has_no_failures` now rejects the intentional W08 audit migration and secure audit timeline activation.

The earlier Wave 01 static debug/admin marker failures were fixed by keeping the runtime route probes while avoiding forbidden source literals.

## 6. Documentation Updated

- `docs/06_visibility_and_projections.md` now names the Anti-AML-2 tests and source guards.
- `docs/09_vulnerability_matrix.md` now documents AML-2 as a future Wave 15 audit timeline vulnerability and states the secure Wave 08 baseline.
- `docs/12_testing_strategy.md` now lists the Anti-AML-2 command and coverage.
- `docs/15_risk_register.md` adds `R-038` for Anti-AML-2 guard drift.

## 7. CTF Invariants Checked

- No checker behavior was added.
- No public attack data was added.
- No exploit or reference-fix script was added.
- No planned vulnerability behavior was added.
- Existing secure dedup behavior remains covered by the focused test pattern.
- Existing owner note and owner EDD paths remain functional.

## 8. Security Invariants Checked

- Audit views do not expose note bodies, EDD confidential comments, raw diffs, credentials, session material, raw DB rows, checker-private state, or artificial flag fields.
- Timeline permission remains separate from sensitive-field visibility.
- Projection allowlists remain explicit.
- Cross-owner timeline behavior remains fail-closed.
- Deferred activity routes remain absent and do not leak private sentinels.

## 9. Self-Review

This task intentionally changed only tests and documentation. The new Anti-AML-2 test verifies both sides of the contract: private stores are still available through their legitimate owner-only endpoints, while audit timeline/activity surfaces do not disclose those private values.

The source guard is intentionally scoped to the audit DTO and presenter sections rather than the full server file because the server must still contain owner note and EDD DTOs that legitimately expose private business fields to the owner.

## 10. Risks / Open Questions

- A full Wave 08 branch gate is still expected in W08-T04.
- Production binary audit wiring remains the W08-T02 file-scope caveat unless a follow-up explicitly allows `cmd/aml-api/main.go`.
- Source guards are pattern-based and protect against obvious raw exposure; runtime sentinel tests remain the stronger behavioral proof.

## 11. Ready for Orchestrator Review

No. Anti-AML-2 implementation and focused validation are complete, but the full Python unittest command remains blocked by historical Wave 05-07 gate expectations that are outside the W08-T03 allowed edit scope.
