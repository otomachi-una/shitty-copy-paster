# Wave 07 W07-T03 Handoff - Dedup Visibility Regression and Anti-AML-1 Tests

## 1. Summary

W07-T03 adds explicit anti-AML-1 regression coverage for the secure dedup side-view endpoints. The tests plant victim private `CaseNote.body` and `EDDRecord.confidential_comment` sentinel values on a duplicate candidate and verify that secure dedup list and merge-preview responses remain public-only.

Ready for orchestrator review: yes.

## 2. Implementation Details

- Added `TestAntiAML1DedupMergePreviewDoesNotLeakCandidatePrivateData` to prove the secure merge-preview does not disclose duplicate private notes or EDD confidential comments.
- Added `TestCaseDuplicatePreviewResponseShapeIsStable` to lock dedup list and merge-preview JSON to the expected public DTO fields.
- Expanded dedup response leak assertions to reject private note, EDD, audit/diff, auth/session, owner identifier, raw DB row, checker-private, and artificial flag markers.
- Added projection contract tests that forbid private fields in current side-view projection contracts.
- Added source-level tests that inspect the dedup DTO and presenter section to prevent accidental direct references to private note or EDD store structs/fields.
- Updated documentation to clarify that Wave 07 has secure dedup HTTP endpoints, while AML-1 remains future-only.

## 3. Files Changed

- `internal/httpapi/domain_server_test.go`
- `internal/projection/contracts_test.go`
- `tests/projection_visibility_test.go`
- `tests/test_wave04_gate.py`
- `tests/test_wave05_gate.py`
- `tests/test_wave06_gate.py`
- `docs/06_visibility_and_projections.md`
- `docs/09_vulnerability_matrix.md`
- `docs/12_testing_strategy.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_07_W07-T03_handoff.md`

## 4. Tests Added

- HTTP anti-AML-1 private sentinel regression for dedup merge-preview and duplicate list.
- HTTP dedup response-shape regression for `CaseDuplicatePreviewView`.
- Current side-view projection contract private-field denial.
- Source guardrail for dedup DTO/presenter private store references.
- Historical Wave 04, Wave 05, and Wave 06 gate unit expectations now recognize secure Wave 07 dedup expansion while leaving the underlying historical gate scripts strict.

Forbidden examples covered include `body`, `CaseNote`, `confidential_comment`, `EDDRecord`, `private_notes`, `audit`, `diff`, `password_hash`, `token_hash`, `session`, `owner_user_id`, `analyst_user_id`, `author_user_id`, `assigned_user_id`, `checker_private`, and `flag_value`.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run "Dedup|AML1|Visibility|CaseDuplicatePreview" -count=1` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/projection ./tests -run "Projection|Dedup" -count=1` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` - passed.

All Go commands were run with a local writable `GOCACHE` under `%TEMP%`.

## 6. Documentation Updated

- `docs/06_visibility_and_projections.md` now documents W07-T03 anti-AML-1 sentinels, response-shape locking, and source guardrails.
- `docs/09_vulnerability_matrix.md` now states that secure Wave 07 dedup HTTP endpoints exist and remain public-only.
- `docs/12_testing_strategy.md` now lists the anti-AML-1, response-shape, projection, and source guard tests plus focused commands.
- `docs/15_risk_register.md` now tracks anti-AML-1 regression drift as mitigated by named tests and source guards.

## 7. CTF Invariants Checked

- AML-1 vulnerable behavior is not implemented.
- No checker PUT/GET behavior was added.
- No public attack data was added.
- No exploit or reference-fix scripts were added.
- Future checker owner note paths remain unaffected by secure dedup tests.

## 8. Security Invariants Checked

- Duplicate candidate visibility does not grant private investigation visibility.
- Secure merge-preview exposes only public overlap metadata.
- Private note and EDD confidential sentinels are absent from dedup responses.
- Auth/session, owner identifier, raw DB row, and checker-private markers are rejected from dedup responses/projections.

## 9. Self-Review

The implementation is test-only plus documentation and stays within W07-T03 scope. The secure contract chosen is that dedup responses may expose candidate public summaries and deterministic match metadata, but never private investigation bodies or confidential EDD comments. The new tests are designed to fail if a future edit adds `body`, `confidential_comment`, private-store structs, or similar markers to current dedup DTOs/presenters.

## 10. Risks / Open Questions

- Live PostgreSQL dedup leak coverage remains tied to broader opt-in integration paths; W07-T03 focused on DB-free HTTP/projection regression coverage.
- Future AML-1 implementation must intentionally update these secure baseline tests or add vulnerability-wave-specific fixtures without weakening historical secure gate expectations.

## 11. Ready for Orchestrator Review

yes
