# W14-T01 Handoff — AML-1 Vulnerable Dedup Preview Profile

## 1. Summary

W14-T01 introduces AML-1 as a controlled `aml1_vulnerable` Go source profile.
Only the tagged profile changes dedup merge-preview to expose duplicate
`private_notes[].body`; the default profile remains secure and public-only.

## 2. Implementation Details

- Added default and `aml1_vulnerable` profile files under `internal/httpapi`.
- Routed merge-preview through a profile-specific response helper.
- Added a targeted casework repository lookup for duplicate private notes,
  scoped by requester-owned source case plus shared `dedup_hint`.
- Preserved duplicate candidate discovery and public metadata.
- Kept EDD comments, EDD narrative fields, audit diffs, credentials, sessions,
  checker-private state, and unrelated internals out of AML-1 output.

## 3. Files Changed

- `internal/casework/repository.go`
- `internal/casework/repository_test.go`
- `internal/httpapi/server.go`
- `internal/httpapi/dedup_profile_secure.go`
- `internal/httpapi/dedup_profile_aml1_vulnerable.go`
- `internal/httpapi/domain_server_test.go`
- `internal/httpapi/aml1_vulnerable_dedup_test.go`
- `scripts/check_wave14_gate.py`
- `tests/test_wave14_gate.py`
- `docs/09_vulnerability_matrix.md`
- `docs/06_visibility_and_projections.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_14_validation_summary.md`
- `docs/wave_reports/wave_14_W14-T01_handoff.md`

## 4. Tests Added

- Repository test for the targeted duplicate private-note lookup.
- Tagged AML-1 positive HTTP test for merge-preview private note body exposure.
- Wave 14 gate script regression tests.

## 5. Tests Run

Passed:

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml1_vulnerable ./internal/httpapi -run TestAML1VulnerableDedupMergePreviewExposesOnlyDuplicatePrivateNotes -count=1 -v`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml1_vulnerable ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: 97 tests
- `python -B -m unittest discover -s tests -p "test_wave14_gate.py"`: 5 tests
- `python -B -m unittest discover -s tests -p "test_*.py"`: 219 tests
- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave14_gate.py`
- `python -B scripts/validate_forcad_config.py`
- `python -B scripts/check_competition_matrix_gate.py`

`make wave14-gate` was not added because W14-T01 file scope did not include the
Makefile.

## 6. Documentation Updated

- Vulnerability matrix documents AML-1 as implemented only in the
  `aml1_vulnerable` profile and keeps exploit/fix waves locked.
- Projection docs describe the default secure profile and the tagged AML-1
  merge-preview projection.
- Testing strategy documents default and tagged gate commands.
- Risk register records AML-1 scope guardrails.

## 7. CTF Invariants Checked

- Checker PUT/GET owner paths are not changed.
- CHECK/HAVOC remains independent of the AML-1 side view.
- No exploit script or reference fix is added.
- Public attack data remains credential-free and raw-flag-free.

## 8. Security Invariants Checked

- AML-1 is local to dedup merge-preview.
- EDD comments, audit diffs, credentials, sessions, checker-private state,
  debug/admin toggles, and direct DB checker access remain excluded.

## 9. Self-Review

The vulnerable behavior is intentionally isolated behind a Go build tag and a
single profile helper. The default secure profile still returns the historical
public-only DTO.

## 10. Risks / Open Questions

- The reference exploit is intentionally deferred until Wave 19.
- The reference fix is intentionally deferred until Wave 24.

## 11. Ready for Orchestrator Review

Yes.
