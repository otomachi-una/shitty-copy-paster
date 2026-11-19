# Wave 13 W13-T05 Handoff - Noise and Retention Guard

## 1. Summary

Implemented optional checker lifecycle actions for non-secret noise and added a
retention smoke guard to the Wave 13 CHECK/HAVOC framework. The checker can now
create and verify deterministic noise across customers, transactions, cases,
case notes, EDD, graph hints, exports, and network-room summaries where the
normal owner/public APIs support them. The retention smoke guard protects the
active flag-bearing tables from premature physical deletion patterns.

## 2. Implementation Details

- Added explicit `putnoise` and `getnoise` checker actions.
- Added MAC-protected `NoisePrivateState` encoding/decoding for checker-private
  noise locators and owner credentials.
- Added credential-free public noise data for non-secret locators only.
- Added deterministic noise fixture and idempotency-key helpers.
- Added `check_retention` as a default Wave 13 subcheck.
- Added a static retention scan over `case_notes` and `edd_records` for direct
  physical delete/truncate/drop patterns in migration, internal, and script
  sources.
- Preserved place 1 and place 2 PUT/GET semantics and owner-only retrieval
  paths.

## 3. Files Changed

- `checkers/sentinel_aml/checker.py`
- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_foundation.py`
- `tests/test_checker_check_workflow.py`
- `tests/test_wave13_gate.py`
- `scripts/check_wave13_gate.py`
- `docs/08_checker_design.md`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_13_W13-T05_handoff.md`

## 4. Tests Added

- Noise private-state round trip and tamper rejection.
- Public noise-data secret exclusion.
- `putnoise`/`getnoise` argument parsing and CLI output shape.
- Fake-service `putnoise`/`getnoise` workflow tests.
- Noise flag-store non-interference checks.
- Retention-sensitive table contract and static delete-pattern rejection.
- Wave 13 gate markers for noise actions and retention guard.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_checker_foundation.py"`:
  pass, 24 tests.
- `python -B -m unittest discover -s tests -p "test_checker_check_workflow.py"`:
  pass, 31 tests.
- `python -B -m unittest discover -s tests -p "test_wave13_gate.py"`:
  pass, 6 tests.
- `python -B scripts\check_wave13_gate.py`: pass.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  pass, 93 tests.
- `python -B scripts\check_docs_tree.py`: pass.
- `python -B scripts\validate_forcad_config.py`: pass.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: pass after setting
  workspace `GOCACHE`; Go still printed a sandboxed telemetry-token warning.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: pass after setting
  workspace `GOCACHE`; Go still printed a sandboxed telemetry-token warning.

## 6. Documentation Updated

- `docs/08_checker_design.md` documents `putnoise`, `getnoise`, the public and
  private noise-state split, and the retention smoke guard.
- `docs/12_testing_strategy.md` documents the Wave 13 noise/retention matrix
  and gate expectations.

## 7. CTF Invariants Checked

- Noise creation uses normal product APIs only.
- Noise data does not create a checker-only bypass path.
- Place 1 remains `CaseNote.body`; place 2 remains
  `EDDRecord.confidential_comment`.
- GET paths still use owner notes and owner EDD views only.
- No vulnerabilities, exploits, or reference fixes were added.

## 8. Security Invariants Checked

- Public noise data excludes credentials, tokens, sessions, flags, checker
  secrets, private state, note bodies, confidential comments, and private EDD
  fields.
- Noise writes non-secret note and EDD content only, so it does not interfere
  with checker flag stores.
- Checker source remains free of direct DB/import bypasses and hidden
  debug/admin/checker-only endpoints.
- Retention smoke protects `case_notes` and `edd_records`, the two active
  flag-bearing storage tables.

## 9. Self-Review

The implementation is intentionally conservative: noise is optional, uses the
same owner workflows as the existing checker, and stores all reusable sensitive
state in MAC-protected private data. Public output is locator-only. The static
retention check is a smoke guard, not a full data-retention policy engine.

## 10. Risks / Open Questions

- `make wave13-gate` could not be run in this Windows shell because `make` is
  not installed; equivalent component commands were run directly.
- Full `python -B -m unittest discover -s tests -p "test_*.py"` still has a
  historical Wave 11 gate expectation that place 2 GET should fail closed,
  which conflicts with the accepted Wave 12 two-place checker state.
- Go emits a telemetry-token warning under the sandbox even with a workspace
  build cache, but `go test` and `go vet` exit successfully.

## 11. Ready for Orchestrator Review

Yes.
