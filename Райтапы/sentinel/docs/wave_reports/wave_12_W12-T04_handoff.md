# Wave 12 W12-T04 Handoff - Multi-Place Checker Regression and Security Matrix

## 1. Summary

W12-T04 adds the current Wave 12 checker gate and regression tests for the
multi-place checker matrix. The gate validates that place 1 remains active,
place 2 is active, public/private PFR data stays separated, cross-place state
confusion fails, GET paths use owner views only, and checker source avoids
DB/internal, hidden, side-view, exploit, and fix behavior.

## 2. Implementation Details

- Added `scripts/check_wave12_gate.py`.
- Added `tests/test_wave12_gate.py`.
- Added `make wave12-gate`.
- Updated `docs/12_testing_strategy.md` with the Wave 12 multi-place checker
  security matrix.
- Preserved the historical Wave 11 gate and documented that it is no longer the
  current-branch authority after Wave 12 place 2 activation.

## 3. Files Changed

- `Makefile`
- `scripts/check_wave12_gate.py`
- `tests/test_wave12_gate.py`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_12_W12-T04_handoff.md`

## 4. Tests Added

- Wave 12 gate current-branch success test.
- DB/internal checker marker rejection test.
- Side-view checker GET source rejection test.
- Place 2 deactivation rejection test.
- Public attack-data secret leak rejection test.
- Exploit/fix script rejection test.
- Missing Wave 12 handoff/docs rejection test.
- Missing Makefile target rejection test.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_*checker*.py"`: passed,
  58 tests.
- `python -B -m unittest discover -s tests -p "test_wave12_gate.py"`:
  passed, 8 tests.
- `python -B scripts/check_wave12_gate.py`: passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: passed with
  workspace-local Go cache settings on this Windows host.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: passed with
  workspace-local Go cache settings on this Windows host.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.
- `python -B -m unittest discover -s tests -p "test_*.py"`: failed with one
  legacy Wave 11 gate assertion. `tests/test_wave11_gate.py` still expects
  `scripts/check_wave11_gate.py` to report place 2 GET parsing as unsupported;
  Wave 12 intentionally supports active place 2 PUT/GET.
- `make wave12-gate`: not executable on this host because `make`,
  `mingw32-make`, and `gmake` are not installed. The target exists and each
  command in the target was run directly and passed.

## 6. Documentation Updated

- `docs/12_testing_strategy.md` now documents the Wave 12 gate, active
  multi-place checker coverage, non-goals, and the distinction between the
  historical Wave 11 gate and the current Wave 12 gate.

## 7. CTF Invariants Checked

- Both flag stores remain active only through checker owner workflows.
- Public attack data remains credential-free and flag-free.
- Checker GET uses owner views only.
- No planned vulnerability behavior is introduced.

## 8. Security Invariants Checked

- Gate tests fail on obvious public attack-data secret markers.
- Gate tests fail on checker source references to DB/internal packages.
- Gate tests fail on checker GET side-view endpoint markers.
- Gate tests fail on exploit/fix script creation.

## 9. Self-Review

The Wave 12 gate is intentionally current-branch oriented. It does not weaken
the historical Wave 11 gate; instead it supersedes it for branches where place
2 activation is intentional.

## 10. Risks / Open Questions

- Full `test_*.py` discovery still includes the historical Wave 11 gate, which
  expects place 2 parsing to fail. This remains a known orchestration mismatch
  unless the old gate is retired or updated outside W12-T04 scope.

## 11. Ready for Orchestrator Review

No. The Wave 12 gate and its component commands pass, but full Python discovery
is still blocked by the historical Wave 11 gate assertion and this host cannot
execute `make wave12-gate` because no `make` binary is installed.
