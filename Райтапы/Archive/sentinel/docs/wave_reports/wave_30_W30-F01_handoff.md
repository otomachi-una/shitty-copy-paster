# W30-F01 Handoff - Stabilize Final Aggregate Gate Liveness

## 1. Summary

Stabilized the final aggregate `wave29-gate` so the exact
`timeout 300 make wave29-gate` command exits within the 300-second review
bound while preserving all checker, matrix, sploit, patch, vulnerable-profile,
release/offline Go, vet, docs, ForcAD, archive hygiene, and regression
evidence.

## 2. Implementation Details

- Added `scripts/run_vulnerable_profile_tests.py` to run AML-1 through AML-5
  focused vulnerable-profile package checks with one shared out-of-repository
  GOCACHE/APPDATA pair for the aggregate invocation.
- Updated `wave29-gate` to call the vulnerable-profile helper instead of five
  cache-cold tagged Go test Makefile lines.
- Updated `scripts/run_go_release_tests.py` so the untagged release/offline
  package runner reuses one shared out-of-repository GOCACHE/APPDATA pair
  across package tests while retaining per-package names, timeouts, and
  subprocess cleanup.
- Added unit coverage for the new vulnerable-profile helper and for shared
  cache reuse in the Go release runner.
- Updated Wave 29 static gate checks to require the helper and reject a return
  to cache-cold direct tagged lines or full tagged `./...` sweeps.
- Changed `competition-matrix-gate` to use `$(PYTHON)` so make-equipped hosts
  without a `python` binary can still use the existing `PYTHON` fallback.

## 3. Files Changed

- `Makefile`
- `scripts/run_go_release_tests.py`
- `scripts/run_vulnerable_profile_tests.py`
- `scripts/check_wave29_gate.py`
- `tests/test_run_go_release_tests.py`
- `tests/test_run_vulnerable_profile_tests.py`
- `tests/test_wave29_gate.py`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_30_final_validation_summary.md`
- `docs/wave_reports/wave_30_release_readiness_manifest.md`
- `docs/wave_reports/wave_30_W30-F01_handoff.md`

## 4. Tests Added

- Vulnerable-profile helper runs all five AML tags with one shared external
  cache/appdata pair.
- Vulnerable-profile helper returns bounded failure on a stuck package command.
- Release Go runner reuses one shared external cache/appdata pair across
  packages.
- Wave 29 static gate rejects missing vulnerable-profile helper coverage and
  duplicate full tagged sweeps inside `wave29-gate`.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_run_vulnerable_profile_tests.py"` -
  exit 0, 2 tests.
- `python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"` -
  exit 0, 3 tests.
- `python -B -m unittest discover -s tests -p "test_wave29_gate.py"` -
  exit 0, 11 tests.
- `python -B scripts/check_wave29_gate.py` - exit 0.
- `timeout 300 make wave29-gate` - exit 0, elapsed 3m39.837s on the final
  settled-tree rerun.
- `python -B scripts/check_archive_hygiene.py` - exit 0.

## 6. Documentation Updated

- Updated the testing strategy with the W30-F01 shared-cache liveness design
  and final aggregate command evidence.
- Updated the Wave 30 final validation summary with the corrected W30-F01 gate
  result and preserved-evidence list.
- Updated the release-readiness manifest to allow shared out-of-repository
  release caches while preserving required evidence coverage.

## 7. CTF Invariants Checked

- ForcAD checker type remains `pfr`.
- Exactly two checker places remain active.
- Place 1 remains `CaseNote.body`; place 2 remains
  `EDDRecord.confidential_comment`.
- Checker GET remains owner-view only.
- All five vulnerabilities, sploits, and fixes remain represented.
- CHECK/HAVOC remains release-blocking.

## 8. Security Invariants Checked

- No sensitive field exposure, side-view widening, direct DB path, hidden
  debug/admin path, or product endpoint behavior changed.
- Caches are created outside the repository and archive hygiene remains green.

## 9. Self-Review

The fix changes release-gate execution structure only. It preserves the same
matrix evidence and makes the expensive Go phases cache-warm within a single
aggregate invocation without moving caches into the repository or increasing
the 300-second timeout.

## 10. Risks / Open Questions

- The local proof uses WSL because this Windows host lacks native GNU
  `timeout`/`make`; the command inside WSL is the required
  `timeout 300 make wave29-gate`.
- Final Wave 30 acceptance remains orchestrator-only.

## 11. Ready for Orchestrator Review

yes
