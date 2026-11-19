# Wave 28 W28-F02 Handoff - Gate and Competition Matrix Final Fix Cells

## 1. Summary

W28-F02 adds the missing Wave 28 gate script, unittest coverage, and Makefile
target, then aligns the competition matrix so AML-5 fixed-checker,
exploit-blocked, and anti-coarse-fix cells are concrete alongside AML-1 through
AML-4. Wave 28 remains validation evidence only; competition readiness still
requires a later full regression/final packaging wave.

## 2. Implementation Details

- Added `scripts/check_wave28_gate.py` with JSON pass/fail output.
- Added `tests/test_wave28_gate.py` covering the current branch, AML-5 patch
  inventory, patch scope, exploit-blocked evidence, anti-coarse-fix evidence,
  and Makefile target coverage.
- Updated `scripts/check_competition_matrix_gate.py` to require exactly five
  reference exploits and exactly five standard reference fix patches.
- Updated competition matrix tests to assert AML-5 fix cells are concrete and
  missing/nonstandard fix inventory is rejected.
- Added `wave28-gate` to the Makefile with checker tests, Wave 28 tests,
  runner liveness tests, matrix tests, five exploit compile checks, five patch
  apply checks, bounded release/offline Go tests, Go vet, Wave 28 gate, matrix
  gate, docs tree, ForcAD validation, and archive hygiene.

## 3. Files Changed

- `scripts/check_wave28_gate.py`
- `tests/test_wave28_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/09_vulnerability_matrix.md`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_28_W28-F02_handoff.md`

## 4. Tests Added

- Wave 28 positive current-branch validation.
- Negative tests for missing AML-5 patch, extra nonstandard fixes, docs-only
  fixes, gate-only fixes, outside-scope targets, endpoint/dossier/worker
  removal, sensitive-field renames, raw private data reintroduction,
  debug/admin/direct DB shortcuts, and unbounded Go test Makefile steps.
- Exploit evidence tests proving `aml_network_room.py` succeeds against
  vulnerable dossier output and fails safely against fixed public dossier output.
- Matrix tests for all five fixes concrete.

## 5. Tests Run

| Command | Exit | Evidence |
| --- | ---: | --- |
| `python -B -m unittest discover -s tests -p "test_wave28_gate.py"` | 0 | 18 tests passed. |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | 0 | 32 tests passed. |
| `python -B scripts/check_wave28_gate.py` | 0 | Wave 28 JSON gate passed. |
| `python -B scripts/check_competition_matrix_gate.py` | 0 | Competition matrix JSON gate passed with all five fix cells concrete. |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | 0 | 97 checker tests passed. |
| `python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"` | 0 | 2 runner liveness tests passed. |
| External-cache `python -B -m py_compile` for all five exploits | 0 | All five exploit scripts compile without repo-local bytecode. |
| `git apply --check --whitespace=error` for AML-1 through AML-5 patches | 0 | All five patch artifacts apply cleanly. |
| `python -B scripts/run_go_release_tests.py --go go --package-timeout 120` | 0 | Package-by-package release/offline Go tests passed. |
| Release/offline `go vet ./...` with temp `GOCACHE`/`APPDATA` | 0 | Go vet passed. |
| `python -B scripts/check_docs_tree.py` | 0 | Docs tree passed. |
| `python -B scripts/validate_forcad_config.py` | 0 | ForcAD config shape passed. |
| `python -B scripts/check_archive_hygiene.py` | 0 | Archive hygiene passed. |
| `timeout 300 make wave28-gate` | 1 | Windows `TIMEOUT.EXE` rejected GNU syntax: `Invalid syntax`. |
| `make wave28-gate` | 1 | `make` is not installed on this Windows host. |
| `bash -lc "timeout 300 make wave28-gate"` | 1 | Bash/WSL launch failed with `E_ACCESSDENIED`. |

## 6. Documentation Updated

`docs/09_vulnerability_matrix.md` now records AML-5 fix evidence as concrete in
Wave 28 validation while keeping final readiness pending.
`docs/12_testing_strategy.md` now documents Wave 28 gate scope, negative tests,
and aggregate gate commands.

## 7. CTF Invariants Checked

- All five reference exploits remain part of the gate.
- All five reference fix patches must apply cleanly.
- Checker PUT/GET and CHECK/HAVOC preservation remain gate requirements.
- Final competition readiness is not claimed by Wave 28.

## 8. Security Invariants Checked

- The Wave 28 gate rejects fixed network-room dossiers that leak foreign private
  notes, EDD confidential comments, audit diffs, hashes, credentials, sessions,
  checker-private state, raw DB rows, debug/admin paths, or sensitive-field
  renames.
- The gate rejects endpoint/dossier/worker removal and other coarse fixes.

## 9. Self-Review

No product behavior, checker behavior, sploit behavior, patch semantics, public
attack data, migrations, or deployment config were changed. Earlier wave gates
were not weakened. The matrix now requires the planned final fix inventory
exactly and continues to reject nonstandard extras.

## 10. Risks / Open Questions

- Wave 28 closes individual fix-cell validation only. A final regression and
  packaging wave still needs to run before competition readiness can be claimed.
- The exact GNU `timeout 300 make wave28-gate` wrapper could not be executed on
  this Windows host because GNU timeout/make are unavailable. The Makefile
  target exists and all target component commands passed when run directly.

## 11. Ready for Orchestrator Review

yes, for orchestrator review in an environment with GNU `timeout` and `make`.
