# W19-T02 Handoff - AML-1 Exploit Gate and Matrix Evidence

## 1. Summary

Strengthened Wave 19 validation without changing product code, checker code, or
exploit behavior. The gate now proves Wave 19 contains exactly one reference
exploit, keeps reference fixes absent, validates CLI/import-safe exploit shape,
and ties matrix evidence to the accepted AML-1 exploit-success cell.

## 2. Implementation Details

- Added a dedicated Wave 19 exploit CLI/import-safety check requiring parser,
  main entrypoint, main guard, and no import-time HTTP/exploit execution.
- Tightened fix validation so `fixes/sentinel_aml/` must remain README-only;
  nonstandard filenames, nested files, and future fix artifacts are rejected.
- Added `test_competition_matrix_gate.py` to the `make wave19-gate` wrapper so
  matrix evidence is executed with the Wave 19 closure target.
- Added a competition-matrix sequence check requiring exactly
  `aml_dedup_preview.py` under `sploits/sentinel_aml/` and no fix artifacts
  beyond `fixes/sentinel_aml/README.md`.
- Preserved the existing matrix interpretation: AML-1 exploit-success is
  concrete; AML-2 through AML-5 exploits remain pending; all fixes remain
  pending.

## 3. Files Changed

- `scripts/check_wave19_gate.py`
- `tests/test_wave19_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/wave_reports/wave_19_W19-T02_handoff.md`

## 4. Tests Added

- CLI help/import-safe exploit behavior coverage.
- Import-time exploit execution rejection coverage.
- README-only reference-fix directory rejection coverage.
- Competition matrix sequence coverage for exactly one Wave 19 exploit and no
  fix artifacts.
- Competition matrix rejection coverage for extra exploit scripts and
  nonstandard fix artifacts.

## 5. Tests Run

All final W19-T02 validation commands passed:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: 97 tests
  passed.
- `python -B -m unittest discover -s tests -p "test_wave19_gate.py"`: 15 tests
  passed.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  19 tests passed.
- `python -B -m py_compile scripts/check_wave19_gate.py scripts/check_competition_matrix_gate.py tests/test_wave19_gate.py tests/test_competition_matrix_gate.py`:
  passed.
- `python -B scripts/check_wave19_gate.py`: passed with checks for exactly one
  AML-1 exploit, CLI/import safety, no later exploits, no reference fixes,
  Makefile wiring, and docs/handoff evidence.
- `python -B scripts/check_competition_matrix_gate.py`: passed with AML-1
  exploit-success concrete, AML-2 through AML-5 exploit-success pending, and
  all fix cells pending.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`:
  passed after sandbox escalation for Windows Go build-cache access.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`: passed
  after sandbox escalation for Windows Go build-cache access.
- `timeout 300 make wave19-gate`: passed through WSL with temporary `/tmp`
  shims mapping `python` to `python3` and `go` to the Windows Go 1.24.2 binary,
  because native Windows `make` was unavailable and WSL's default Go was
  `go1.18 gccgo`.

## 6. Documentation Updated

Added this W19-T02 handoff report with scope, validation, matrix
interpretation, invariants, and review status.

Matrix Interpretation: the competition matrix now has AML-1 exploit-success as
concrete through `sploits/sentinel_aml/aml_dedup_preview.py`,
`scripts/check_wave19_gate.py`, and `tests/test_wave19_gate.py`. AML-2 through
AML-5 exploit-success cells remain pending, and every fixed checker,
exploit-blocked, and anti-coarse-fix cell remains pending.

## 7. CTF Invariants Checked

- Both flag stores remain active.
- CHECK/HAVOC remains unchanged.
- The exploit script is not a checker dependency.
- Public attack data remains unchanged and credential-free.

## 8. Security Invariants Checked

- Validation rejects direct DB primitives, raw SQL markers, debug/admin routes,
  shell imports/execution, checker-private state, and public attack-data
  credential lookups.
- No service behavior, vulnerability behavior, checker behavior, or reference
  fix behavior was changed.

## 9. Self-Review

The W19-T02 changes are validation-only and stay within the allowed file scope.
They strengthen acceptance evidence without turning the exploit into a generic
framework or unlocking Wave 20/Wave 24 work.

## 10. Risks / Open Questions

The literal `timeout 300 make wave19-gate` wrapper depends on a host with
GNU-compatible `make`, `timeout`, Python, and a Go toolchain compatible with
`go.mod`. On this Windows host, WSL plus temporary `/tmp` command shims may be
needed for wrapper execution without changing repository files.

## 11. Ready for Orchestrator Review

Yes.
