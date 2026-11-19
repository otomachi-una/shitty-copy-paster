# W14-T02 Handoff - AML-1 Gate and Competition Matrix Integration

## 1. Summary

W14-T02 integrates AML-1 into the Wave 14 validation and competition matrix.
The AML-1 vulnerable-checker cell is concrete, while AML-1 exploit-success,
fixed-checker, exploit-blocked, and anti-coarse-fix cells remain pending.

## 2. Implementation Details

- Added `make wave14-gate` to run checker tests, Wave 14 gate tests, default Go
  tests, tagged `aml1_vulnerable` Go tests, Go vet, docs tree, Wave 14 gate,
  competition matrix gate, and ForcAD config validation.
- Extended `scripts/check_wave14_gate.py` to require the Makefile target and to
  reject accidental AML-2 through AML-5 activation markers.
- Extended `scripts/check_competition_matrix_gate.py` so AML-1 vulnerable
  checker evidence is concrete through `scripts/check_wave14_gate.py`, while
  exploit/fix cells remain pending.
- Added Python gate tests for missing AML-1 artifacts, early exploit/fix files,
  future AML activation markers, and missing Wave 14 Makefile wiring.

## 3. Files Changed

- `Makefile`
- `scripts/check_wave14_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_wave14_gate.py`
- `tests/test_competition_matrix_gate.py`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_14_validation_summary.md`

## 4. Tests Added

- Wave 14 gate tests for missing `wave14-gate`, accidental AML-2 activation,
  missing AML-1 vulnerable profile, EDD leakage in the AML-1 lookup, early
  exploit/fix artifacts, and debug/admin profile toggles.
- Competition matrix tests for the concrete AML-1 vulnerable-checker cell,
  pending AML-1 exploit/fix cells, future AML activation markers, and copied
  tree script evaluation.

## 5. Tests Run

Passed:

- `python -B -m unittest discover -s tests -p "test_wave14_gate.py"`
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`
- `python -B -m unittest discover -s tests -p "test_*.py"`
- `python -B scripts/check_wave14_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_docs_tree.py`
- `python -B scripts/validate_forcad_config.py`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml1_vulnerable ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`

`python -B scripts/check_wave13_gate.py` remained historical and failed only on
its pre-Wave-14 no-vulnerable-behavior check. The Wave 13 gate was not weakened.

`make wave14-gate` was wired but could not run on this Windows host because no
`make` executable was installed. Its component commands were run directly.

## 6. Documentation Updated

- `docs/12_testing_strategy.md` documents the Wave 14 gate commands and what
  the AML-1 concrete matrix cell proves.
- `docs/wave_reports/wave_14_validation_summary.md` records the Wave 14 gate
  and competition-matrix evidence.

## 7. CTF Invariants Checked

- AML-1 is the only newly active planned vulnerability.
- Vulnerable checker evidence is concrete for AML-1.
- Reference exploit and reference fix cells remain pending.
- Public attack data remains credential-free and raw-flag-free.

## 8. Security Invariants Checked

- Gate scans reject debug/admin variant toggles.
- Gate scans reject AML-2 through AML-5 activation markers.
- Gate scans reject early AML-1 exploit/fix files.
- AML-1 remains local to dedup merge-preview.

## 9. Self-Review

The concrete matrix cell after W14-T02 is AML-1 vulnerable checker. The pending
cells are AML-1 exploit-success, AML-1 fixed checker, AML-1 exploit-blocked, and
AML-1 anti-coarse-fix. No exploit or fix implementation was added.

## 10. Risks / Open Questions

- Literal `make wave14-gate` still requires a POSIX/Linux or Windows host with
  `make` installed.
- Wave 14 remains under review until the orchestrator accepts W14-F01 liveness
  evidence and the complete Wave 14 gate.

## 11. Ready for Orchestrator Review

Yes.
