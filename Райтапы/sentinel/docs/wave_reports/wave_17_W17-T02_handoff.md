# Wave 17 W17-T02 Handoff

## 1. Summary

Added the Wave 17 validation gate and promoted the AML-4 vulnerable-checker
competition matrix cell to concrete. AML-4 exploit/fix cells remain pending,
AML-5 remains locked, and prior AML-1/AML-2/AML-3 matrix checks are preserved.

## 2. Implementation Details

- Added `scripts/check_wave17_gate.py` with checks for:
  - AML-4 secure/tagged export profile split;
  - dispute export profile hook usage;
  - export bundle profile contract;
  - default/tagged AML-4 test presence;
  - absence of reference sploits/fixes;
  - absence of debug/admin runtime toggles;
  - absence of AML-5 activation markers;
  - `wave17-gate` Makefile command coverage;
  - W17-T01 handoff presence.
- Added `tests/test_wave17_gate.py` with current-tree and negative fixture
  coverage for missing profiles, overbroad leaks, default output body fields,
  early sploit/fix files, debug/admin toggles, AML-5 markers, and missing
  Makefile target.
- Updated the competition matrix gate so AML-4 vulnerable-checker evidence is
  concrete while AML-4 exploit-success, fixed-checker, exploit-blocked, and
  anti-coarse-fix cells remain pending.
- Added `make wave17-gate` with the required checker tests, Wave 17 tests, Go
  default/tagged tests, Go vet, docs tree, Wave 17 gate, competition matrix
  gate, and ForcAD config validation.

## 3. Files Changed

- `Makefile`
- `scripts/check_wave17_gate.py`
- `tests/test_wave17_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `docs/wave_reports/wave_17_W17-T02_handoff.md`

## 4. Tests Added

- Wave 17 gate unit tests in `tests/test_wave17_gate.py`.
- AML-4 competition matrix tests in `tests/test_competition_matrix_gate.py`.

## 5. Tests Run

Commands were run from Windows PowerShell. Go commands used `GOTOOLCHAIN=local`,
`GOFLAGS=-mod=vendor`, `GOTELEMETRY=off`, and temp `GOCACHE`/`APPDATA`
directories outside the repository.

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave17_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
go test ./...
go test -tags aml4_vulnerable ./...
go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave17_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
```

Results:

- `test_checker_*.py`: pass, 97 tests.
- `test_wave17_gate.py`: pass, 8 tests.
- `test_competition_matrix_gate.py`: pass, 14 tests.
- `go test ./...`: pass.
- `go test -tags aml4_vulnerable ./...`: pass.
- `go vet ./...`: pass.
- `scripts/check_docs_tree.py`: pass.
- `scripts/check_wave17_gate.py`: pass.
- `scripts/check_competition_matrix_gate.py`: pass.
- `scripts/validate_forcad_config.py`: pass.
- `scripts/check_archive_hygiene.py`: pass.

`make wave17-gate` could not be executed on this host because `make` is not
installed in the Windows PowerShell environment. The Makefile target was added
and validated by `scripts/check_wave17_gate.py`; all component commands in the
target were run directly and passed.

## 6. Documentation Updated

Added this Wave 17 W17-T02 handoff report with gate evidence and the local
`make` availability note.

## 7. CTF Invariants Checked

- Checker remains HTTP-only and unchanged.
- AML-4 vulnerable-checker matrix cell is concrete.
- AML-4 exploit/fix cells remain pending.
- AML-1, AML-2, and AML-3 matrix checks remain present.
- AML-5 remains locked by Wave 17 and competition matrix gates.
- No sploit or reference fix files were added.

## 8. Security Invariants Checked

- Gate rejects debug/admin runtime toggles.
- Gate rejects direct expansion into AML-5 markers.
- Matrix gate still rejects early exploit/fix artifacts.
- Public attack-data and checker owner paths were not changed.

## 9. Self-Review

The Wave 17 gate is marker-based like prior wave gates and checks both current
artifacts and negative fixture behavior. The competition matrix now recognizes
AML-4 as the newest concrete vulnerable profile without weakening earlier AML
cells. The only local validation gap is direct execution of `make wave17-gate`,
blocked by missing `make`; the target contents were validated and run as direct
component commands.

## 10. Risks / Open Questions

- Orchestrator should run `make wave17-gate` on a POSIX or make-enabled review
  host.
- Broader Wave 17 documentation alignment remains for W17-T03.

## 11. Ready for Orchestrator Review

yes
