# Wave 16 W16-T02 Handoff

## 1. Summary

Added the Wave 16 validation gate for the AML-3 vulnerable graph profile and
extended the competition matrix so AML-3 has a concrete vulnerable-checker cell
while AML-3 exploit/fix cells remain pending. Added `make wave16-gate` with the
required checker, Go, docs, Wave 16, competition matrix, and ForcAD validation
commands.

## 2. Implementation Details

- Added `scripts/check_wave16_gate.py`.
- Added `tests/test_wave16_gate.py`.
- Extended `scripts/check_competition_matrix_gate.py` with AML-3 concrete and
  pending cells.
- Extended `tests/test_competition_matrix_gate.py` for AML-3 artifact and
  exploit/fix pending checks.
- Added `wave16-gate` to `Makefile`.
- Preserved AML-1 and AML-2 matrix checks.
- Kept AML-4 and AML-5 activation markers forbidden.
- Kept reference exploit/fix files forbidden for AML-3.

## 3. Files Changed

- `scripts/check_wave16_gate.py`
- `tests/test_wave16_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/wave_reports/wave_16_W16-T02_handoff.md`

## 4. Tests Added

- Wave 16 gate unit tests for current-branch success.
- Negative tests for missing AML-3 vulnerable profile, unrelated graph profile
  leakage, early AML-3 exploit/fix files, debug/admin profile toggles, direct DB
  checker paths, early AML-4 activation, and missing `wave16-gate` target.
- Competition matrix tests for AML-3 concrete vulnerable-checker evidence and
  AML-3 exploit/fix pending enforcement.

## 5. Tests Run

Commands were run from `C:\Users\2005g\GolandProjects\Sentinel_AML` on Windows
PowerShell. Go commands used `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`,
`GOTELEMETRY=off`, and workspace-local `GOCACHE`/`APPDATA`.

| Command | Result |
| --- | --- |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; 97 tests in 4.985s |
| `python -B -m unittest discover -s tests -p "test_wave16_gate.py"` | exit 0; 8 tests in 0.258s |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; 12 tests in 0.392s |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...` | exit 0 |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml3_vulnerable ./...` | exit 0 |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` | exit 0 |
| `python -B scripts/check_docs_tree.py` | exit 0 |
| `python -B scripts/check_wave16_gate.py` | exit 0 |
| `python -B scripts/check_competition_matrix_gate.py` | exit 0 |
| `python -B scripts/validate_forcad_config.py` | exit 0 |
| `make wave16-gate` | exit 1 on this Windows host because `make` is not installed on PATH |

`scripts/check_wave16_gate.py` statically validates that the `wave16-gate`
target includes the required component commands. The literal wrapper still
needs to be rerun on a make-equipped review host for final acceptance.

## 6. Documentation Updated

Added this W16-T02 handoff report with exact validation evidence and the local
`make` availability limitation.

## 7. CTF Invariants Checked

- AML-3 vulnerable-checker matrix cell is concrete.
- AML-1 and AML-2 matrix behavior remains preserved.
- AML-3 exploit-success, fixed-checker, exploit-blocked, and anti-coarse-fix
  cells remain pending.
- Checker remains HTTP-only and owner-view based.
- Public attack data and checker state behavior were not changed.

## 8. Security Invariants Checked

- Gate rejects debug/admin profile toggles.
- Gate rejects direct DB checker paths.
- Gate rejects AML-4 and AML-5 activation markers.
- Gate checks AML-3 is bounded to the graph EDD-summary
  `confidential_comment` profile.
- No reference exploit or reference fix file was added.

## 9. Self-Review

The Wave 16 gate validates both the profile artifacts and the source-level
guardrails needed for AML-3. The competition matrix now has AML-1, AML-2, and
AML-3 vulnerable-checker cells concrete while keeping exploit/fix cells pending.
No Wave 13, Wave 14, or Wave 15 checks were removed.

## 10. Risks / Open Questions

- Final `make wave16-gate` wrapper evidence is blocked on this Windows host by
  missing `make`; component commands passed directly.
- Broader Wave 16 roadmap and vulnerability-matrix documentation remains for a
  later documentation/status task.

## 11. Ready for Orchestrator Review

no
