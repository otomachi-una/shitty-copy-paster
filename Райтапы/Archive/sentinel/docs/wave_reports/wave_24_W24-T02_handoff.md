# W24-T02 Handoff - Wave 24 Gate and Competition Matrix Update

## 1. Summary

Added the Wave 24 validation gate for the AML-1 reference fix artifact and
updated the competition matrix so only AML-1 fixed checker, exploit-blocked,
and anti-coarse-fix cells are concrete. AML-2 through AML-5 fix cells remain
pending.

## 2. Implementation Details

- Added `scripts/check_wave24_gate.py` with JSON pass/fail output.
- The Wave 24 gate requires exactly five reference exploits to remain present.
- It requires exactly one AML-1 reference fix artifact:
  `fixes/sentinel_aml/aml_dedup_preview.patch` or `.diff`.
- It rejects AML-2 through AML-5 fix artifacts and nonstandard fix files.
- It runs `git apply --check --whitespace=error` for the AML-1 patch.
- It statically validates the patch scope, safe projection change, exploit
  blocking markers, and anti-coarse-fix evidence that dedup public fields and
  owner APIs remain covered.
- Updated `scripts/check_competition_matrix_gate.py` so AML-1 fix cells are
  concrete through W24 while AML-2 through AML-5 fix cells remain pending.
- Added `wave24-gate` to `Makefile`.

## 3. Files Changed

- `scripts/check_wave24_gate.py`
- `tests/test_wave24_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/wave_reports/wave_24_W24-T02_handoff.md`

## 4. Tests Added

- Wave 24 gate happy path.
- Missing AML-1 fix artifact failure.
- Extra/nonstandard fix artifact failure.
- Missing exploit inventory failure.
- Missing safe projection marker failure.
- Reintroduced `private_notes` failure.
- Coarse dedup endpoint removal failure.
- Corrupt patch apply failure.
- Missing W24-T01 evidence failure.
- `wave24-gate` Makefile target coverage failure.
- Competition matrix AML-1 fix concrete and AML-2 through AML-5 fix pending
  assertions.

## 5. Tests Run

| Command | Result |
| --- | --- |
| `python -B scripts\check_wave24_gate.py` | exit 0; status `pass` |
| `python -B scripts\check_competition_matrix_gate.py` | exit 0; status `pass` |
| `python -B -m unittest discover -s tests -p "test_wave24_gate.py"` | exit 0; 10 tests passed |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; 28 tests passed |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; 97 tests passed |
| no-repo-cache `python -B -m py_compile` for all five exploits | exit 0 |
| release/offline `go test ./...` | exit 0 |
| release/offline `go vet ./...` | exit 0 |
| `python -B scripts\check_docs_tree.py` | exit 0; status `pass` |
| `python -B scripts\validate_forcad_config.py` | exit 0 |
| `python -B scripts\check_archive_hygiene.py` | exit 0; status `pass` |
| `make wave24-gate` | not runnable in this Windows shell; `make` is not installed in PATH |

## 6. Documentation Updated

This handoff records W24-T02 gate and matrix evidence for orchestrator review.

## 7. CTF Invariants Checked

- Previous AML-1 through AML-5 exploit-success cells remain concrete.
- Only AML-1 fix cells become concrete.
- CHECK/HAVOC remains release-blocking through checker tests in
  `wave24-gate`.
- Public attack-data contracts are unchanged.

## 8. Security Invariants Checked

- The gate rejects broad AML-1 patch targets, reintroduced private-note
  serialization, direct DB shortcuts, debug/admin paths, shell/subprocess
  primitives, and dedup/merge-preview owner API removals.
- AML-2 through AML-5 fix artifacts remain rejected.

## 9. Self-Review

The implementation is static and deterministic for artifact validation, while
the Makefile target carries the runnable checker, Go, py_compile, docs, ForcAD,
matrix, and archive checks.

## 10. Risks / Open Questions

- `make wave24-gate` depends on `make` being installed in the local shell.

## 11. Ready for Orchestrator Review

Yes.
