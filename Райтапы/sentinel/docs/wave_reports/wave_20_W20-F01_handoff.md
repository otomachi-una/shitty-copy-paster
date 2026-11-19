# W20-F01 Handoff - Gate Liveness and Archive Hygiene Fix

## 1. Summary

Wave 20 gate hygiene was fixed so generated Python bytecode/cache artifacts are
not left in the repository and `wave20-gate` runs archive hygiene as an
official final closure check. Wave 20 remains under review and is not marked
accepted by this handoff.

## 2. Implementation Details

- Removed generated `sploits/sentinel_aml/__pycache__/` bytecode artifacts
  from the working snapshot.
- Made `.gitignore` explicitly reject `*.pyc` and `*.pyo` in addition to the
  existing Python cache patterns.
- Updated `wave20-gate` so exploit `py_compile` commands use
  `PYTHONPYCACHEPREFIX` outside the repository snapshot.
- Added `python -B scripts/check_archive_hygiene.py` as the final command in
  `wave20-gate`, after commands that can generate bytecode.
- Updated `scripts/check_wave20_gate.py` so the Wave 20 gate requires archive
  hygiene and this W20-F01 handoff evidence.
- Extended tests for sploit bytecode/cache rejection and Wave 20 archive
  hygiene closure wiring.

## 3. Files Changed

- `.gitignore`
- `Makefile`
- `scripts/check_wave20_gate.py`
- `tests/test_wave20_gate.py`
- `tests/test_archive_hygiene.py`
- `docs/wave_reports/wave_20_validation_summary.md`
- `docs/wave_reports/wave_20_W20-F01_handoff.md`

## 4. Tests Added

- Archive hygiene rejects `sploits/sentinel_aml/__pycache__/` and `.pyo`
  bytecode artifacts.
- Wave 20 gate rejects a `wave20-gate` target that omits archive hygiene.

## 5. Tests Run

Component and closure evidence:

| Command | Result |
| --- | --- |
| `python -B scripts/check_archive_hygiene.py` | exit 0; pass |
| `python -B -m unittest discover -s tests -p "test_archive_hygiene.py"` | exit 0; pass; 8 tests |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; pass; 97 tests |
| `python -B -m unittest discover -s tests -p "test_wave20_gate.py"` | exit 0; pass; 13 tests |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; pass; 21 tests |
| `python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py` | exit 0; pass |
| `python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py` | exit 0; pass |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...` | exit 0; pass after rerun outside the restricted sandbox because the Windows Go build cache was denied in sandboxed execution |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` | exit 0; pass after rerun outside the restricted sandbox for the same Go cache condition |
| `timeout 300 make wave20-gate` | exit 0; pass in 17.5 seconds via WSL `/usr/bin/make` without temporary command shims |
| `python -B scripts/check_archive_hygiene.py` after aggregate gate | exit 0; pass |

The standalone `py_compile` commands created CPython bytecode as a normal local
side effect; those generated artifacts were removed before final closure. The
official `wave20-gate` target compiles with `PYTHONPYCACHEPREFIX` outside the
repository snapshot and runs archive hygiene last, so the aggregate gate leaves
the repository clean.

## 6. Documentation Updated

- This W20-F01 handoff records the gate liveness and archive hygiene fix.
- `docs/wave_reports/wave_20_validation_summary.md` is updated with fixed
  gate evidence after validation.

## 7. CTF Invariants Checked

- Checker place 1 remains owner `CaseNote.body` PUT/GET.
- Checker place 2 remains owner `EDDRecord.confidential_comment` PUT/GET.
- Public attack data remains locator-only and credential-free.
- AML-2 exploit remains outside checker code.
- AML-3 through AML-5 exploit scripts remain locked.
- All reference fixes remain locked.

## 8. Security Invariants Checked

- No debug/admin toggles were added.
- No direct database access was added to checker or exploit code.
- No shell execution was added to exploits.
- No credential, session, or flag leakage was added to logs or public attack
  data.

## 9. Self-Review

The fix is limited to release-gate hygiene and generated-artifact prevention.
No product, checker, vulnerability, exploit behavior, migration, deployment, or
fix artifact was changed.

## 10. Risks / Open Questions

The canonical closure command should be rerun by the orchestrator from a clean
make-capable extraction. This local Windows host used WSL for `make`; the
Makefile itself selected available Python and Go commands and no temporary
command shims were used.

## 11. Ready for Orchestrator Review

Yes.
