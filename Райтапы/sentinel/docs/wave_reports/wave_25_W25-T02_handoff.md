# W25-T02 Handoff - Wave 25 Gate and Competition Matrix Update

## 1. Summary

Implemented the Wave 25 validation gate for the AML-2 reference fix artifact and
updated the competition matrix gate so AML-1 and AML-2 fix cells are concrete.
AML-3 through AML-5 reference fix cells remain pending and their fix artifacts
remain forbidden.

## 2. Implementation Details

- Added `scripts/check_wave25_gate.py` with JSON pass/fail output.
- The gate requires exactly five accepted Sentinel AML exploit scripts.
- The gate requires exactly two reference fix patches:
  `aml_dedup_preview.patch` and `aml_audit_timeline.patch`.
- The AML-2 patch checks require the narrow audit-profile/test targets,
  removal of the raw note-body re-expansion path, preserved redacted
  `case_note.body` evidence, and owner note API coverage.
- Negative checks reject docs-only or gate-constant-only patches, endpoint
  removal, audit disablement, raw-body reintroduction, debug/admin shortcuts,
  direct DB paths, and shell execution.
- Updated `scripts/check_competition_matrix_gate.py` so AML-2 fixed checker,
  exploit-blocked, and anti-coarse-fix cells are concrete while AML-3 through
  AML-5 fix cells remain pending.
- Added `wave25-gate` to the Makefile with checker tests, Wave 25 gate tests,
  competition matrix tests, no-repo-cache py_compile for all five exploits,
  `git apply --check --whitespace=error` for AML-1 and AML-2 patches,
  bounded release/offline Go test and vet, docs-tree validation, ForcAD
  validation, matrix validation, and archive hygiene.

## 3. Files Changed

- `scripts/check_wave25_gate.py`
- `tests/test_wave25_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/wave_reports/wave_25_W25-T02_handoff.md`

## 4. Tests Added

- Positive Wave 25 gate validation.
- Missing AML-2 patch rejection.
- Extra nonstandard fix rejection.
- Missing exploit inventory rejection.
- Docs-only and gate-constant-only fix rejection.
- Timeline endpoint removal rejection.
- Audit disablement rejection.
- Raw note-body reintroduction rejection.
- Direct DB, shell, and debug/admin shortcut rejection.
- AML-2 exploit succeeds on vulnerable fixture and fails safely on fixed
  redacted output.
- Makefile target coverage and unbounded Go test rejection.
- Competition matrix tests for AML-2 concrete fix cells and AML-3 through
  AML-5 pending fix cells.

## 5. Tests Run

- `python -B scripts/check_wave25_gate.py`: exit 0.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0.
- `python -B -m unittest discover -s tests -p "test_wave25_gate.py"`:
  exit 0; 14 tests passed.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 29 tests passed.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0; 97 tests passed.
- No-repo-cache `python -B -m py_compile` for all five Sentinel AML exploits:
  exit 0.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch`:
  exit 0.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_audit_timeline.patch`:
  exit 0.
- Release/offline no-repo-cache
  `go test -p 1 -timeout 120s -count=1 ./...`: exit 0.
- Release/offline no-repo-cache `go vet ./...`: exit 0.
- `python -B scripts/check_docs_tree.py`: exit 0.
- `python -B scripts/validate_forcad_config.py`: exit 0.
- `python -B scripts/check_archive_hygiene.py`: exit 0.
- `make wave25-gate`: exit 1 in this Windows shell because no `make`,
  `mingw32-make`, or `gmake` executable is available on PATH. The Makefile
  target is defined and its component commands above were run directly.

## 6. Documentation Updated

Created this W25-T02 handoff. No broader status-ledger documents were changed in
this gate task.

## 7. CTF Invariants Checked

- AML-1 fix remains concrete.
- AML-2 fix becomes concrete only through the Wave 25 gate and matrix checks.
- AML-3 through AML-5 fixes remain locked.
- CHECK/HAVOC checker tests remain part of `wave25-gate`.
- Public attack-data contracts and exploit scripts were not modified.

## 8. Security Invariants Checked

- The Wave 25 gate rejects raw AML-2 `CaseNote.body` reintroduction in audit
  side views.
- The gate preserves redacted field evidence rather than accepting endpoint or
  audit disablement.
- The gate rejects debug/admin shortcuts, direct DB access, shell execution, and
  credential/session lookup patterns in the AML-2 patch.

## 9. Self-Review

The implementation is intentionally limited to Wave 25 validation, matrix
status, Makefile aggregation, tests, and this handoff. It does not modify
product code, checker code, exploit scripts, migrations, deployment files, or
existing patch semantics.

## 10. Risks / Open Questions

- Local aggregate `make wave25-gate` execution depends on a usable `make`
  binary in the environment.
- The gate is static plus harness-based evidence; full patched-service exploit
  blocking remains represented by the W25-T01 temporary patched-copy evidence
  and by the patch markers enforced here.

## 11. Ready for Orchestrator Review

Yes.
