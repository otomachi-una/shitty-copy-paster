# W27-T02 Handoff - Wave 27 Gate and Competition Matrix Alignment

## 1. Summary

Implemented Wave 27 validation and matrix alignment for the AML-4 reference fix.
The new gate makes `fixes/sentinel_aml/aml_export_redaction.patch`
machine-checkable while keeping AML-5 fix cells pending and AML-5 fix inventory
locked.

Wave 27 remains implemented under review only. This handoff does not accept
Wave 27 and does not unlock AML-5 fix work.

## 2. Implementation Details

- Added `scripts/check_wave27_gate.py` with JSON pass/fail output.
- Required exactly five accepted reference exploits under `sploits/sentinel_aml`.
- Required exactly AML-1 through AML-4 patch artifacts and rejected AML-5 fixes.
- Required `git apply --check --whitespace=error` for AML-1 through AML-4
  patches.
- Validated AML-4 patch scope against only the tagged AML-4 export HTTP profile,
  exporting profile, and AML-4 tagged proof test.
- Required the AML-4 patch to remove linked-case private-note export injection
  while preserving public export evidence, dispute export creation, stored export
  readback, linked public case shells, and owner-only note/EDD paths.
- Rejected docs-only fixes, gate-only fixes, export/dispute endpoint removal,
  raw private body reintroduction, sensitive-field renames, hash/raw-diff leaks,
  debug/admin paths, direct DB shortcuts, shell helpers, and export disablement.
- Updated `scripts/check_competition_matrix_gate.py` so AML-4 fixed-checker,
  exploit-blocked, and anti-coarse-fix cells are concrete in the gate while
  AML-5 fixed-checker, exploit-blocked, and anti-coarse-fix cells remain
  pending.
- Added `wave27-gate` to `Makefile` with checker tests, Wave 27 tests,
  competition matrix tests, all five exploit compiles with no repo bytecode,
  AML-1 through AML-4 patch apply checks, package-by-package release/offline Go
  tests, release/offline Go vet, Wave 27 gate validation, matrix validation,
  docs-tree validation, ForcAD validation, and archive hygiene.

## 3. Files Changed

- `scripts/check_wave27_gate.py`
- `tests/test_wave27_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/09_vulnerability_matrix.md`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_27_W27-T02_handoff.md`

## 4. Tests Added

- Current-branch Wave 27 gate happy path.
- Missing AML-4 fix artifact failure.
- Extra AML-5 fix artifact failure.
- Missing AML-4 exploit inventory failure.
- Docs-only and gate-only fix rejection.
- Outside AML-4 export target rejection.
- Raw linked private note body reintroduction rejection.
- EDD confidential comment, direct DB, debug/admin, and shell shortcut rejection.
- Sensitive rename/hash/raw diff rejection.
- Export and dispute endpoint removal rejection.
- Export handler/bundle removal rejection.
- Export disablement rejection.
- AML-4 exploit parser vulnerable/fixed fixture evidence.
- AML-4 exploit succeeds on vulnerable fixture and fails safely on fixed
  redacted export fixture.
- Fixed export fixture preserves public export evidence and owner-only note/EDD
  paths.
- Wave 27 Makefile target coverage and unbounded Go test rejection.
- Competition matrix AML-4 fix-cell concrete coverage.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_wave27_gate.py"`:
  exit 0, 22 tests.
- `python -B scripts/check_wave27_gate.py`: exit 0, JSON status `pass`.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0, 31 tests.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0, JSON status
  `pass`.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0, 97 tests.
- `python -B scripts/check_docs_tree.py`: exit 0, JSON status `pass`.
- `python -B scripts/validate_forcad_config.py`: exit 0,
  `config.yml ForcAD shape is valid`.
- `python -B scripts/check_archive_hygiene.py`: exit 0, JSON status `pass`.
- `git apply --check --whitespace=error` for AML-1, AML-2, AML-3, and AML-4
  patches: covered by `check_wave27_gate.py` individual patch checks with JSON
  status `pass`; an additional local sequential apply-check command completed
  with no output and final exit 0.
- No-repo-cache py_compile for all five exploits:
  `python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py sploits/sentinel_aml/aml_audit_timeline.py sploits/sentinel_aml/aml_related_graph.py sploits/sentinel_aml/aml_export_redaction.py sploits/sentinel_aml/aml_network_room.py`
  with `PYTHONPYCACHEPREFIX` set under `%TEMP%`: exit 0.
- `python -B scripts/run_go_release_tests.py --go go --package-timeout 120`:
  exit 0. The runner emitted package names before each package test and ran
  release/offline package tests with isolated temporary `GOCACHE` and `APPDATA`.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` with
  isolated temporary `GOCACHE` and `APPDATA`: exit 0.
- `timeout 300 make wave27-gate`: exit 1 on this Windows host before invoking
  `make`; Windows `timeout` reported `Invalid syntax`.
- `where.exe make`: exit 1, no `make` executable found on this host.
- `make wave27-gate`: exit 1, `make` is not recognized on this host.
- `bash -lc "cd /mnt/c/Users/2005g/GolandProjects/Sentinel_AML && command -v make && timeout 300 make wave27-gate"`:
  exit 1 before invoking `make`; WSL Bash startup failed with
  `CreateInstance/E_ACCESSDENIED`.

## 6. Documentation Updated

- Updated `docs/09_vulnerability_matrix.md` to record Wave 27 as implemented
  under review for AML-4, with AML-5 fix cells pending/locked.
- Updated `docs/12_testing_strategy.md` with the Wave 27 gate composition,
  anti-coarse-fix checks, exploit-blocked evidence, and AML-5 lock boundary.
- Created this W27-T02 handoff.

## 7. CTF Invariants Checked

- All five accepted exploits remain required and importable by the gate target.
- AML-1 through AML-4 fixes are checkable; AML-5 fixes remain absent.
- Strong checker/HAVOC coverage remains release-blocking through checker tests,
  bounded Go tests, docs validators, ForcAD validation, and archive hygiene.
- Public attack data schema is unchanged.

## 8. Security Invariants Checked

- The Wave 27 gate rejects fixed export output or patch additions that expose
  linked foreign private notes, EDD confidential comments, internal comments,
  raw audit diffs, value/hash substitutes, credentials, sessions, debug/admin
  data, raw DB rows, direct DB paths, or shell helpers.
- Export/dispute endpoints and owner-only note/EDD paths must remain available.
- AML-5 network-room fix behavior remains out of scope and locked.

## 9. Self-Review

The implementation is limited to the requested validation, matrix, Makefile, and
documentation files. It does not edit product behavior, checker behavior,
reference exploits, accepted AML-1/AML-2/AML-3 patch semantics, migrations,
deployment config, public attack data, or AML-5 fix inventory.

## 10. Risks / Open Questions

- The gate is static plus fixture-based for patch narrowness; runtime behavior
  remains covered by applying the patch and running Go/checker suites in the
  aggregate target.
- Local Windows did not provide GNU `timeout` semantics or `make`, and WSL Bash
  was unavailable due `E_ACCESSDENIED`. The aggregate `wave27-gate` target is
  defined and statically validated, and all component-equivalent checks passed,
  but this host cannot prove `timeout 300 make wave27-gate` exit 0.

## 11. Ready for Orchestrator Review: yes

Yes, for orchestrator review on a make-capable environment with GNU-compatible
`timeout`. The local Windows host could not execute the exact aggregate wrapper,
so the handoff includes the failed wrapper evidence and the passing component
evidence without claiming local aggregate success.
