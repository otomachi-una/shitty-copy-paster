# Wave 18 W18-F02 Handoff

## 1. Summary

Removed local cache artifacts from the deliverable tree, strengthened archive
hygiene validation for wildcard Go cache/application-data directories and
temporary local artifacts, and integrated archive hygiene into `make
wave18-gate`.

## 2. Implementation Details

- Expanded `.gitignore` to reject `.gocache*/`, `.appdata*/`, Python bytecode,
  local coverage outputs, IDE metadata, and temporary archive/package files.
- Strengthened `scripts/check_archive_hygiene.py` so `.gocache-p1/`,
  `.appdata-p1/`, local coverage files, and temporary archives fail the actual
  repository scan.
- Added archive hygiene tests for the current repository tree, wildcard cache
  directories, coverage artifacts, and temporary archives.
- Updated `make wave18-gate` to use release-scoped Go cache/application-data
  locations outside the repository and to run `scripts/check_archive_hygiene.py`
  before closure.
- Updated `scripts/check_wave18_gate.py` and Wave 18 gate tests so the wrapper
  must keep release cache paths out of the repository and must include archive
  hygiene validation.
- Cleaned local `.gocache*` and `.appdata*` artifacts from the deliverable
  source tree.

## 3. Files Changed

- `.gitignore`
- `Makefile`
- `scripts/check_archive_hygiene.py`
- `tests/test_archive_hygiene.py`
- `scripts/check_wave18_gate.py`
- `tests/test_wave18_gate.py`
- `docs/11_deployment.md`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_18_validation_summary.md`
- `docs/wave_reports/wave_18_W18-F02_handoff.md`

## 4. Tests Added

- Archive hygiene regression for the actual repository tree.
- Archive hygiene regression for `.gocache*` and `.appdata*` directories.
- Archive hygiene regression for coverage and temporary archive files.
- Wave 18 gate regressions requiring archive hygiene and release-scoped Go
  cache settings in `make wave18-gate`.

## 5. Tests Run

```sh
python -B scripts/check_archive_hygiene.py
```

Exit code: 0.

```sh
python -B -m unittest discover -s tests -p "test_archive_hygiene.py"
```

Exit code: 0. Ran 7 tests.

```sh
python -B scripts/check_wave18_gate.py
```

Exit code: 0.

```sh
timeout 300 make wave18-gate
```

Exit code: 0. The wrapper ran checker tests, Wave 18 gate tests, competition
matrix tests, default Go tests with release-scoped cache paths outside the
repository, the deterministic AML-5 tagged package runner, Go vet, docs tree,
Wave 18 gate, competition matrix, ForcAD validation, and archive hygiene.

## 6. Documentation Updated

Updated deployment, testing strategy, Wave 18 validation summary, and this
W18-F02 handoff with clean-deliverable and gate evidence.

## 7. CTF Invariants Checked

- Competition artifacts remain reproducible from source and vendored
  dependencies.
- Checker behavior does not depend on host-local cache state.
- No hidden local files affect checker, exploit, or fix behavior.
- AML-5 vulnerable-checker cell remains concrete.
- AML-5 exploit and fix cells remain pending.

## 8. Security Invariants Checked

- Deliverables must not leak host state, tokens, telemetry, local paths, cache
  contents, IDE metadata, or Python bytecode.
- Archive hygiene failures are not masked by narrowing the validator.
- Product behavior, checker behavior, ForcAD config, sploit files, and fix
  files remain untouched.

## 9. Self-Review

This is a release hygiene and packaging fix. It changes gate execution,
archive hygiene validation, tests, ignore rules, and documentation only. It
does not change Go product code, checker semantics, ForcAD config, planned
vulnerability behavior, reference sploits, or reference fixes.

## 10. Risks / Open Questions

- `make wave18-gate` uses release-scoped cache paths outside the repository so
  the gate does not create artifacts that would dirty the deliverable tree.
- Future packaging scripts should run archive hygiene after any build/test
  command that can create local artifacts.

## 11. Ready for Orchestrator Review

yes
