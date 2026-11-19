# W29-T02 - End-to-End Checker, Exploit, Fix Regression Evidence Handoff

## 1. Summary

W29-T02 adds reproducible end-to-end regression evidence across checker,
exploit, vulnerable-profile, and reference-fix combinations. The new runner
applies the reference fix patches in sequence in a clean temporary copy and
validates that the focused fixed proofs and checker regression remain green as
the cumulative fixed service evolves.

## 2. Implementation Details

- Added `scripts/check_wave29_regression.py` with JSON pass/fail output.
- Added `tests/test_wave29_regression.py` covering temp-copy isolation,
  vulnerable tagged command coverage, missing fixed proof markers, checker
  failure after patch application, and exploit compile failures.
- Updated `wave29-gate` to include the new regression unit test and regression
  script.
- Updated `scripts/check_wave29_gate.py` so the full matrix gate requires the
  W29-T02 regression layer.
- Updated `docs/12_testing_strategy.md` with the W29-T02 regression evidence
  flow.

## 3. Files Changed

- `scripts/check_wave29_regression.py`
- `tests/test_wave29_regression.py`
- `scripts/check_wave29_gate.py`
- `tests/test_wave29_gate.py`
- `Makefile`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_29_W29-T02_handoff.md`

## 4. Tests Added

- Regression runner tests for an external clean temporary patch matrix copy.
- Tagged vulnerable-build command coverage tests for AML-1 through AML-5.
- Negative tests for missing fixed proof markers.
- Negative tests for checker regression failure after patch application.
- Negative tests for exploit compile failures.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_wave29_regression.py"` -
  exit 0, 5 tests passed.
- `python -B scripts/check_wave29_regression.py` - exit 0. JSON checks passed
  for checker PUT/GET and CHECK/HAVOC regression, current matrix/Wave 29 Python
  evidence, all five sploit compiles, all five vulnerable build tags, and all
  five cumulative clean-copy patch scenarios.
- `python -B scripts/check_archive_hygiene.py` - exit 0.
- `python -B scripts/validate_forcad_config.py` - exit 0.
- `python -B scripts/check_docs_tree.py` - exit 0.
- `python -B scripts/check_wave29_gate.py` - exit 0.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` -
  exit 0, 32 tests passed.
- `python -B scripts/check_competition_matrix_gate.py` - exit 0.

## 6. Documentation Updated

`docs/12_testing_strategy.md` now describes the Wave 29 end-to-end regression
evidence runner, external temp-copy patch application, vulnerable tagged build
checks, and checker-green evidence across the cumulative fixed service.

## 7. CTF Invariants Checked

- Checker PUT stores through normal analyst workflows.
- Checker GET remains owner-view only for place 1 notes and place 2 EDD.
- CHECK/HAVOC remains part of the regression evidence.
- Reference sploits remain public attack-data and side-view based.

## 8. Security Invariants Checked

- Default secure build remains checked by runner-backed Go tests.
- Vulnerable tagged builds remain scoped to planned side-view vectors.
- Reference fixes remain checked for projection/redaction/reference-only
  behavior and feature preservation.

## 9. Self-Review

No product behavior, checker semantics, public attack-data schema, flag-id
format, sploit semantics, patch semantics, migrations, or deployment config
were changed. Test artifacts are created under system temporary directories,
not inside the repository.

## 10. Risks / Open Questions

- Full regression execution is heavier than the static Wave 29 gate because it
  runs vulnerable tagged builds and temporary patched-copy fixed proofs; the
  final runner uses one external clean checkout to avoid repeated full archive
  copies.
- Final release readiness remains a later wave; W29-T02 provides regression
  evidence only.

## 11. Ready for Orchestrator Review

yes.
