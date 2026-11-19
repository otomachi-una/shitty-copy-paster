# W29-T01 - Full Competition Matrix Gate Handoff

## 1. Summary

Wave 29 adds the full competition matrix gate for Sentinel AML. The gate
validates all checker, vulnerability, exploit, reference-fix, exploit-blocked,
and anti-coarse-fix evidence together without marking final release readiness.

## 2. Implementation Details

- Added `scripts/check_wave29_gate.py` with JSON pass/fail output.
- Added `tests/test_wave29_gate.py` for current-branch success and negative
  coverage around checker shortcuts, exploit inventory/scope, missing patches,
  sensitive-field rename leaks, missing vulnerable-profile coverage, and
  incomplete Makefile targets.
- Added `wave29-gate` to the Makefile.
- The Wave 29 gate composes the current competition matrix with cross-cutting
  CTF/security checks and the AML-1 through AML-5 patch-scope,
  exploit-blocked, and anti-coarse-fix helper checks.

## 3. Files Changed

- `scripts/check_wave29_gate.py`
- `tests/test_wave29_gate.py`
- `Makefile`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_29_W29-T01_handoff.md`

## 4. Tests Added

- Positive full Wave 29 gate validation.
- Negative checker-contract tests for missing place 2 PFR store and direct DB
  shortcuts.
- Negative exploit inventory and side-view-scope tests.
- Negative patch inventory/applicability and sensitive-field rename tests.
- Negative vulnerable-profile coverage and Makefile coverage tests.

## 5. Tests Run

| Command | Exit | Evidence |
| --- | ---: | --- |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | 0 | 97 checker tests passed. |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | 0 | 32 competition matrix tests passed. |
| `python -B -m unittest discover -s tests -p "test_wave29_gate.py"` | 0 | 10 Wave 29 tests passed. |
| `python -B scripts/check_competition_matrix_gate.py` | 0 | Matrix JSON gate passed with all AML-1 through AML-5 vulnerable, exploit-success, fixed-checker, exploit-blocked, and anti-coarse-fix cells concrete. |
| `python -B scripts/check_wave29_gate.py` | 0 | Full Wave 29 JSON gate passed. |
| `python -B scripts/check_docs_tree.py` | 0 | Docs tree passed. |
| `python -B scripts/check_archive_hygiene.py` | 0 | Archive hygiene passed. |
| `make wave29-gate` | 1 | Local Windows host does not have `make` on PATH; the Makefile target is present and statically validated by `scripts/check_wave29_gate.py`. |

## 6. Documentation Updated

`docs/12_testing_strategy.md` documents the Wave 29 full competition matrix gate
scope, target commands, and non-readiness boundary.

## 7. CTF Invariants Checked

- Two active checker flag stores remain required.
- Place 1 remains `CaseNote.body` through owner case-note APIs.
- Place 2 remains `EDDRecord.confidential_comment` through owner EDD APIs.
- Public attack data remains credential-free.
- CHECK/HAVOC remains release-blocking.

## 8. Security Invariants Checked

- Exploits remain side-view only and are checked against owner-private APIs,
  direct DB paths, shell helpers, and debug/admin shortcuts.
- Reference fixes must preserve feature behavior and reject endpoint removal,
  docs-only patches, gate-only patches, sensitive-field renames, direct DB
  shortcuts, and debug/admin paths.

## 9. Self-Review

No product behavior, checker semantics, sploit semantics, patch semantics,
migrations, or deployment config were changed. Wave 29 intentionally does not
mark final release readiness; it validates the completed matrix as a
pre-packaging readiness gate.

## 10. Risks / Open Questions

- Full aggregate `make wave29-gate` evidence depends on a host with GNU
  `make`/shell semantics. This local Windows host could not execute it because
  `make` is not installed on PATH.
- Final release readiness remains a later wave after full regression/package
  validation.

## 11. Ready for Orchestrator Review

yes.
