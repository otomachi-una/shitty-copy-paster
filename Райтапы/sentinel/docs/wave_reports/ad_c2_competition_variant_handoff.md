# AD-C2 Handoff - Competition Variant and Gate Rewrite

## 1. Summary

Added the competition variant/reference-fix strategy and an executable
competition matrix placeholder gate. The repository now has a formal ADR for
moving from pre-exploit "no exploit scripts" gates to vulnerable/fixed matrix
validation once exploit waves start, plus a skeleton reference-fix directory.

## 2. Implementation Details

- Added ADR-0002 for vulnerable/fixed variant strategy and reference-fix
  handling.
- Added `fixes/sentinel_aml/README.md` as the reference-fix skeleton.
- Added `scripts/check_competition_matrix_gate.py` with structural placeholder
  checks for:
  - vulnerable checker gate;
  - exploit-success gate;
  - fixed checker gate;
  - exploit-blocked gate;
  - anti-coarse-fix gate.
- Added a current guard proving no HTTP debug/admin variant toggles exist in
  product/checker/config sources.
- Added `competition-matrix-gate` to the Makefile.

## 3. Files Changed

- `Makefile`
- `docs/decisions/ADR-0002-competition-variant-and-reference-fix-strategy.md`
- `fixes/sentinel_aml/README.md`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `docs/wave_reports/ad_c2_competition_variant_handoff.md`

## 4. Tests Added

- Current-branch competition gate pass test.
- Missing ADR failure test.
- Missing reference-fix skeleton failure test.
- Missing matrix placeholder failure test.
- Debug/admin variant toggle rejection test.

## 5. Tests Run

- `python -B scripts\check_competition_matrix_gate.py`: pass.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  pass, 5 tests.
- `python -B scripts\check_docs_tree.py`: pass.

## 6. Documentation Updated

- ADR-0002 is now the source of truth for competition variants, matrix gates,
  reference exploits, and reference fixes after exploit waves start.
- The reference-fix README documents that fixes must remain narrow and must not
  disable business modules or use debug/admin shortcuts.

## 7. CTF Invariants Checked

- No vulnerable behavior was added.
- No exploit script was added.
- No reference fix implementation was added.
- No checker PUT/GET semantics were changed.
- Future matrix gates preserve checker viability in vulnerable and fixed
  profiles.

## 8. Security Invariants Checked

- The competition gate scans product/checker/config sources for HTTP
  debug/admin variant toggles.
- Variant strategy forbids debug/admin endpoints, checker-only shortcuts,
  public credentials, raw flags, and direct database shortcuts.

## 9. Self-Review

This is a scaffolding and architecture-alignment change. The matrix cells are
intentionally placeholders until vulnerability, exploit, and reference-fix waves
open. The current executable value is structural validation plus debug/admin
toggle prevention.

## 10. Risks / Open Questions

- Later exploit/fix waves must replace placeholder matrix cells with concrete
  vulnerable-positive and fixed-negative commands.
- Historical pre-exploit wave gates may still reject exploit/fix scripts by
  design; ADR-0002 clarifies that current/future competition gates should use
  the matrix once those artifacts are in scope.

## 11. Ready for Orchestrator Review

Yes.
