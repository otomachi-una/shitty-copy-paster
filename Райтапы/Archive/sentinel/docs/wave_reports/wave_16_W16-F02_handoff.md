# W16-F02 Handoff — Repository Archive Hygiene Gate

## 1. Summary

Added packaging hygiene controls so review and competition archives reject local
cache, telemetry, IDE, bytecode, and OS metadata artifacts. The change is
packaging-only and does not alter product, checker, vulnerability, sploit, fix,
migration, or ForcAD behavior.

## 2. Implementation Details

- Extended `.gitignore` for local Go cache, telemetry, appdata, Python
  bytecode, Python cache, and editor artifacts.
- Added `scripts/check_archive_hygiene.py`, which scans repository snapshots for
  forbidden local artifacts while ignoring `.git/` internals.
- Added unit tests for clean trees, root cache/IDE directories, nested
  `__pycache__/`, bytecode files, and `.git/` traversal exclusion.
- Documented clean archive expectations in deployment and testing docs.
- Added risk-register coverage for local artifact leakage.

## 3. Files Changed

- `.gitignore`
- `scripts/check_archive_hygiene.py`
- `tests/test_archive_hygiene.py`
- `docs/11_deployment.md`
- `docs/12_testing_strategy.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_16_W16-F02_handoff.md`

## 4. Tests Added

- `tests/test_archive_hygiene.py`

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_archive_hygiene.py"`:
  pass, 4 tests.
- `python -B scripts/check_archive_hygiene.py`: pass.
- `python -B scripts/check_docs_tree.py`: pass.

## 6. Documentation Updated

Updated deployment and testing strategy docs with forbidden archive artifacts,
clean packaging expectations, and hygiene gate commands. Updated the risk
register with archive local-artifact leakage.

## 7. CTF Invariants Checked

- Checker layout remains `checkers/sentinel_aml/`.
- Sploits layout remains `sploits/sentinel_aml/`.
- ForcAD `config.yml` remains unchanged.

## 8. Security Invariants Checked

- Local cache, telemetry, IDE, bytecode, and OS metadata artifacts are rejected
  from final bundles.
- No source behavior, vulnerability profile, checker path, exploit, or fix was
  changed.

## 9. Self-Review

The hygiene script is read-only and packaging-scoped. It reports forbidden
artifacts but does not delete files itself, keeping cleanup explicit and
reviewable.

## 10. Risks / Open Questions

- Existing local artifact directories must be cleaned before the hygiene gate
  can pass on this checkout.
- Future packaging automation should include this gate before archive creation.

## 11. Ready for Orchestrator Review: yes/no

yes
