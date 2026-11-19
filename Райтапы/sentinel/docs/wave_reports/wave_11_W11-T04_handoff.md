# Wave 11 W11-T04 Handoff - Checker Regression Tests and No-Bypass Guardrails

## 1. Summary

Added Wave 11 checker QA/security guardrails for the first real Sentinel AML
checker behavior. The new gate and tests prove place 1 uses normal HTTP APIs,
keeps public attack data credential-free and flag-free, reads flags only through
the owner case-note view, and preserves out-of-scope boundaries.

## 2. Implementation Details

- Added `scripts/check_wave11_gate.py`, a self-contained JSON-reporting Wave 11
  validator.
- Added CLI PUT PFR output-shape coverage against the fake HTTP service.
- Added `make wave11-gate` with Python discovery, Go test/vet, docs-tree, Wave
  11 gate, and ForcAD config validation.
- Updated testing strategy docs with Wave 11 checker gates and non-goals.
- Static gate checks cover no direct DB/internal imports, no hidden endpoints,
  no side-view GET usage, no place 2 lifecycle, no exploit/fix scripts, docs and
  handoff presence, Makefile target presence, and public/private schema
  separation.

## 3. Files Changed

- `tests/test_checker_put_workflow.py`
- `scripts/check_wave11_gate.py`
- `Makefile`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_11_W11-T04_handoff.md`

## 4. Tests Added

- CLI-level checker PUT test proving PFR output contains `flag_id` and
  `attack_data`.
- Public attack-data assertions that exclude raw flag, credentials, bearer
  token, and private state from the public object.
- Wave 11 gate checks for checker source no-bypass boundaries, checker
  regression test presence, absent exploit/fix scripts, docs, handoffs, and
  Makefile integration.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_*checker*.py"` - pass, 25 tests.
- `python -B -m unittest discover -s tests -p "test_*.py"` - pass, 113 tests.
- `python -B scripts/check_wave11_gate.py` - pass.
- `python -B scripts/validate_forcad_config.py` - pass.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - pass with
  command-local `GOCACHE` and `APPDATA` pointed into the workspace to avoid
  Windows sandbox cache/telemetry permission failures.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - pass with
  command-local `GOCACHE` and `APPDATA` pointed into the workspace.

## 6. Documentation Updated

- `docs/12_testing_strategy.md` documents Wave 11 checker coverage,
  `scripts/check_wave11_gate.py`, `make wave11-gate`, and explicit Wave 11
  non-goals.

## 7. CTF Invariants Checked

- No checker bypass.
- No public credentials.
- No side-view GET.
- No place 2 lifecycle, HAVOC, exploit, or reference-fix behavior.
- Public attack data remains locator/hint-only.

## 8. Security Invariants Checked

- Raw flag is allowed only in fake-server private note request/response fixtures
  for owner note behavior tests.
- Tests and gate assert private data is absent from public attack data.
- Checker source gate rejects DB/internal dependency markers and hidden endpoint
  markers.

## 9. Self-Review

The change is limited to checker tests, Wave 11 gate script, Makefile target,
testing docs, and this handoff. No product features, migrations,
vulnerabilities, exploits, fixes, place 2 lifecycle, HAVOC, debug/admin routes,
or public attack-data route were added.

## 10. Risks / Open Questions

- The Wave 11 gate is static plus schema-helper based; live service behavior is
  still covered by fake HTTP checker tests rather than a running deployment.
- Historical gates remain wave-specific and may reject intentional later-wave
  expansions when run against the current branch.

## 11. Ready for Orchestrator Review

Yes.
