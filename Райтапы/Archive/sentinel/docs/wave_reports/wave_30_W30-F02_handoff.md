# Wave 30 W30-F02 Handoff - Final Release Gate Target

## 1. Summary

W30-F02 adds `wave30-gate` as the single Wave 30 release-readiness command and
aligns the active ledgers around that command. The target delegates to the
stabilized Wave 29 matrix/regression evidence, then runs Wave 30 wiring
validation, ForcAD validation, archive hygiene, and release archive generation.
Wave 30 remains ready for orchestrator review only; this does not claim final
competition readiness.

## 2. Implementation Details

- Added `scripts/check_wave30_gate.py` with JSON pass/fail output for final
  target wiring, Wave 29 delegate integrity, and release-doc status wording.
- Added `tests/test_wave30_gate.py` to reject a missing target, docs-only target,
  missing release archive generation, missing final command docs, and weakened
  Wave 29 delegation.
- Added `wave30-gate` to `Makefile`. It runs Wave 30 tests, `wave29-gate`,
  `competition-matrix-gate`, `check_wave30_gate.py`, ForcAD validation, archive
  hygiene, and `release-archive`.
- Updated status docs so final acceptance evidence is owned by
  `timeout 300 make wave30-gate`, while Wave 30 acceptance and final competition
  readiness remain orchestrator-owned.

Status-ledger diff summary:

- Before: Wave 30 final review evidence centered on `make wave29-gate`; no
  Wave 30-owned final gate target existed.
- After: Wave 30 is ready for orchestrator review through the exact
  `timeout 300 make wave30-gate` command; no future feature waves are unlocked;
  only final release-candidate handoff/package promotion remains after
  orchestrator acceptance.

## 3. Files Changed

- `Makefile`
- `scripts/check_wave30_gate.py`
- `tests/test_wave30_gate.py`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/source_of_truth_map.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_30_final_validation_summary.md`
- `docs/wave_reports/wave_30_release_readiness_manifest.md`
- `docs/wave_reports/wave_30_W30-F02_handoff.md`

## 4. Tests Added

- `tests/test_wave30_gate.py` covers concrete target wiring, release archive
  coverage, documentation naming, and negative cases for docs-only or weakened
  final gates.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_wave30_gate.py"` - exit 0,
  6 tests in 2.833s after final documentation updates.
- `python -B scripts/check_wave30_gate.py` - exit 0.
- `python -B scripts/check_docs_tree.py` - exit 0.
- `timeout 300 make wave30-gate` - exit 0, elapsed 4m3.712s on the WSL
  GNU-timeout/make path.
- `python -B scripts/check_docs_tree.py` - exit 0 after final documentation
  updates.
- `python -B scripts/check_archive_hygiene.py` - exit 0 after final
  documentation updates.

The `wave30-gate` run produced
`/tmp/sentinel-aml-release/sentinel_aml_release.tar.gz` with 668 files and
SHA-256 `7ee8026ce68da3ca1f59507b19ec077151d06d1229bfafc7b1688cafa43b2fa5`.

## 6. Documentation Updated

- `docs/12_testing_strategy.md` now names `timeout 300 make wave30-gate` as the
  single final acceptance command and clarifies that `wave29-gate` is the
  delegated matrix/regression command.
- `docs/wave_reports/wave_30_release_readiness_manifest.md` and
  `docs/wave_reports/wave_30_final_validation_summary.md` record final target
  structure and exact W30-F02 evidence.
- Roadmap, waves, source map, execution log, and risk register now agree that
  Wave 30 is ready for orchestrator review only, with no future feature waves
  unlocked.

## 7. CTF Invariants Checked

- ForcAD checker type remains `pfr`.
- Exactly two checker places remain documented and validated.
- Place 1 remains `CaseNote.body`; place 2 remains
  `EDDRecord.confidential_comment`.
- Checker PUT/GET, CHECK/HAVOC, five sploit compiles, five patch apply checks,
  Wave 29 regression, matrix validation, ForcAD validation, and archive hygiene
  all remain in the final target path.

## 8. Security Invariants Checked

- No product behavior, checker behavior, exploit behavior, fix patch semantics,
  public attack-data schema, or config semantics changed.
- The final gate still rejects docs-only final evidence and preserves Wave 29
  anti-coarse-fix coverage for endpoint removal, feature disabling,
  sensitive-field renames, debug/admin shortcuts, and direct DB shortcuts.
- No side-view widening, private-field exposure, credentials, sessions, raw
  audit diffs, hashes, checker-private state, or raw DB rows were introduced.

## 9. Self-Review

The final target is concrete and diagnostic: it runs Wave 30 target tests first,
then the full stabilized Wave 29 aggregate evidence, then final release checks.
The status ledgers no longer treat Wave 29 component evidence as the only final
acceptance path. Final competition readiness is intentionally not claimed.

## 10. Risks / Open Questions

- Orchestrator still owns final Wave 30 acceptance and may require a fresh
  review-environment run of `timeout 300 make wave30-gate`.
- Release archive checksums can change when evidence docs are edited; archive
  hygiene, inventory, and generated-archive validation remain the stable
  acceptance properties.

## 11. Ready for Orchestrator Review

Ready for Orchestrator Review: yes
