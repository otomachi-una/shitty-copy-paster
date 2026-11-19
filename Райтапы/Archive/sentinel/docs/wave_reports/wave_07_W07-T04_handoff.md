# Wave 07 W07-T04 Handoff - Wave 07 Gate, Docs Alignment, and Validation Summary

## 1. Summary

W07-T04 adds the Wave 07 branch validation gate, regression tests for that gate, `make wave07-gate`, source-of-truth status alignment, and `docs/wave_reports/wave_07_validation_summary.md`. The gate validates the secure dedup baseline and rejects accidental AML-1 private-note/EDD leakage before the planned Wave 14 vulnerability.

Ready for orchestrator review: yes.

## 2. Implementation Details

- Added `scripts/check_wave07_gate.py` with JSON pass/fail output.
- Added `tests/test_wave07_gate.py` for current-branch pass behavior and intentional drift fixtures.
- Added `make wave07-gate`.
- Updated source-of-truth status so Wave 06 is complete and Wave 07 is `needs fixes` pending orchestrator acceptance.
- Updated docs to make `scripts/check_wave07_gate.py` and `docs/wave_reports/wave_07_validation_summary.md` the current branch validation authority.
- Preserved older wave gate scripts as historical validators that may reject intentional later-wave expansion.

## 3. Files Changed

- `scripts/check_wave07_gate.py`
- `tests/test_docs_tree.py`
- `tests/test_wave07_gate.py`
- `Makefile`
- `README.md`
- `docs/03_api_contract.md`
- `docs/04_database_model.md`
- `docs/06_visibility_and_projections.md`
- `docs/09_vulnerability_matrix.md`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/source_of_truth_map.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_07_validation_summary.md`
- `docs/wave_reports/wave_07_W07-T04_handoff.md`

## 4. Tests Added

- Gate current-branch pass test.
- Missing dedup migration/metadata failure fixture.
- Checker/public attack-data route failure fixture.
- Dedup DTO/presenter private-field failure fixture.
- Missing anti-AML-1 test failure fixture.
- Forbidden exploit script failure fixture.
- Missing status-doc markers failure fixture.

## 5. Tests Run

- `make wave07-gate` - not runnable on this Windows host because no `make`, `mingw32-make`, or `gmake` executable is installed on `PATH`; the target exists in `Makefile`.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/check_wave07_gate.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run "Dedup|AML1|Visibility|CaseDuplicatePreview" -count=1` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/projection ./tests -run "Projection|Dedup|Wave07" -count=1` - passed.

Go commands used vendor mode and a local writable `GOCACHE` where needed. The direct commands are exactly the commands run by `make wave07-gate` plus the focused test commands.

## 6. Documentation Updated

- README now lists Wave 07 status and `make wave07-gate`.
- Roadmap, waves, and source-of-truth map now identify Wave 06 as complete and Wave 07 as the current `needs fixes` review wave.
- API, database, vulnerability matrix, visibility, and testing docs now describe the secure dedup gate and anti-AML-1 boundary.
- Risk register adds Wave 07 gate drift mitigation.
- Validation summary records scope, tests, CTF invariants, and security invariants.

## 7. CTF Invariants Checked

- No checker PUT/GET behavior was added.
- No public attack data was added.
- No planned vulnerability was added.
- No exploit or reference-fix scripts were added.
- AML-1 remains locked until Wave 14.

## 8. Security Invariants Checked

- Gate fails if dedup preview exposes note-body or EDD confidential-comment fields.
- Gate fails on obvious checker, public attack-data, graph/export/network, debug, or admin route expansion.
- Dedup DTO/projection shape remains public-only.
- Private `CaseNote.body` and `EDDRecord.confidential_comment` remain owner-only.

## 9. Self-Review

This task changed validation wiring, tests, and documentation only. It did not modify product behavior, migrations, repository code, HTTP handlers, checker code, sploit placeholders, or ForcAD config. The gate intentionally treats Wave 06 as historical and Wave 07 as current branch authority.

## 10. Risks / Open Questions

- Earlier wave gate scripts remain strict historical closures and may fail on the current Wave 07 branch by design.
- Local Windows PATH lacks `make`, so `make wave07-gate` could not be executed in this environment. The target is present and its underlying commands pass directly.
- Live PostgreSQL dedup route validation remains covered by broader opt-in integration patterns, not a new W07-specific live target.

## 11. Ready for Orchestrator Review

yes
