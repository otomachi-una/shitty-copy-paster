# Wave 09 W09-T04 Handoff

## 1. Summary

Created the Wave 09 validation gate, Python gate regression tests, Makefile target, validation summary, and source-of-truth status updates for the secure related-graph baseline. Wave 08 is marked complete, and Wave 09 remains `needs fixes` until orchestrator review accepts W09-T01 through W09-T04.

## 2. Implementation Details

- Added `scripts/check_wave09_gate.py` with JSON pass/fail output for the current branch.
- Added `tests/test_wave09_gate.py` with current-branch pass coverage and intentional drift fixtures.
- Added `make wave09-gate`.
- Updated status and testing docs to identify Wave 09 as the current validation authority.
- Added `docs/wave_reports/wave_09_validation_summary.md`.

The gate validates `000007_create_entity_graph.sql`, `internal/graph`, secure graph routes, `GraphEntityView`, `GraphRelatedCaseView`, `EDDGraphSummaryView`, projection allowlists, Anti-AML-3 test markers, forbidden private graph fields, absence of checker/public attack-data/export/network/debug/admin route expansion, absence of exploit/fix scripts, Wave 09 reports, docs status, docs tree, and ForcAD config.

## 3. Files Changed

- `scripts/check_wave09_gate.py`
- `tests/test_wave09_gate.py`
- `Makefile`
- `README.md`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/source_of_truth_map.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_09_validation_summary.md`
- `docs/wave_reports/wave_09_W09-T04_handoff.md`

## 4. Tests Added

- `tests/test_wave09_gate.py`
  - current branch gate pass check;
  - missing graph migration fixture;
  - graph repository private-field fixture;
  - out-of-scope route fixture;
  - graph presenter private-field fixture;
  - missing Anti-AML-3 tests fixture;
  - exploit/fix script fixture;
  - missing docs status fixture;
  - missing Makefile target fixture.

## 5. Tests Run

- `make wave09-gate`: not runnable on this Windows host because `make` is not installed on `PATH`; the target exists and all underlying commands were run directly.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: first run failed on Windows default Go build-cache access denied; rerun with `GOCACHE` set to `.gocache` passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: passed with `GOCACHE` set to `.gocache`.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/projection ./tests -run "AML3|Graph|Visibility|Projection" -count=1`: passed.
- `python -B -m unittest discover -s tests -p "test_wave09_gate.py"`: passed, 9 tests.
- `python -B -m unittest discover -s tests -p "test_*.py"`: passed, 79 tests.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/check_wave09_gate.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.

## 6. Documentation Updated

- README current status and command list.
- Testing strategy Wave 09 graph/gate coverage.
- Roadmap and waves status ledger.
- Source-of-truth map current branch authority.
- Risk register entry R-043 for Wave 09 gate drift.
- Execution log entries for W09-T03 and W09-T04.
- Wave 09 validation summary.

## 7. CTF Invariants Checked

- No checker PUT/GET behavior added.
- No public attack data added.
- No planned vulnerability added.
- No exploit or reference-fix scripts added.
- ForcAD config unchanged.
- AML-3 remains future-only until Wave 16.

## 8. Security Invariants Checked

- Graph endpoints remain authenticated and owned-hint scoped.
- Graph DTOs are explicit and safe metadata only.
- `CaseNote.body` and `EDDRecord.confidential_comment` remain outside graph responses.
- Raw audit diffs, hashes, credentials, sessions, owner IDs, trace IDs, counterparty fingerprints, checker-private markers, artificial flag fields, and raw DB rows remain outside graph DTOs.
- Cross-owner graph access remains fail-closed.

## 9. Self-Review

The work is validation/docs only and does not change product runtime behavior. The gate is intentionally strict about Wave 09’s graph surface while treating prior gates as historical branch validators after later-wave expansion. Anti-AML-3 remains a negative security baseline, not a vulnerability implementation.

## 10. Risks / Open Questions

- Historical gates may continue to need explicit test expectation updates as future waves intentionally add new migrations/routes.
- Live PostgreSQL execution is not part of the Wave 09 close gate unless a future orchestrator requires graph live coverage.

## 11. Ready for Orchestrator Review

Yes.
