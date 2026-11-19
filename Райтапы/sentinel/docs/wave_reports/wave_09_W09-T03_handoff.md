# W09-T03 Handoff — Anti-AML-3 Regression and Visibility Matrix

## 1. Summary

Added named Anti-AML-3 regression coverage proving secure Wave 09 graph visibility does not disclose private case-note bodies or EDD confidential comments. The work is test and documentation focused; no production behavior, checker behavior, exploit code, or vulnerability behavior was added.

## 2. Implementation Details

- Added `TestAntiAML3RelatedGraphDoesNotExposePrivateStores`.
- The test creates:
  - a victim analyst with a customer, case, private note, and EDD record;
  - a second analyst with an owned customer sharing the same `entity_hint`;
  - high-entropy victim `CaseNote.body` and `EDDRecord.confidential_comment` sentinel values.
- The test verifies:
  - owner note and owner EDD endpoints still return private business fields to the owner;
  - graph entity, related-case, and EDD-summary endpoints may show safe related metadata;
  - graph responses for both analysts never include victim private sentinel values;
  - cross-owner direct note and EDD reads still fail closed.
- Added `TestAntiAML3GraphProjectionContractsDenyPrivateFields`.
- Added `TestAntiAML3GraphRepositorySummariesStayMetadataOnly`.
- Preserved existing Anti-AML-1, Anti-AML-2, W06 visibility, graph, and projection tests.

## 3. Files Changed

- `internal/httpapi/graph_server_test.go`
- `internal/projection/contracts_test.go`
- `tests/projection_visibility_test.go`
- `docs/06_visibility_and_projections.md`
- `docs/09_vulnerability_matrix.md`
- `docs/12_testing_strategy.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_09_W09-T03_handoff.md`

## 4. Tests Added

- `TestAntiAML3RelatedGraphDoesNotExposePrivateStores`
- `TestAntiAML3GraphProjectionContractsDenyPrivateFields`
- `TestAntiAML3GraphRepositorySummariesStayMetadataOnly`

These tests fail on obvious graph leakage of private note body values, EDD confidential comments, raw audit diffs, hashes, credentials, session material, owner IDs in graph outputs, checker-private markers, artificial flag fields, transaction traces, counterparty fingerprints, or raw DB rows.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/projection ./tests -run "AML3|Graph|Visibility|Projection" -count=1` — passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` — passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` — passed.
- `python -B scripts/check_docs_tree.py` — passed.
- `python -B scripts/validate_forcad_config.py` — passed.

## 6. Documentation Updated

- Visibility/projection docs now name the Anti-AML-3 matrix and graph source guards.
- Vulnerability matrix now defines AML-3 as future-only until Wave 16.
- Testing strategy now lists the W09-T03 focused command and named tests.
- Risk register now tracks Anti-AML-3 guard drift.

## 7. CTF Invariants Checked

- No checker PUT/GET behavior was added.
- No public attack data was added.
- No exploit or reference-fix scripts were added.
- Existing future checker owner paths remain intact.
- AML-3 exploit behavior remains impossible in the secure baseline.

## 8. Security Invariants Checked

- Graph responses never reveal private case-note body values or EDD confidential comment values.
- Graph response field names remain allowlisted safe metadata only.
- Cross-owner direct private note and EDD reads fail closed.
- Owner note and owner EDD visibility remains intact for normal owner workflows.
- Source guards cover graph repository summaries, graph HTTP DTOs, graph presenters, and projection contracts.

## 9. Self-Review

The change stayed within the W09-T03 test/doc scope. It did not touch production HTTP handlers, repositories, migrations, checker code, sploits, ForcAD config, or planned vulnerability behavior. The Anti-AML-3 tests exercise both endpoint behavior and static projection/source boundaries.

## 10. Risks / Open Questions

- Wave 09 still needs a dedicated W09-T04 branch gate and validation summary to align historical gate expectations with the secure graph expansion.
- Live PostgreSQL graph HTTP integration was not required by W09-T03 and was not run.
- AML-3 remains intentionally undefined beyond its future Wave 16 boundary.

## 11. Ready for Orchestrator Review: yes

