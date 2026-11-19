# W16-T03 Handoff — AML-3 Documentation and Risk Alignment

## 1. Summary

Aligned Wave 16 documentation so AML-3 is described as implemented only under
the `aml3_vulnerable` profile and still under review. The docs now identify the
exact graph endpoint and leaked field, keep exploit/fix work locked, and point
behavior authority back to `docs/09_vulnerability_matrix.md`.

## 2. Implementation Details

- Updated AML-3 source-of-truth wording to define
  `GET /api/graph/entities/{entity_hint}/edd-summaries` as the only tagged
  vulnerable endpoint.
- Documented `confidential_comment` as the only intended AML-3 leaked field.
- Preserved default graph metadata-only behavior and owner checker GET paths.
- Updated status ledgers so Wave 16 is under review, not complete, and Wave 21
  unlocks only after Wave 16 acceptance.
- Added AML-3 scope and Wave 16 gate-drift risks.

## 3. Files Changed

- `docs/09_vulnerability_matrix.md`
- `docs/06_visibility_and_projections.md`
- `docs/audit_export_graph_invariants.md`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/source_of_truth_map.md`
- `docs/15_risk_register.md`
- `docs/14_agent_execution_log.md`
- `docs/wave_reports/wave_16_validation_summary.md`
- `docs/wave_reports/wave_16_W16-T03_handoff.md`

## 4. Tests Added

No code tests were added; this task is documentation/source-of-truth alignment.

## 5. Tests Run

- `python -B scripts/check_docs_tree.py`: pass.
- `python -B scripts/check_wave16_gate.py`: pass.
- `python -B scripts/check_competition_matrix_gate.py`: pass.

## 6. Documentation Updated

Updated vulnerability, visibility/projection, audit/export/graph invariant,
testing strategy, roadmap, waves, source-of-truth, risk, execution-log, and Wave
16 validation/handoff documents.

## 7. CTF Invariants Checked

- Two active checker flag stores remain checker-owned.
- AML-3 does not add or require a reference exploit in Wave 16.
- Public attack data remains locator-only.
- Wave 21 remains blocked until Wave 16 acceptance.

## 8. Security Invariants Checked

- Default graph remains secure and metadata-only.
- Tagged vulnerable behavior is narrow and documented.
- Protected fields outside `EDDRecord.confidential_comment` remain forbidden.
- Checker GET remains independent of graph side views.

## 9. Self-Review

The documentation now distinguishes secure default graph behavior, the
`aml3_vulnerable` profile, and future exploit/fix sequencing. I did not alter
product code, checker behavior, gate scripts, exploit files, or reference fixes.

## 10. Risks / Open Questions

- Wave 16 still needs orchestrator acceptance before it can close.
- A make-equipped host should provide final wrapper evidence if local `make`
  remains unavailable.
- AML-4/AML-5 and AML-3 exploit/fix work remain locked.

## 11. Ready for Orchestrator Review: yes/no

yes
