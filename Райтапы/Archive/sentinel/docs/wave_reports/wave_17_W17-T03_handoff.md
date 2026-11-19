# Wave 17 W17-T03 Handoff

## 1. Summary

Aligned documentation for AML-4 after W17-T01/T02. AML-4 is now documented as
implemented only under the `aml4_vulnerable` Go build tag and still under
review. The default export build remains recursively redacted, AML-4
exploit/fix work remains locked, and AML-5 remains future-only.

## 2. Implementation Details

- Updated `docs/09_vulnerability_matrix.md` with the AML-4 source-of-truth
  section, including endpoint/process, leaked field, protected exclusions, gate
  authority, and future fix direction.
- Updated projection and audit/export/graph invariant docs to distinguish
  secure/default export behavior from tagged vulnerable behavior.
- Updated testing strategy with Wave 17 gate coverage and exact command set.
- Updated roadmap, waves, and source-of-truth map so Wave 17 is under review
  and Wave 22 unlocks only after Wave 17 acceptance.
- Added risk-register entries for AML-4 scope control and Wave 17/AML-5 gate
  drift.
- Added Wave 17 validation summary and this W17-T03 handoff report.

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
- `docs/wave_reports/wave_17_validation_summary.md`
- `docs/wave_reports/wave_17_W17-T03_handoff.md`

## 4. Tests Added

No tests were added in W17-T03. This was a documentation and status alignment
task.

## 5. Tests Run

```sh
python -B scripts/check_docs_tree.py
python -B scripts/check_wave17_gate.py
python -B scripts/check_competition_matrix_gate.py
```

Results: all passed.

## 6. Documentation Updated

- AML-4 now points to `docs/09_vulnerability_matrix.md` as the authoritative
  behavior source.
- Default build secure export behavior is explicit.
- Tagged `aml4_vulnerable` behavior is bounded to dispute export
  `linked_private_notes[].body`.
- AML-4 exploit/fix sequencing stays future-only.
- Wave 17 status is under review, not complete.

## 7. CTF Invariants Checked

- No exploit/fix claims were added.
- Checker owner paths remain independent of export side views.
- Public attack data remains locator-only.
- Wave 22 remains locked until Wave 17 acceptance.
- AML-5 remains locked for Wave 18.

## 8. Security Invariants Checked

- Default export behavior remains documented as recursively redacted.
- AML-4 vulnerable field is bounded to linked duplicate-case private note
  bodies.
- Root private notes, EDD confidential comments, audit diffs, graph data,
  network-room dossier data, credentials, sessions, checker-private state, raw
  rows, debug/admin controls, and broad serialization remain forbidden.

## 9. Self-Review

The documentation now reflects the implemented profile without marking Wave 17
complete. Source-of-truth references remain centered on
`docs/09_vulnerability_matrix.md`, and status ledgers agree that Wave 17 is
under review. Historical Wave 10 secure export text remains as baseline context
while the current AML-4 profile is described in Wave 17 sections.

## 10. Risks / Open Questions

- W17-T03 did not rerun Go or checker tests because this task is docs-only; the
  validation summary references W17-T01/T02 command evidence.
- `make wave17-gate` still needs wrapper confirmation on a make-enabled
  orchestrator host.
- R-068 and R-069 remain open until Wave 17 is accepted.

## 11. Ready for Orchestrator Review

yes
