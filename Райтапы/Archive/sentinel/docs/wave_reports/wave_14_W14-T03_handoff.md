# W14-T03 Handoff - AML-1 Documentation and Risk Alignment

## 1. Summary

W14-T03 aligns the source-of-truth documentation for the first planned
vulnerable A/D slice. AML-1 is documented as implemented only in the
`aml1_vulnerable` profile, while AML-1 exploit/fix work and AML-2 through AML-5
remain future-only.

## 2. Documentation Details

- Made `docs/09_vulnerability_matrix.md` the explicit source of truth for
  vulnerability behavior, variant scope, exploit/fix sequencing, and protected
  field boundaries.
- Recorded the AML-1 endpoint and process:
  `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`
  exposes duplicate `private_notes[].body` only in the tagged profile, only
  when the requester owns the source case and the target is a valid dedup
  candidate.
- Documented that checker GET remains unchanged: place 1 reads owner notes
  directly and place 2 reads owner EDD directly.
- Updated roadmap and wave ledgers so Wave 14 is under review, not merely
  planned.
- Preserved the secure default profile as necessary comparison evidence for
  later fixed/profile validation.

## 3. Files Changed

- `docs/09_vulnerability_matrix.md`
- `docs/06_visibility_and_projections.md`
- `docs/08_checker_design.md`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/source_of_truth_map.md`
- `docs/wave_reports/wave_14_validation_summary.md`

## 4. Tests Run

Passed:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave14_gate.py`

## 5. Documentation Updated

- Vulnerability matrix now states AML-1 is implemented and under review only in
  `aml1_vulnerable`.
- Visibility/projection docs point back to the vulnerability matrix for AML-1
  behavior and protected fields.
- Checker design explicitly states AML-1 does not change checker PUT/GET.
- Roadmap and waves mark Wave 14 as under review and keep exploit/fix work
  locked.
- Risk register records AML-1 scope and source-of-truth guardrails.

## 6. CTF Invariants Checked

- Vulnerability first, exploit later, fix after exploit evidence, full matrix
  last.
- AML-1 exploit remains locked until Wave 19.
- AML-1 fix remains locked until Wave 24.
- AML-2 through AML-5 remain future-only.

## 7. Security Invariants Checked

- Documentation keeps AML-1 local to dedup merge-preview.
- Protected fields remain explicit: EDD confidential comments, EDD narrative
  fields, audit diffs, credentials, sessions, checker-private state, public
  attack data, raw DB rows, and debug/admin controls are not normalized as AML-1
  behavior.

## 8. Self-Review

The missing ambiguity was status drift: some docs still described Wave 14 as
planned even after AML-1 implementation and gate work. W14-T03 reconciles that
by marking Wave 14 under review while leaving future exploit/fix scopes locked.

## 9. Risks / Open Questions

- Wave 14 remains under review until W14-F01 liveness evidence and the Wave 14
  gate are accepted by the orchestrator.
- The orchestrator still chooses whether to proceed next with Wave 19 AML-1
  exploit evidence or continue vulnerability-profile implementation in Wave 15.

## 10. Ready for Orchestrator Review

Yes.
