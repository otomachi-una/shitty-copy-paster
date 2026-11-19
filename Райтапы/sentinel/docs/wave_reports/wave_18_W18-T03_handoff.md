# Wave 18 W18-T03 Handoff

## 1. Summary

Aligned Wave 18 documentation and status sources after W18-T01/T02. The docs
now state that AML-5 is implemented only under `aml5_vulnerable`, Wave 18 is
under review, and Wave 23 plus `sploits/sentinel_aml/aml_network_room.py`
remain locked until orchestrator acceptance.

## 2. Documentation Details

- Documented default secure network-room behavior as references-first and
  public/redacted.
- Documented tagged AML-5 behavior as local to
  `GET /api/network/rooms/{room_id}/dossier`.
- Recorded the intended AML-5 leak fields: `foreign_private_notes` and
  `foreign_edd_comments`.
- Recorded protected exclusions for credentials, sessions, checker-private
  state, public attack data, raw rows, audit diffs, EDD narrative fields,
  broad source-case blobs, debug/admin controls, exploit artifacts, and fix
  artifacts.
- Updated status ledgers so Wave 18 is under review and Wave 23 remains locked
  pending Wave 18 acceptance.
- Preserved the source-of-truth hierarchy with `docs/09_vulnerability_matrix.md`
  as the vulnerability behavior authority and `docs/13_roadmap.md` as the
  status ledger authority.

## 3. Files Changed

- `docs/09_vulnerability_matrix.md`
- `docs/06_visibility_and_projections.md`
- `docs/network_room_model.md`
- `docs/10_workers_and_async_flows.md`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/source_of_truth_map.md`
- `docs/15_risk_register.md`
- `docs/14_agent_execution_log.md`
- `docs/wave_reports/wave_18_validation_summary.md`
- `docs/wave_reports/wave_18_W18-T03_handoff.md`

## 4. Tests Added

None. This task is documentation/status-only.

## 5. Tests Run

```sh
python -B scripts/check_docs_tree.py
```

Exit code: 0.

```sh
python -B scripts/check_wave18_gate.py
```

Exit code: 0.

```sh
python -B scripts/check_competition_matrix_gate.py
```

Exit code: 0.

## 6. Documentation Updated

Updated vulnerability, visibility, network-room, worker, testing, roadmap,
wave, source-map, risk, execution-log, validation-summary, and handoff
documentation for Wave 18.

## 7. CTF Invariants Checked

- No exploit or fix artifacts were added.
- Both checker places remain active in the docs.
- CHECK/HAVOC remains the source of truth for anti-coarse-fix coverage.
- Wave 23 remains locked until Wave 18 acceptance.

## 8. Security Invariants Checked

- Docs do not normalize broad private data access.
- Docs do not imply room participation grants default access to foreign private
  data.
- The default network-room profile remains references-first.
- No debug/admin toggle, direct DB checker path, credential leak, session leak,
  checker-private leak, or broad serializer leak was documented as intended
  behavior.

## 9. Self-Review

This was limited to documentation and status alignment. Code, checker logic,
ForcAD config, public attack data, sploits, fixes, and previous-wave behavior
were intentionally untouched.

## 10. Risks / Open Questions

- Wave 18 remains under review until orchestrator acceptance.
- Wave 23 and Wave 28 sequencing must remain locked until the orchestrator
  opens those waves.

## 11. Ready for Orchestrator Review

yes
