# Wave 13 W13-T04 Handoff - Export and Network-Room CHECK/HAVOC

## 1. Summary

Implemented and validated `check_export` and `check_network_room` for the Wave
13 CHECK/HAVOC framework. These subchecks make export and network-room modules
part of the checker SLA so teams cannot pass by disabling the AML-4/AML-5 side
surfaces, while preserving the secure public/redacted baseline.

## 2. Implementation Details

- `check_export` creates an owned investigation case, writes non-secret note and
  EDD context, requests a case export, reads the export back, and validates the
  `public_redacted` export shape.
- Export validation checks the export envelope, root/linked case shells, audit
  summaries, EDD summaries, and item metadata.
- `check_network_room` creates deterministic same-entity investigation cases,
  observes the normal network-room summary list, reads a dossier, and verifies
  references-only public case summaries.
- Network-room validation requires the created case references, room relation
  metadata, `public_redacted` policy, and `private_data_omitted` case markers.
- Place 1 and place 2 PUT/GET behavior was not changed.

## 3. Files Changed

- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_check_workflow.py`
- `docs/08_checker_design.md`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_13_W13-T04_handoff.md`

## 4. Tests Added

- Export creation/readback through normal HTTP routes.
- Export disabled route fails CHECK.
- Export private-field leakage fails CHECK.
- Network-room summary and dossier public-shape validation.
- Network-room disabled route fails CHECK.
- Missing materialized room fails CHECK.
- Network-room private-field leakage fails CHECK.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_checker_check_workflow.py"`:
  pass.
- `python -B -m unittest discover -s tests -p "test_checker_foundation.py"`:
  pass.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  pass.
- `python -B scripts\check_wave13_gate.py`: pass.
- `python -B scripts\validate_forcad_config.py`: pass.

## 6. Documentation Updated

- `docs/08_checker_design.md` documents `check_export` and
  `check_network_room`, including the normal API route sequence and secure
  public/redacted side-view use.
- `docs/12_testing_strategy.md` documents disabled-module and private-field
  regression coverage for export and network-room CHECK/HAVOC.

## 7. CTF Invariants Checked

- CHECK/HAVOC uses normal product HTTP APIs only.
- Export and network-room side views are not used to recover flags.
- Disabled export or network-room modules fail CHECK instead of silently
  succeeding.
- Future AML-4/AML-5 fixes should preserve these secure baseline DTOs.

## 8. Security Invariants Checked

- Export bundles reject private note bodies, EDD confidential comments, EDD
  narrative fields, raw audit diffs, hashes, auth/session fields, owner IDs,
  checker-private markers, and flags.
- Network-room summaries and dossiers expose references/public summaries only
  and reject private note/EDD data.
- Sensitive values remain redacted from checker failure messages.

## 9. Self-Review

The T04 checks are deliberately anti-coarse-fix checks: they require the modules
to exist and return secure redacted DTOs, without weakening flag-store privacy
or adding any checker-only bypass path.

## 10. Risks / Open Questions

- Fake-service tests validate checker behavior and response contracts; live
  deployment checks may still need to account for asynchronous room
  materialization timing.
- Later noise/retention checks extend the default dispatcher but do not alter
  the export/network-room contract.

## 11. Ready for Orchestrator Review

Yes.
