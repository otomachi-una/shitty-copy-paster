# Wave 13 W13-T03 Handoff - Audit and Graph CHECK/HAVOC

## 1. Summary

Implemented and validated `check_audit` and `check_graph` for the Wave 13
CHECK/HAVOC framework. Both subchecks exercise normal HTTP APIs, require the
secure side-view modules to remain available, and reject private flag-store
material in audit timeline and graph DTO responses.

## 2. Implementation Details

- `check_audit` creates an owned case, writes a non-secret private case note,
  reads the owner case timeline, verifies a case-note event exists, and requires
  redacted diff metadata for sensitive changes.
- `check_graph` creates two owned investigations for customers sharing an
  `entity_hint`, reads the graph entity summary and related-case list, and
  verifies relation/count fields plus public case metadata.
- Audit DTO validation allows only public event metadata and redaction markers.
- Graph DTO validation allows only public graph summary and related-case
  fields; confidential EDD fields, note bodies, owner/auth/session data, and
  checker-private markers are rejected.
- Place 1 and place 2 PUT/GET behavior was not changed.

## 3. Files Changed

- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_check_workflow.py`
- `docs/08_checker_design.md`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_13_W13-T03_handoff.md`

## 4. Tests Added

- Audit timeline contains a case-note event but not the raw note body.
- Audit timeline leakage of private note content is rejected.
- Missing audit timeline support fails CHECK.
- Missing audit note event fails CHECK.
- Graph response tests assert relation type, customer/case counts, related-case
  presence, and absence of private note/EDD fields.
- Graph private-field leakage is rejected.
- Missing graph support fails CHECK.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_checker_check_workflow.py"`:
  pass, 31 tests.
- `python -B -m unittest discover -s tests -p "test_checker_foundation.py"`:
  pass.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  pass.
- `python -B scripts\check_wave13_gate.py`: pass.
- `python -B scripts\validate_forcad_config.py`: pass.

## 6. Documentation Updated

- `docs/08_checker_design.md` documents `check_audit` and `check_graph` and
  states that side views are allowed only as secure public/redacted CHECK
  surfaces, never as flag recovery paths.
- `docs/12_testing_strategy.md` documents the audit/graph CHECK matrix and
  disabled-module/private-field failure expectations.

## 7. CTF Invariants Checked

- CHECK/HAVOC uses normal HTTP APIs only.
- Audit and graph side views are not used to recover flags.
- Missing audit or graph modules fail CHECK instead of silently succeeding.
- Future AML-2/AML-3 fixes should preserve these secure baseline DTOs.

## 8. Security Invariants Checked

- Raw note bodies and EDD confidential comments are rejected in audit/graph
  public side-view responses.
- Auth/session/owner/checker-private markers remain excluded from graph DTOs.
- Sensitive values remain redacted from checker failure messages.

## 9. Self-Review

The T03 checks validate module availability and secure DTO shape without
loosening the owner-only flag-store contract. The fake-service tests now inspect
actual graph response payloads rather than only route usage.

## 10. Risks / Open Questions

- Fake-service tests prove checker behavior and expected contracts; live
  deployment timing or async projection lag remains an integration concern.
- Later Wave 13 export/network/noise checks extend the same framework but do
  not change the audit/graph contract.

## 11. Ready for Orchestrator Review

Yes.
