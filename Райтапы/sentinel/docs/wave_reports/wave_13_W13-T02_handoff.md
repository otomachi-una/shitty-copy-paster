# Wave 13 W13-T02 Handoff - Basic, Dedup, and Notes CHECK/HAVOC

## 1. Summary

Implemented and validated the first business-function CHECK/HAVOC subchecks:
`check_basic`, `check_case_notes`, and `check_dedup`. These subchecks exercise
normal owner HTTP APIs and fail closed when the corresponding customer/account/
transaction, case-note, or dedup surfaces are unavailable or return unsafe data.

## 2. Implementation Details

- `check_basic` registers or logs in a deterministic checker analyst, creates a
  customer, creates an account, creates a transaction, and reads the created
  customer/account/transaction data back.
- `check_case_notes` creates an owned alert/case workflow, writes a non-secret
  private note, and verifies owner note readback.
- `check_dedup` creates an owned duplicate pair with the same `dedup_hint`,
  verifies the expected duplicate candidate, and checks merge-preview public
  fields only.
- Dedup presenter validation rejects private note bodies, EDD confidential
  comments, audit/diff data, owner identifiers, auth/session fields, flags, and
  checker-private markers.
- Place 1 and place 2 PUT/GET behavior was not changed.

## 3. Files Changed

- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_check_workflow.py`
- `docs/08_checker_design.md`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_13_W13-T02_handoff.md`

## 4. Tests Added

- Happy-path route-order coverage for `check_basic`, `check_case_notes`, and
  `check_dedup`.
- Explicit missing case-note API fail-closed coverage.
- Existing dedup negative tests cover missing duplicate candidates and private
  merge-preview leakage.
- Existing case-note tests prove CHECK does not read foreign case-note bodies or
  write flag-looking content.

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

- `docs/08_checker_design.md` documents the Wave 13 business subchecks and the
  normal API paths they cover.
- `docs/12_testing_strategy.md` documents route-order, disabled-module, and
  public-only merge-preview expectations.

## 7. CTF Invariants Checked

- CHECK/HAVOC uses normal HTTP APIs only.
- CHECK/HAVOC does not use database access or checker-only endpoints.
- CHECK/HAVOC does not recover flags from place 1 or place 2.
- Disabling customer/account/transaction, notes, or dedup behavior causes CHECK
  failure instead of silent success.

## 8. Security Invariants Checked

- `check_case_notes` uses a non-secret note body and owner note readback only.
- Dedup and merge-preview responses are validated as public-only DTOs.
- Sensitive values are redacted from checker failure messages.
- Public/private checker state and flag-store GET semantics remain unchanged.

## 9. Self-Review

The W13-T02 subchecks are deterministic and scoped to business availability and
secure DTO shape. The tests now pin the expected route progression for the
basic/notes/dedup trio and explicitly fail closed on a missing note API.

## 10. Risks / Open Questions

- The fake service validates checker behavior without a live deployment; live
  integration remains a Wave 13 operational gate.
- Later Wave 13 subchecks expand the default dispatcher beyond the W13-T02
  trio, but do not change these subcheck contracts.

## 11. Ready for Orchestrator Review

Yes.
