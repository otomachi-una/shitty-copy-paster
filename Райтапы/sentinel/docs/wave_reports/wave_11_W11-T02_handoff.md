# Wave 11 W11-T02 Handoff - Place 1 PUT Workflow Through Normal Case-Note APIs

## 1. Summary

Implemented and tested the place 1 checker PUT workflow against a fake HTTP
Sentinel AML service. PUT creates a normal investigation through business APIs,
stores the flag only as private `CaseNote.body`, and returns the W11-T01 PFR
private state plus credential-free public attack data.

## 2. Implementation Details

- Tightened PUT authentication to perform `POST /api/auth/register` followed by
  `POST /api/auth/login`.
- Kept deterministic analyst/customer/account/transaction/case setup data
  derived from the checker idempotency key.
- Exercised the full normal API sequence:
  register, login, create customer, create account, create suspicious
  transaction, read alert queue, claim alert, create case, create private note.
- Validated expected response IDs and alert fields before continuing to later
  steps.
- Preserved place mismatch rejection for place 2 and unknown places before any
  place-specific HTTP work.
- Preserved W11-T01 PFR state split: MACed private state and public attack data
  with only object locators and hints.

## 3. Files Changed

- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_put_workflow.py`
- `docs/08_checker_design.md`
- `docs/07_flag_stores.md`
- `docs/wave_reports/wave_11_W11-T02_handoff.md`

## 4. Tests Added

- Full successful PUT route sequence against an in-memory fake HTTP service.
- Assertion that the raw flag appears only in `POST /api/cases/{case_id}/notes`.
- Public attack-data exclusion of flag, credentials, token, checker secret, and
  private state.
- Private state contains future GET recovery data while staying out of public
  attack data.
- Missing intermediate ID returns checker failure.
- Failed intermediate HTTP response returns checker failure.
- Place 2 PUT remains deferred/fail-closed.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_*checker*.py"` - pass, 14 tests.
- `python -B -m unittest discover -s tests -p "test_*.py"` - pass, 102 tests.
- `python -B scripts/validate_forcad_config.py` - pass.
- Checker-source invariant scan for direct DB/internal/debug/admin/checker-route
  markers - pass.

Go gates were not run because no Go product APIs, migrations, authorization
logic, or Go internals were modified.

## 6. Documentation Updated

- `docs/08_checker_design.md` now documents the concrete place 1 PUT route
  sequence and the rule that raw flag material is sent only to the private
  case-note creation endpoint.
- `docs/07_flag_stores.md` now records the implemented PUT investigation setup
  path and explicit public-data exclusions.

## 7. CTF Invariants Checked

- Checker PUT uses normal HTTP business APIs only.
- No hidden endpoint or direct database path was introduced.
- Public attack data contains enough non-secret business object locators and
  hints for future exploit work.
- No exploit script, vulnerability, HAVOC, reference fix, or place 2 GET was
  implemented.
- Owner case-note GET path remains the future correctness path.

## 8. Security Invariants Checked

- Raw flag is sent only to `POST /api/cases/{case_id}/notes` as private business
  content, verified by fake-server request capture.
- Raw flag is absent from public attack data by test.
- Credentials and bearer token are absent from public attack data by test.
- Private checker state is not embedded in public attack data by test.
- Error paths do not intentionally print raw flag or private state.

## 9. Self-Review

The change stays inside checker, checker tests, and docs. Product Go code,
migrations, authorization logic, vulnerability behavior, exploit scripts,
reference fixes, debug/admin endpoints, and `config.yml` were not changed.
The fake service proves the PUT workflow without requiring a live deployment.

## 10. Risks / Open Questions

- Live-service PUT was not run as part of this packet; the acceptance target was
  fake HTTP service exercise plus unit coverage.
- The checker still depends on the product's deterministic risk service creating
  an alert for the high-value transaction.
- Repeated PUT for an already-created deterministic customer may receive product
  duplicate conflicts; private state from the successful PUT remains the
  supported GET recovery path.

## 11. Ready for Orchestrator Review

Yes.
