# Wave 11 W11-T01 Handoff - Checker Contract, HTTP Client, and Safe State Schemas

## 1. Summary

Implemented the Sentinel AML Wave 11 checker foundation for place 1 PUT/GET.
Place 1 stores flags in `CaseNote.body` through normal owner-authenticated HTTP
business APIs. Place 2 remains explicit fail-closed/deferred behavior.

## 2. Implementation Details

- Added explicit `check`, `put`, and `get` action parsing.
- Added fail-closed parsing for malformed actions, malformed place values,
  place 2, and unknown places before place-specific HTTP work starts.
- Added a standard-library HTTP client wrapper with deterministic default
  per-request timeout, JSON encoding/decoding, bearer-token support, health,
  auth, customer, account, transaction, alert, case, and case-note helpers.
- Added place 1 private state as a base64url JSON envelope with canonical
  payload JSON and HMAC-SHA256 MAC.
- Added place 1 public attack-data generation with only `service`, `store`,
  `case_id`, `customer_id`, `dedup_hint`, and `typology_hint`.
- Added deterministic idempotency helper:
  `HMAC_SHA256(checker_secret, flag + "\x00" + place + "\x00" + service_name)`.
- Kept checker implementation standard-library only.

## 3. Files Changed

- `checkers/sentinel_aml/checker.py`
- `checkers/sentinel_aml/checker_lib.py`
- `checkers/sentinel_aml/requirements.txt`
- `tests/test_checker_foundation.py`
- `docs/01_ctf_contract.md`
- `docs/07_flag_stores.md`
- `docs/08_checker_design.md`
- `docs/open_questions.md`
- `docs/wave_reports/wave_11_W11-T01_handoff.md`

## 4. Tests Added

- Private state encode/decode round trip.
- Private state tamper rejection.
- Public attack data credential/private-material exclusion.
- Unsupported place 2 and unknown place fail-closed behavior.
- Idempotency key formula check.
- Checker import/source guard for direct DB or Go-internal dependencies.
- Deterministic timeout and URL defaults.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_checker_foundation.py"` - pass, 7 tests.
- `python -B -m unittest discover -s tests -p "test_*.py"` - pass, 95 tests.
- `python -B scripts/validate_forcad_config.py` - pass.

Go gates were not run because no Go product APIs, migrations, authorization
logic, or Go internals were modified.

## 6. Documentation Updated

- `docs/08_checker_design.md` now documents actions, place 1 flow, private
  state envelope, public attack data, and idempotency.
- `docs/01_ctf_contract.md` now documents the Wave 11 PFR split and correct
  task-list `config.yml` shape.
- `docs/07_flag_stores.md` now marks place 1 active and place 2 deferred.
- `docs/open_questions.md` now records place 1 checker state and public
  attack-data schema as resolved in W11-T01.

No ADR was added because prior docs did not define a conflicting concrete
private `flag_id` format.

## 7. CTF Invariants Checked

- No public credentials.
- No direct DB checker path.
- No hidden debug/admin helpers.
- No exploit or reference-fix behavior.
- Place 2 remains deferred and fail-closed.
- `CaseNote.body` remains a normal private business field accessed through
  product APIs.

## 8. Security Invariants Checked

- Public attack data excludes usernames, passwords, tokens, sessions, raw flags,
  checker secrets, and private state by test.
- Private state is integrity-protected and rejects tampering by test.
- Checker errors avoid printing raw flags or private state.
- Checker source scan found no direct DB/Go-internal dependency markers and no
  checker/attack-data product endpoints.

## 9. Self-Review

The implementation is scoped to the checker foundation and docs. It introduces
no product API changes, migrations, exploit scripts, vulnerability behavior, or
reference fixes. The place 1 flow uses existing owner APIs only. The helper layer
is testable without a live service, while runtime PUT/GET can operate against a
live Sentinel AML API.

## 10. Risks / Open Questions

- The product API has no owner lookup by deterministic customer registration,
  so repeated PUT recovery without the previously returned private state is not
  attempted.
- The checker secret falls back to a deterministic development value for local
  tests; deployment should set `SENTINEL_AML_CHECKER_SECRET`.
- Full live-service PUT/GET was not run in this task because the acceptance
  target was foundation behavior testable without a live service.

## 11. Ready for Orchestrator Review

Yes.
