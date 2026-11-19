# Wave 12 W12-T02 Handoff - Place 2 PUT Workflow Through Owner EDD APIs

## 1. Summary

W12-T02 implements real place 2 PUT behavior through normal owner-authenticated
HTTP APIs. The checker now stores place 2 flags only in
`EDDRecord.confidential_comment` by creating a checker-owned customer and EDD
record, then returns MAC-protected private state plus credential-free and
flag-free public attack data.

## 2. Implementation Details

- Implemented `place2_put`.
- Reused the normal auth flow: register deterministic checker analyst, then
  login.
- Created deterministic place 2 customer fixture values from the HMAC
  idempotency key.
- Created the checker-owned customer through `POST /api/customers`.
- Created the EDD record through `POST /api/customers/{customer_id}/edd`.
- Sent the raw flag only as the `confidential_comment` field in the owner EDD
  create request.
- Required customer `id` and `entity_hint` from the customer response.
- Required EDD `id` and matching `customer_id` from the EDD response.
- Built `Place2PrivateState` with owner credentials/token recovery data,
  `customer_id`, `edd_record_id`, `entity_hint`, `typology_hint`, and
  idempotency key.
- Built place 2 public attack data with only `service`, public `store` label,
  `customer_id`, `entity_hint`, and `typology_hint`.
- Kept the public `store` value as `EDDRecord` so public attack data does not
  include the literal `confidential_comment` field name.

## 3. Files Changed

- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_foundation.py`
- `tests/test_checker_put_workflow.py`
- `docs/01_ctf_contract.md`
- `docs/07_flag_stores.md`
- `docs/08_checker_design.md`
- `docs/wave_reports/wave_12_W12-T02_handoff.md`

## 4. Tests Added

- Successful place 2 PUT route sequence.
- Place 2 checker CLI PUT PFR output shape.
- Raw flag appears only in the EDD confidential-comment request payload.
- Place 2 public attack data excludes flag, username, password, token, checker
  secret, session, private state, and `confidential_comment`.
- Missing customer `entity_hint` returns checker mumble.
- Missing EDD `id` returns checker mumble.
- EDD response `customer_id` mismatch returns checker mumble.
- Failed EDD HTTP status returns checker failure.
- Place 1 PUT route sequence remains covered and green.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_*checker*.py"`: passed,
  47 tests.
- `python -B scripts/validate_forcad_config.py`: passed.
- `python -B scripts/check_docs_tree.py`: passed.
- Static checker scan for DB/internal/hidden endpoint markers: no matches.
- `python -B -m unittest discover -s tests -p "test_*.py"`: failed with one
  legacy Wave 11 gate assertion. `tests/test_wave11_gate.py` still expects
  `scripts/check_wave11_gate.py` to report place 2 GET parsing as unsupported;
  Wave 12 intentionally supports place 2 dispatch.
- Go gates were not run because no Go files were touched.

## 6. Documentation Updated

- `docs/08_checker_design.md` now documents the concrete place 2 PUT route
  sequence and the W12-T03 GET deferral.
- `docs/07_flag_stores.md` now documents the place 2 public/private split and
  public `EDDRecord` store label.
- `docs/01_ctf_contract.md` now clarifies that place 2 public attack data must
  not contain `confidential_comment`.

## 7. CTF Invariants Checked

- Checker writes place 2 flags through normal owner business APIs only.
- No hidden endpoint, debug route, admin route, public attack-data route, or
  direct database path was added.
- Public attack data contains future locator hints only: `customer_id`,
  `entity_hint`, and `typology_hint`.
- Public attack data contains no credentials, token, session, raw flag, checker
  secret, private state, or `confidential_comment`.
- Place 1 PUT remains unchanged and covered by tests.

## 8. Security Invariants Checked

- Raw flag appears only in the owner EDD create payload field
  `confidential_comment`.
- Raw flag is absent from auth and customer setup requests.
- Raw flag, credentials, bearer token, checker secret, session marker, private
  state, and `confidential_comment` are absent from place 2 public attack data
  by test.
- Checker source still has no direct DB, Go/internal, hidden, debug, admin, or
  checker-only route marker.

## 9. Self-Review

The implementation stays within checker and docs scope. It uses the existing
standard-library HTTP client and the product's owner EDD API. Response
validation fails closed when IDs or required hints are missing. The only suite
blocker is a historical Wave 11 gate expectation that has not yet been advanced
for Wave 12.

## 10. Risks / Open Questions

- W12-T03 still needs to implement place 2 GET through
  `GET /api/customers/{customer_id}/edd`.
- A Wave 12 gate or orchestrator-approved update to the legacy Wave 11 gate is
  needed before the full `test_*.py` discovery command can pass with place 2
  active.

## 11. Ready for Orchestrator Review

No. The W12-T02 scoped checker behavior passes, but full-suite discovery is
still blocked by the legacy Wave 11 gate assertion that place 2 GET parsing must
fail.
