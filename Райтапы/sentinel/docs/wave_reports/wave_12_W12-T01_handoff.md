# Wave 12 W12-T01 Handoff - Place 2 State Contract and Checker Dispatch

## 1. Summary

W12-T01 extends the checker contract from Wave 11 place 1 to Wave 12 place 2.
Place 1 `CaseNote.body` behavior and public/private state shape remain
unchanged. Place 2 now has explicit checker dispatch, a typed private state
schema for `EDDRecord.confidential_comment`, place-aware decode validation, and
credential-free public attack data.

## 2. Implementation Details

- Added `Place2PrivateState` with schema version, service, store, place, owner
  username/password/token recovery data, `customer_id`, `edd_record_id`,
  `entity_hint`, `typology_hint`, and idempotency key.
- Generalized private-state encode/decode to accept place 1 and place 2
  dataclasses while preserving HMAC-SHA256 MAC protection over canonical JSON.
- Added expected-place validation so place 1 state cannot be used for place 2
  and place 2 state cannot be used for place 1.
- Added place/store mismatch, malformed schema, missing-field, and tamper
  rejection for both state families.
- Added place 2 public attack data with only `service`, `store`,
  `customer_id`, `entity_hint`, and `typology_hint`.
- Added shared `public_attack_data_for_state` dispatch and reused the shared
  public-data safety assertion for both places.
- Updated checker argument parsing so place 2 is a supported dispatch place and
  unknown places remain fail-closed.
- Updated the CLI entrypoint to dispatch place 1 and place 2 PUT/GET by parsed
  place. Place 2 HTTP workflows remain pending W12-T02 and W12-T03 and fail
  with checker mumble until those tasks implement the normal owner EDD API
  lifecycle.
- Added EDD HTTP helper methods for normal owner endpoints without adding any
  hidden, debug, admin, side-view, database, or repository path.

## 3. Files Changed

- `checkers/sentinel_aml/checker.py`
- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_foundation.py`
- `tests/test_checker_put_workflow.py`
- `tests/test_checker_get_workflow.py`
- `docs/01_ctf_contract.md`
- `docs/07_flag_stores.md`
- `docs/08_checker_design.md`
- `docs/open_questions.md`
- `docs/wave_reports/wave_12_W12-T01_handoff.md`

## 4. Tests Added

- Place 2 private state encode/decode round trip.
- Place 2 private state tamper rejection.
- Place/store mismatch rejection.
- Place 1 state passed to place 2 rejection.
- Place 2 state passed to place 1 rejection.
- Malformed place 2 state rejection.
- Public attack-data exclusion checks for both places.
- Shared public attack-data builder checks for both places.
- Explicit place 2 argument dispatch checks.
- Unknown place fail-closed checks.
- Place 2 GET wrong-flag check before HTTP.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_*checker*.py"`: passed,
  39 tests.
- `python -B scripts/validate_forcad_config.py`: passed.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B -m unittest discover -s tests -p "test_*.py"`: failed with one
  legacy Wave 11 gate assertion. `tests/test_wave11_gate.py` still expects
  `scripts/check_wave11_gate.py` to report place 2 GET parsing as unsupported;
  W12-T01 intentionally changes place 2 to a supported dispatch place. The
  prior Wave 11 gate files were not modified because they are outside the
  W12-T01 file scope.
- Go gates were not run because no Go files were touched.

## 6. Documentation Updated

- `docs/01_ctf_contract.md` now marks place 2 as a Wave 12 checker
  state/dispatch contract for `EDDRecord.confidential_comment`.
- `docs/07_flag_stores.md` now documents the place 2 private/public state split
  and keeps the historical Wave 11 deferral note.
- `docs/08_checker_design.md` now documents place 2 dispatch, owner EDD API
  boundaries, the place 2 private state envelope, public attack data, and
  side-view exclusions.
- `docs/open_questions.md` resolves the previous place 2 state/public-data
  contract question and leaves the concrete HTTP workflows to W12-T02/W12-T03.

## 7. CTF Invariants Checked

- PFR split remains: private checker state is separate from public attack data.
- Public attack data is locator/hint-only and contains no credentials or flags.
- Checker source has no direct DB or Go/internal dependency.
- No hidden debug/admin helper was added.
- No planned vulnerability, exploit, or reference-fix behavior was added.
- Place 1 maps to `CaseNote.body` and remains active.
- Place 2 maps to `EDDRecord.confidential_comment`.

## 8. Security Invariants Checked

- `EDDRecord.confidential_comment` remains private owner data.
- Place 2 state is HMAC protected and tamper detecting.
- Place/store mismatch and cross-place private state use fail before HTTP.
- Place 2 GET stub performs only state/idempotency validation and does not call
  graph, audit, export, network-room, dedup, or side-view endpoints.
- Checker errors do not intentionally print raw flags or private state.

## 9. Self-Review

The implementation is scoped to checker contract code, checker tests, and
documentation. It preserves place 1 behavior while making place 2 explicit and
testable without a live service. The main unresolved tension is that the full
historical test suite still includes a Wave 11 gate whose current-branch
assertion is intentionally incompatible with Wave 12 activation of place 2.

## 10. Risks / Open Questions

- W12-T02 must implement the real place 2 PUT workflow through normal owner EDD
  APIs.
- W12-T03 must implement the real place 2 GET workflow through the owner EDD
  view only.
- A Wave 12 gate or an orchestrator-approved update to the legacy Wave 11 gate
  will be needed before `python -B -m unittest discover -s tests -p "test_*.py"`
  can pass after place 2 activation.

## 11. Ready for Orchestrator Review

No. The W12-T01 scoped checker tests and config validation pass, but the full
requested Python suite has one expected legacy Wave 11 gate failure that cannot
be corrected inside the W12-T01 file scope.
