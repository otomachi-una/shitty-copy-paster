# Wave 12 W12-T03 Handoff - Place 2 GET Workflow Through Owner EDD APIs

## 1. Summary

W12-T03 implements real place 2 GET behavior through the normal owner EDD read
endpoint. The checker now restores place 2 private state, verifies the
idempotency binding, uses the stored owner token or re-authenticates on
`401`/`403`, reads `GET /api/customers/{customer_id}/edd`, and verifies the
flag in `EDDRecord.confidential_comment`.

## 2. Implementation Details

- Implemented `place2_get`.
- Decodes private state with `expected_place=PLACE_2`.
- Rejects place mismatch, tampering, and wrong flag/idempotency mismatch before
  HTTP access.
- Tries the stored bearer token first.
- Re-authenticates with private-state username/password on `401` or `403`.
- Reads only `GET /api/customers/{customer_id}/edd`.
- Verifies the owner EDD response has matching `id`, matching `customer_id`,
  and `confidential_comment == flag`.
- Maps missing EDD owner view, missing `confidential_comment`, EDD identity
  mismatch, and bad confidential comment value to corrupt.
- Leaves malformed JSON and unexpected non-404 HTTP statuses on the existing
  mumble/down paths.

## 3. Files Changed

- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_get_workflow.py`
- `docs/07_flag_stores.md`
- `docs/08_checker_design.md`
- `docs/wave_reports/wave_12_W12-T03_handoff.md`

## 4. Tests Added

- Successful place 2 GET with stored owner token.
- Successful place 2 GET after re-authentication.
- CLI place 2 GET success output.
- Wrong flag/private-state mismatch fails before HTTP.
- Tampered place 2 private state fails before HTTP.
- Missing EDD owner view is corrupt.
- Missing `confidential_comment` is corrupt.
- Wrong confidential comment value is corrupt.
- EDD `id` or `customer_id` mismatch is corrupt.
- Auth failure does not fall back to side views.
- Bad EDD HTTP status remains mumble and does not leak server error text through
  checker CLI output.
- Place 1 GET remains covered and green.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_*checker*.py"`: passed,
  58 tests.
- `python -B -m py_compile checkers/sentinel_aml/checker.py checkers/sentinel_aml/checker_lib.py`:
  passed.
- `python -B scripts/validate_forcad_config.py`: passed.
- `python -B scripts/check_docs_tree.py`: passed.
- Static checker scan for DB/internal/hidden/side-view route markers: no
  matches.
- `python -B -m unittest discover -s tests -p "test_*.py"`: failed with one
  legacy Wave 11 gate assertion. `tests/test_wave11_gate.py` still expects
  `scripts/check_wave11_gate.py` to report place 2 GET parsing as unsupported;
  Wave 12 intentionally supports place 2 dispatch and GET.
- Go gates were not run because no Go files were touched.

## 6. Documentation Updated

- `docs/08_checker_design.md` now documents the concrete place 2 GET owner EDD
  sequence, exact verification rule, re-authentication behavior, and side-view
  exclusions.
- `docs/07_flag_stores.md` now marks place 2 PUT/GET as active through owner
  EDD APIs and records the `id`, `customer_id`, and
  `confidential_comment == flag` verification rule.

## 7. CTF Invariants Checked

- Checker GET uses owner EDD view only.
- GET restores credentials and object IDs from private `flag_id`, not public
  attack data.
- No graph, audit, export, network-room, dedup, debug, admin, or DB path was
  added.
- Place 1 GET remains green.
- Future AML-3/AML-4/AML-5 secure fixes should not break this owner EDD path.

## 8. Security Invariants Checked

- `confidential_comment` is observed only through the owner EDD response.
- Wrong flag and tampered state fail before HTTP when possible.
- Auth failure does not trigger side-view fallback.
- CLI error output does not include raw flag or private state in covered error
  paths.
- Checker source has no side-view endpoint markers.

## 9. Self-Review

The implementation mirrors the accepted place 1 GET model while keeping place 2
strictly on the owner EDD API. The tests use an in-memory fake HTTP service that
records all requests and would fail if the checker tried side-view routes.
Behavior remains testable without a live service.

## 10. Risks / Open Questions

- A Wave 12 gate or orchestrator-approved update to the legacy Wave 11 gate is
  needed before full `test_*.py` discovery can pass after place 2 activation.
- W12-T04 should add/update static Wave 12 guardrails for both place 2 PUT and
  GET so the stale Wave 11 expectation is no longer the current-branch gate.

## 11. Ready for Orchestrator Review

No. The W12-T03 scoped checker behavior passes, but full-suite discovery remains
blocked by the legacy Wave 11 gate assertion that place 2 GET parsing must fail.
