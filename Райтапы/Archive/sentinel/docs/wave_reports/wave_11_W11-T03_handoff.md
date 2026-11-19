# Wave 11 W11-T03 Handoff - Place 1 GET Workflow Through Owner Case-Note View

## 1. Summary

Implemented and tested place 1 GET verification through the owner case-note
view. GET decodes and verifies the private state, uses the original
checker-created owner token or re-authenticates with private-state credentials,
calls only `GET /api/cases/{case_id}/notes`, and verifies the expected flag by
exact note ID, case ID, and body match.

## 2. Implementation Details

- Preserved W11-T01 private state decoding and HMAC tamper validation.
- Preserved token-first GET with owner login fallback on `401` or `403`.
- Mapped missing owner case/note view (`404`) to corrupt.
- Kept wrong flag/private-state mismatch fail-closed before HTTP.
- Kept exact note verification: `note.id == note_id`, `note.case_id == case_id`,
  and `note.body == flag`.
- Stopped HTTP status exception messages from including server-provided error
  text, preventing raw flag/private-state echo through checker stderr.
- Added fake HTTP tests proving side-view endpoints are not called.

## 3. Files Changed

- `checkers/sentinel_aml/checker_lib.py`
- `tests/test_checker_get_workflow.py`
- `docs/08_checker_design.md`
- `docs/07_flag_stores.md`
- `docs/wave_reports/wave_11_W11-T03_handoff.md`

## 4. Tests Added

- Successful GET with stale token, owner login fallback, and retry against
  owner notes.
- Successful GET using stored owner token.
- Wrong flag detected before HTTP.
- Tampered private state rejected before HTTP.
- Note body mismatch returns corrupt.
- Missing case/note owner view returns corrupt.
- Missing expected note returns corrupt.
- Auth failure after retry fails without side-view reads.
- Checker stderr does not leak raw flag or private state on HTTP error.
- Place 2 GET remains deferred/fail-closed.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_*checker*.py"` - pass, 24 tests.
- `python -B -m unittest discover -s tests -p "test_*.py"` - pass, 112 tests.
- `python -B scripts/validate_forcad_config.py` - pass.
- Checker-source invariant scan for direct DB/internal/debug/admin/checker-route
  and side-view endpoint markers - pass.

Go gates were not run because no Go product APIs, migrations, authorization
logic, or Go internals were modified.

## 6. Documentation Updated

- `docs/08_checker_design.md` now documents place 1 GET owner-note-only behavior,
  exact verification, forbidden side-view reads, and failure mapping.
- `docs/07_flag_stores.md` now documents owner note GET as the only place 1 flag
  read path and explicitly excludes dedup/audit/graph/export/network-room side
  views.

## 7. CTF Invariants Checked

- GET uses owner-view only.
- GET does not use public attack data as credential state.
- GET does not use dedup, audit, graph, export, network-room, merge-preview, or
  other side views to retrieve flags.
- Place 2 and HAVOC remain deferred.
- Future AML-1 through AML-5 fixes should not break owner case-note GET.

## 8. Security Invariants Checked

- Checker errors do not intentionally include raw flags or private checker state.
- Tampered private state is rejected before any HTTP request.
- Wrong flag/private-state mismatch is rejected before any HTTP request.
- Cross-owner failures remain fail-closed because GET only uses owner credentials
  from private state against owner-scoped case-note APIs.

## 9. Self-Review

The change is scoped to checker code, checker tests, and docs. It does not touch
product Go code, migrations, authorization logic, vulnerabilities, exploits,
reference fixes, debug/admin endpoints, side-view APIs, place 2 implementation,
or `config.yml`.

## 10. Risks / Open Questions

- Live-service GET was not run in this packet; fake HTTP tests exercise the
  checker behavior and failure classes.
- The checker relies on the product owner note endpoint preserving exact private
  `CaseNote.body` visibility for the original owner.

## 11. Ready for Orchestrator Review

Yes.
