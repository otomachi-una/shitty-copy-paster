# Wave 12 Review - AD-C0 Formal Close

## Status

accepted

## Summary

AD-C0 reviewed the active two-place checker contract for Sentinel AML. Place 1
and place 2 are both active through normal owner-authenticated product APIs.
The checker remains PFR-compatible, keeps public attack data locator-only, and
stores recovery credentials/state only in MAC-protected private `flag_id`
envelopes.

Wave 13 can start without checker flag-store ambiguity. CHECK/HAVOC, planned
vulnerabilities, reference exploits, and reference fixes remain out of scope for
this close.

## Gates Run

- `python -B scripts/check_wave12_gate.py`: pass.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: pass.
- `python -B scripts/validate_forcad_config.py`: pass.
- `python -B scripts/check_docs_tree.py`: pass.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: pass with
  workspace-local Go cache/appdata settings on this Windows host.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: pass with the same
  workspace-local environment.

## Evidence for Place 1

- PUT writes the raw flag only to `POST /api/cases/{case_id}/notes` as private
  note body content.
- GET reads only `GET /api/cases/{case_id}/notes` as the checker-created owner.
- Tests cover the full PUT route sequence, owner-token/re-auth GET behavior,
  wrong flag rejection, tamper rejection, missing note/case handling, and
  side-view non-use.

## Evidence for Place 2

- PUT writes the raw flag only to `POST /api/customers/{customer_id}/edd` as
  `confidential_comment`.
- GET reads only `GET /api/customers/{customer_id}/edd` as the checker-created
  owner.
- Tests cover the full PUT route sequence, owner-token/re-auth GET behavior,
  wrong flag rejection, tamper rejection, missing EDD/comment handling, identity
  mismatch handling, and side-view non-use.

## Public/Private Split Evidence

- Place 1 public attack data contains only `service`, `store`, `case_id`,
  `customer_id`, `dedup_hint`, and `typology_hint`.
- Place 2 public attack data contains only `service`, `store`, `customer_id`,
  `entity_hint`, and `typology_hint`.
- Public attack data is tested and gated against usernames, passwords, bearer
  tokens, sessions, raw flags, checker secrets, private state, and
  `confidential_comment`.
- Private `flag_id` state contains owner recovery data and object IDs inside a
  canonical JSON envelope protected by HMAC-SHA256 with the checker secret.

## Remaining Gaps

- No AD-C0 checker flag-store gaps remain.
- Non-blocking local caveat: `make wave12-gate` cannot run on this host because
  no `make`, `mingw32-make`, or `gmake` executable is installed. The target
  exists and its component commands were run directly.
- Non-blocking historical caveat: full all-test discovery still includes a
  Wave 11 gate test that expects place 2 to fail. Wave 12 intentionally
  activates place 2, so `scripts/check_wave12_gate.py` is the current branch
  authority.
- Wave 13 still owns strong CHECK/HAVOC, noise, restart, retention, and live
  checker integration.

## Ready for Orchestrator Review

yes
