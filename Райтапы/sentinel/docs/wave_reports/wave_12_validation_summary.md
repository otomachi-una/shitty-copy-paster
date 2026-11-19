# Wave 12 Validation Summary

## Summary

Wave 12 activates the second checker flag store for Sentinel AML. Place 1
continues to store and verify flags through the owner case-note path in
`CaseNote.body`. Place 2 now stores and verifies flags through the owner EDD
path in `EDDRecord.confidential_comment`.

Wave 11 is complete. Wave 12 is implemented and awaiting orchestrator review.
CHECK/HAVOC remains Wave 13. Planned vulnerability, exploit, and reference-fix
waves remain locked.

## Scope Validated

- Place 1 PUT/GET remains active through normal case-note APIs.
- Place 2 PUT creates checker-owned customer/EDD data through normal owner EDD
  APIs and sends the raw flag only as `confidential_comment`.
- Place 2 GET reads only `GET /api/customers/{customer_id}/edd` as the original
  checker-created owner.
- Private checker state for both places is MACed and place-aware.
- Public attack data for both places is credential-free and flag-free.
- Cross-place private-state confusion is rejected.
- Checker source remains HTTP-only with no direct DB/internal dependency.
- Side-view routes are not checker GET paths.

## Commands and Results

- `make wave12-gate`: attempted and failed because `make` is not installed in
  this Windows PowerShell environment. `make`, `mingw32-make`, and `gmake` are
  absent from PATH.
- `python -B -m unittest discover -s tests -p "test_*checker*.py"`: passed, 58
  tests.
- `python -B -m unittest discover -s tests -p "test_wave12_gate.py"`: passed,
  8 tests.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: passed with
  command-local `GOTELEMETRY=off`, `GOCACHE`, and `APPDATA` pointed into the
  workspace for this Windows host.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: passed with the same
  command-local environment.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/check_wave12_gate.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.
- Additional sanity run, `python -B -m unittest discover -s tests -p "test_*.py"`:
  failed with 1 failure after 161 tests. The failure is the historical Wave 11
  gate test expecting place 2 parsing to fail; Wave 12 intentionally activates
  place 2 PUT/GET.

The `make wave12-gate` target exists, and every command inside that target was
run directly and passed. The local failure is the missing `make` executable, not
a failing Wave 12 gate component.

## Wave 12 Gate Authority

Current branch validation authority lives in `scripts/check_wave12_gate.py` and
this validation summary. Earlier wave gates remain historical branch gates and
may reject intentional later-wave expansions.

`scripts/check_wave12_gate.py` validates place 2 activation, place 1
preservation, public/private PFR separation, cross-place state rejection,
owner-view-only GET paths, absence of direct DB/internal checker dependencies,
absence of hidden endpoints, absence of exploit/fix scripts, Wave 12 handoff
presence, testing-strategy status, Makefile target presence, and ForcAD config
validity.

## CTF Invariants

- Checker uses normal product APIs only.
- Public attack data contains no credentials, tokens, sessions, raw flags,
  checker secrets, or private checker state.
- Private checker state is separate from public attack data.
- No direct database checker dependency exists.
- No hidden debug/admin shortcut exists.
- Both owner GET paths remain stable for future fixes.
- No planned vulnerability, exploit, or reference-fix behavior is active.

## Security Invariants

- Place 1 raw flags are sent only to the private case-note creation API.
- Place 2 raw flags are sent only to the owner EDD confidential comment API.
- GET does not use dedup, audit, graph, export, network-room, merge-preview, or
  other side-view endpoints.
- Documentation examples use placeholders and do not include reusable secrets,
  tokens, raw private state, or real-looking flags.
- Checker errors must avoid raw flags, credentials, tokens, and private state.

## Known Gaps

- The host lacks a `make` executable, so `make wave12-gate` cannot be executed
  end to end here even though its component commands pass directly.
- Full `python -B -m unittest discover -s tests -p "test_*.py"` includes a
  historical Wave 11 gate test that expects place 2 parsing to fail. Wave 12
  intentionally activates place 2, so the current branch authority is
  `scripts/check_wave12_gate.py`.
- Live competition checker integration, restart behavior, retention windows,
  and CHECK/HAVOC/noise remain Wave 13 work.

## Ready for Orchestrator Review

yes, with the local `make` executable caveat above.
