# Wave 11 Validation Summary

## Summary

Wave 11 adds the first real checker behavior for Sentinel AML. Place 1 PUT/GET
stores and verifies flags through normal owner-authenticated case-note APIs in
`CaseNote.body`. The current branch authority is `scripts/check_wave11_gate.py`
plus `make wave11-gate`. Wave 10 is complete; Wave 11 remains `needs fixes`
until W11-T01, W11-T02, W11-T03, W11-T04, and W11-T05 pass orchestrator review.

Place 2 remains Wave 12. CHECK/HAVOC remains Wave 13. Planned vulnerability
waves remain locked.

## Scope Validated

- Checker action parsing supports `check`, `put`, and `get`.
- Place 1 PUT creates normal business objects through HTTP only:
  register, login, customer, account, suspicious transaction, alert queue, alert
  claim, case create, and private case-note create.
- Place 1 GET verifies flags only through `GET /api/cases/{case_id}/notes` as
  the original owner, using the stored token or owner re-authentication.
- Private checker state is a MACed checker-only envelope.
- Public attack data contains only `service`, `store`, `case_id`,
  `customer_id`, `dedup_hint`, and `typology_hint`.
- Public attack data is credential-free and flag-free.
- Place 2 remains deferred/fail-closed.
- HAVOC, vulnerabilities, exploits, reference fixes, public attack-data product
  routes, checker product routes, debug/admin shortcuts, and direct DB checker
  paths remain out of scope.

## Tests and Gates

Wave 11 validation expects these commands:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B -m unittest discover -s tests -p 'test_*.py'
python -B scripts/check_docs_tree.py
python -B scripts/check_wave11_gate.py
python -B scripts/validate_forcad_config.py
make wave11-gate
```

Current W11-T05 local results:

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed with
  command-local `GOTELEMETRY=off`, `GOCACHE`, and `APPDATA` pointed into the
  workspace to avoid Windows sandbox cache/telemetry permission failures.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed with the same
  command-local environment.
- `python -B -m unittest discover -s tests -p "test_*.py"` - passed with 120
  tests.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/check_wave11_gate.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.
- `make wave11-gate` - attempted, but `make` is not installed in this Windows
  PowerShell environment. The target exists, and every command in the target was
  run directly and passed.

The Wave 11 gate checks:

- checker source has no direct database or Go/internal dependency markers;
- checker source does not call hidden checker, public attack-data, debug, or
  admin endpoints;
- place 1 GET uses the owner case-note endpoint only and has no side-view
  endpoint dependency;
- CLI/action parsing rejects place 2;
- private state and public attack data remain separated;
- checker regression tests for PUT, GET, tamper detection, public exclusions,
  no side views, and place 2 deferral exist;
- exploit and reference-fix scripts remain absent;
- Wave 11 handoffs and this validation summary exist;
- roadmap, waves, source-of-truth, testing strategy, and risk register identify
  Wave 10 complete and Wave 11 under review;
- ForcAD config remains valid.

## CTF Invariants

- Checker uses normal product APIs only.
- Public attack data is credential-free and flag-free.
- Private checker state is separate from public attack data.
- No direct DB dependency exists in checker code.
- No hidden debug/admin shortcut exists.
- No planned vulnerability exists before its wave.
- Place 2 remains Wave 12.
- CHECK/HAVOC remains Wave 13.

## Security Invariants

- Raw flags are sent only to the private owner note endpoint in checker PUT and
  appear only in fake-server private note request/response fixtures.
- Public outputs are tested and gated against raw flags, credentials, bearer
  tokens, checker secrets, and private state.
- Checker errors avoid server-provided raw error text and do not intentionally
  print raw flags or private checker state.
- Cross-owner access remains fail-closed through existing owner-scoped product
  APIs.

## Known Gaps

- Live service checker PUT/GET is not part of the default Wave 11 local gate;
  fake HTTP tests cover checker behavior without requiring a running deployment.
- Historical prior-wave gate scripts may reject intentional later-wave
  expansions. Current branch validation authority is `scripts/check_wave11_gate.py`.

## Ready for Orchestrator Review

yes
