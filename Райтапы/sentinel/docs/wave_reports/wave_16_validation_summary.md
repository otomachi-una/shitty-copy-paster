# Wave 16 Validation Summary

Status: under review.

## Scope Validated

Wave 16 implements AML-3 only under the `aml3_vulnerable` Go build tag. The
tagged profile is limited to
`GET /api/graph/entities/{entity_hint}/edd-summaries`, where related EDD summary
items may include `confidential_comment` after normal authentication and the
owned-`entity_hint` graph access check. The default build remains the secure
metadata-only graph profile.

`docs/09_vulnerability_matrix.md` is the source of truth for AML-3 behavior,
protected-field exclusions, and exploit/fix sequencing.

## Commands and Results

W16-T01/W16-T02 implementation evidence recorded these component results:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: pass, 97
  tests, process exited.
- `python -B -m unittest discover -s tests -p "test_wave16_gate.py"`: pass, 8
  tests.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  pass, 12 tests.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`: pass.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags
  aml3_vulnerable ./...`: pass.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`: pass.
- `python -B scripts/check_docs_tree.py`: pass.
- `python -B scripts/check_wave16_gate.py`: pass.
- `python -B scripts/check_competition_matrix_gate.py`: pass.
- `python -B scripts/validate_forcad_config.py`: pass.

W16-T03 documentation alignment requires and records:

- `python -B scripts/check_docs_tree.py`: pass.
- `python -B scripts/check_wave16_gate.py`: pass.
- `python -B scripts/check_competition_matrix_gate.py`: pass.

`make wave16-gate` remains the authoritative wrapper for orchestrator closure.
On this Windows host the literal wrapper was previously unavailable because no
make-compatible executable was on PATH, so final wrapper closure requires a
make-equipped review host or equivalent orchestrator environment.

## CTF Invariants

- Two active checker flag stores remain owner-owned: `CaseNote.body` for place
  1 and `EDDRecord.confidential_comment` for place 2.
- Checker PUT/GET still uses normal owner HTTP APIs only and does not use graph
  side views.
- AML-3 does not add a reference exploit or reference fix in Wave 16.
- Public attack data remains locator-only and credential-free.
- Wave 21 remains locked until Wave 16 is accepted by orchestrator review.

## Security Invariants

- Default graph responses remain metadata-only.
- Tagged AML-3 vulnerable behavior is narrow and limited to graph EDD summaries.
- Protected exclusions remain explicit: `CaseNote.body`, EDD narrative fields,
  raw audit diffs, export bundles, network-room dossiers, credentials,
  sessions, checker-private state, public attack data, raw database rows, and
  debug/admin controls must not be exposed by AML-3.
- No hidden route, runtime toggle, direct database checker path, broad
  serialization leak, exploit script, or reference fix is documented as active.

## Known Gaps

- Wave 16 is not complete until orchestrator review accepts the gate evidence.
- `make wave16-gate` wrapper execution still needs make-equipped environment
  evidence if the local Windows host lacks `make`.
- AML-3 reference exploit work remains scheduled for Wave 21 after Wave 16
  acceptance; AML-3 fix work remains scheduled for Wave 26 after exploit
  evidence.

## Ready for Orchestrator Review

yes, for Wave 16 documentation/source-of-truth review; no claim of Wave 16
completion is made before orchestrator acceptance.
