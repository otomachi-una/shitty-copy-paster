# Wave 34 Network-Room Lifecycle

## Summary

Wave 34 turns network-room creation from seeded/static test setup into a
deterministic runtime lifecycle. `aml-worker` now scans real case/customer
state, creates or finds one room for each shared entity/typology group, attaches
all matching cases, and adds owning analysts as participants.

## Runtime Model

Canonical worker commands:

```sh
go run ./cmd/aml-worker
go run ./cmd/aml-worker --once
```

The long-running command polls at a fixed interval. The `--once` mode performs
one bounded scan and exits; runtime smoke and restart-safety tests use this
mode.

Eligibility is deterministic:

```text
same normalized customer.entity_hint + same normalized case.typology_hint
```

Only groups with at least two cases are materialized. Reruns are idempotent
through database uniqueness on room keys, room-case links, and participants.

## Security Boundary

The worker stores room metadata, case references, and participant metadata only.
It does not copy case-note bodies, EDD confidential comments, audit diffs,
export payloads, checker-private state, flags, public attack data, credentials,
or raw source records.

AML-5 remains bounded to the normal network-room dossier side view. The secure
profile keeps private dossier data redacted; the competition
`network_room_detail`/`aml5_vulnerable` profile may expose the intended bounded
foreign dossier details after normal deterministic room participation exists.

## Evidence Commands

Recorded local commands for this implementation:

- `python -B -m py_compile scripts/runtime_smoke.py`
- `python -B -m unittest discover -s tests -p "test_runtime_smoke.py"`
- `go test ./internal/networkroom ./cmd/aml-worker`
- `go test ./internal/httpapi -run "NetworkRoom|Wave34Network|LivePostgresWave34Network"`
- `go test -tags network_room_detail ./internal/httpapi ./internal/networkroom`
- `go test -tags "case_match_preview audit_detail_view entity_review_summary linked_case_export_detail network_room_detail" ./internal/httpapi ./internal/networkroom`
- `go build ./cmd/aml-worker`
- `go test ./internal/networkroom ./cmd/aml-worker ./internal/httpapi`
- `go build -tags "network_room_detail" ./cmd/aml-api ./cmd/aml-worker ./scripts/migrate`
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_docs_tree.py`
- `python -B scripts/validate_forcad_config.py`

Live runtime evidence recorded on the local Windows host with Docker Desktop:

- `python -B scripts/runtime_smoke.py` - exit 0, elapsed 30.187s.
- Runtime smoke worker materialization phase logged `groups=1`,
  `cases_attached=2`, `participants_joined=2`,
  `duplicate_case_links=0`, and `duplicate_participants=0`.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable go test ./internal/httpapi -run TestLivePostgresWave34NetworkRoomLifecycleIntegration -count=1` - exit 0.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable go test -tags network_room_detail ./internal/httpapi -run TestLivePostgresWave34NetworkRoomLifecycleIntegration -count=1` - exit 0.

Full live runtime acceptance remains environment dependent and is covered by:

```sh
python -B scripts/runtime_smoke.py
```

The opt-in PostgreSQL hook is:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://... go test ./internal/httpapi -run TestLivePostgresWave34NetworkRoomLifecycleIntegration
```

## Anti-Goals

- No magic seeded rooms for AML-5.
- No debug or admin trigger endpoint.
- No direct DB shortcut for checker or sploit flows.
- No broad room membership grant to private notes, EDD records, audit events,
  exports, or checker state.
- No final player/admin release archive.
