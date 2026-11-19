# Wave 18 W18-T01 Handoff

## 1. Summary

Implemented the controlled AML-5 vulnerable profile behind the
`aml5_vulnerable` Go build tag. Default network-room dossiers remain
references-first and safe. Tagged builds intentionally expose bounded foreign
source-case private data only through the authenticated network-room dossier
path after normal room participation.

Wave 18 is implemented for review only and is not marked accepted by this
handoff.

## 2. Implementation Details

- Added a network-room dossier profile split in `internal/httpapi`:
  `network_room_profile_secure.go` for default builds and
  `network_room_profile_aml5_vulnerable.go` for tagged vulnerable builds.
- Changed the dossier handler to call the profile hook after the normal
  participant-scoped `GetRoomForUser` check succeeds.
- Added tagged repository reader `ListVulnerableDossierCases` that preserves
  `network_room_participants owned` scoping before loading private note bodies
  and EDD confidential comments for cases materialized in the room.
- Added tagged `BuildVulnerableDossier`, which emits private values only for
  cases not owned by the requester and keeps own-case private data omitted.
- Kept the default `BuildSafeDossier` and default network-room HTTP tests safe
  under `!aml5_vulnerable`.
- Added `scripts/check_wave18_gate.py` and `tests/test_wave18_gate.py` for
  profile, test, handoff, exploit/fix, and debug/admin guardrails.

## 3. Files Changed

- `internal/networkroom/repository.go`
- `internal/networkroom/dossier_profile_aml5_vulnerable.go`
- `internal/networkroom/repository_aml5_vulnerable.go`
- `internal/networkroom/repository_aml5_vulnerable_test.go`
- `internal/httpapi/server.go`
- `internal/httpapi/network_room_profile_secure.go`
- `internal/httpapi/network_room_profile_aml5_vulnerable.go`
- `internal/httpapi/network_room_server_test.go`
- `internal/httpapi/aml5_vulnerable_network_room_test.go`
- `scripts/check_wave18_gate.py`
- `tests/test_wave18_gate.py`
- `docs/wave_reports/wave_18_W18-T01_handoff.md`

## 4. Tests Added

- `TestAML5VulnerableDossierLeaksOnlyForeignSourcePrivateData`
- `TestAML5VulnerableRepositoryReaderUsesParticipantScopeAndBoundedPrivateJoins`
- `TestAML5VulnerableNetworkRoomDossierLeaksOnlyForeignSourcePrivateDataAfterJoin`
- `Wave18GateTest` guardrail tests for profile split, forbidden fields,
  exploit/fix absence, and debug/admin toggle rejection.

## 5. Tests Run

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
```

Exit code: 0.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml5_vulnerable ./...
```

Exit code: 0.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
```

Exit code: 0.

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
```

Exit code: 0. Ran 97 tests.

```sh
python -B -m unittest discover -s tests -p "test_wave18_gate.py"
```

Exit code: 0. Ran 5 tests.

```sh
python -B scripts/check_wave18_gate.py
```

Exit code: 0.

```sh
python -B scripts/check_docs_tree.py
```

Exit code: 0.

## 6. Documentation Updated

Added this Wave 18 W18-T01 handoff report. Source-of-truth status files are not
advanced to accepted in this implementation task.

## 7. CTF Invariants Checked

- Checker owner PUT/GET for place 1 and place 2 remains out of scope.
- CHECK/HAVOC code remains untouched.
- Public attack data remains unchanged and credential-free.
- No exploit or fix scripts were added.
- AML-5 is selected only by compile-time Go build tag, not runtime config.

## 8. Security Invariants Checked

- Default build remains safe and references-first.
- Tagged leak is local to `GET /api/network/rooms/{room_id}/dossier`.
- Tagged leak requires normal authentication and room participant scope.
- Tagged leak includes only foreign source-case note body and EDD confidential
  comment samples.
- No credentials, sessions, checker-private state, audit raw diffs, public
  attack data, raw rows, debug/admin controls, or AML-1 through AML-4 expansion
  are introduced.

## 9. Self-Review

The implementation deliberately avoids checker code, public attack data,
ForcAD config, AML-1 through AML-4 profiles, sploit/fix directories,
debug/admin toggles, direct DB checker access, and root owner API behavior. The
new repository reader is build-tagged and participant-scoped; the default
dossier query still avoids private joins.

## 10. Risks / Open Questions

- Wave 18 remains under review until the orchestrator accepts the new tagged
  profile and gate evidence.
- The future AML-5 reference exploit remains locked until Wave 23 and must use
  public attack data plus normal APIs only.
- The future AML-5 reference fix remains locked until Wave 28 after exploit
  evidence is captured.

## 11. Ready for Orchestrator Review

yes
