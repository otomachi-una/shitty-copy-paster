# W23-T01 Handoff - AML-5 Network-Room Reference Exploit

## 1. Summary

Implemented `sploits/sentinel_aml/aml_network_room.py` as the W23 reference exploit
for AML‑5. The exploit follows the normal public-attack-data flow and uses only
standard-library HTTP APIs to register/login, create attacker-owned workflow objects,
discover/join network-room participation, and extract the flag from the vulnerable
network-room dossier view.

## 2. Implementation Details

- Added `aml_network_room.py` with CLI `host port attack_info [--timeout]`.
- `load_attack_data` accepts inline JSON or a JSON file path and validates structure
  and forbidden public fields/values (credentials, private state, sessions, flag-like
  blobs).
- Deterministic attacker credentials are derived from public metadata hash.
- Workflow creates attacker-owned: customer → account → transaction → alert claim → case,
  then discovers a room via public locator metadata and joins it.
- Dossier fetch is limited to `GET /api/network/rooms/{room_id}/dossier`.
- Flag extraction is restricted to `foreign_private_notes[].body` and
  `foreign_edd_comments[].confidential_comment`.

## 3. Files Changed

- `sploits/sentinel_aml/aml_network_room.py`
- `sploits/sentinel_aml/README.md`
- `tests/test_wave23_gate.py`
- `docs/wave_reports/wave_23_W23-T01_handoff.md`

## 4. Tests Added

- `tests/test_wave23_gate.py`
  - import-safety test (no network calls at import)
  - CLI help parsing
  - attack-data parsing from JSON file / nested payload
  - rejection of malformed, credentialed, and flag-like public attack data
  - exploit success path with fake `GET /api/network/rooms/{id}/dossier` leak
  - safe failure on redacted dossier
  - source-scope checks for required allowed primitives and absent forbidden primitives

## 5. Tests Run

- `python -B -m py_compile sploits/sentinel_aml/aml_network_room.py`
- `python -m unittest tests/test_wave23_gate.py`

## 6. Documentation Updated

- `sploits/sentinel_aml/README.md` now includes the AML-5 exploit contract:
  expected public store/fields, workflow path, side view, leaked fields, and
  previously locked future script status.

## 7. CTF Invariants Checked

- Public attack data contract remains credential-free and checker-private state-free in
  exploit validation.
- No checker/private fixtures are read by the exploit.
- No direct DB access, shell/subprocess execution, or reference-fix behavior.
- Standard HTTP APIs only; no modifications to `internal/`, `cmd/`, `migrations/`,
  or `docker-compose.yml`.

## 8. Security Invariants Checked

- Exploit targets only `GET /api/network/rooms/{room_id}/dossier` in the network-room
  workflow after normal auth/session bootstrap.
- No calls to graph, audit, export, owner case-note/EDD APIs, debug/admin routes.
- No local file writes/network side effects at import time.

## 9. Self-Review

- Behavior matches AML-5 chain requirements: public locator metadata is used, attacker
  is created via normal onboarding flow, room membership is achieved through normal room
  APIs, and the leaked token is taken only from known vulnerable dossier fields.
- `run_exploit` fails with concise errors when network-room membership, alerting, or
  dossier extraction does not produce a flag-like token.
- Tests are currently focused at the exploit unit level with fake transport stubs.

## 10. Risks / Open Questions

- The real service must materialize/list accessible network rooms for the newly created
  attacker case as expected by the chain; current fake transport assumes this behavior.
- If production rooms only use a fixed typology (`counterparty-watchlist`), fallback room
  matching by `entity_hint` remains permissive to avoid brittle failures.

## 11. Ready for Orchestrator Review

Yes.
