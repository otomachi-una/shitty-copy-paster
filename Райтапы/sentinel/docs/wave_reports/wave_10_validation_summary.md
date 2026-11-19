# Wave 10 Validation Summary

## Summary

Wave 10 adds secure export/dispute and network-room baselines. The current branch authority is `scripts/check_wave10_gate.py` plus `make wave10-gate`. Wave 09 is complete; Wave 10 remains `needs fixes` until W10-T01, W10-T02, W10-T03, W10-T04, and W10-T05 pass orchestrator review.

## Scope Validated

- `000008_create_exports_disputes.sql` defines `disputes`, `exports`, and `export_items`.
- `internal/exporting` builds deterministic public/redacted export bundles for root, linked, and nested linked cases.
- Secure export routes are active:
  - `POST /api/cases/{case_id}/exports`
  - `GET /api/exports/{export_id}`
  - `POST /api/disputes`
  - `POST /api/disputes/{dispute_id}/export`
- `000009_create_network_rooms.sql` defines `network_rooms`, `network_room_cases`, and `network_room_participants`.
- `internal/networkroom` stores room metadata, participant metadata, and case references only.
- Secure network-room routes are active:
  - `GET /api/network/rooms`
  - `GET /api/network/rooms/{room_id}`
  - `POST /api/network/rooms/{room_id}/join`
  - `GET /api/network/rooms/{room_id}/dossier`
- Projection contracts include `ExportBundleView`, export shell/summary/item views, `NetworkRoomSummaryView`, `NetworkRoomCaseView`, and `NetworkRoomDossierView`.

## Tests and Gates

Wave 10 validation expects these commands:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B -m unittest discover -s tests -p 'test_*.py'
python -B scripts/check_docs_tree.py
python -B scripts/check_wave10_gate.py
python -B scripts/validate_forcad_config.py
make wave10-gate
```

Current W10-T05 local results:

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` — passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` — passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` — passed with 88 tests.
- `python -B scripts/check_docs_tree.py` — passed.
- `python -B scripts/check_wave10_gate.py` — passed.
- `python -B scripts/validate_forcad_config.py` — passed.
- `make wave10-gate` — not run because `make` is not installed in this Windows shell; every target command was run directly and passed.

The gate checks:

- migration ordering and table scope through Wave 10;
- export recursive redaction for root, linked, and nested linked cases;
- network-room references-only storage and participant-scoped dossier reads;
- secure route registration for export and network-room APIs;
- absence of checker, public attack-data, debug, admin, broad graph root, broad network root, exploit, and reference-fix behavior;
- DTO/projection allowlists for export and network-room views;
- Anti-AML-4 and Anti-AML-5 HTTP/source regression test presence;
- docs tree and ForcAD config validity;
- Wave 10 handoff reports and this validation summary.

## CTF Invariants

- No checker PUT/GET path exists.
- No public attack data exists.
- No exploit or reference-fix scripts exist.
- AML-4 remains future-only until Wave 17.
- AML-5 remains future-only until Wave 18.
- `CaseNote.body` and `EDDRecord.confidential_comment` remain normal owner-private business fields only.

## Security Invariants

- Export output is public/redacted by default and omits private note bodies, EDD confidential comments, EDD narrative fields, raw audit diffs, value hashes, credentials, sessions, checker-private markers, artificial flag fields, and raw DB rows.
- Network-room dossier output is references-first and omits private note bodies, EDD confidential comments, raw EDD narrative fields, raw audit diffs, value hashes, credentials, sessions, counterparty fingerprints, trace IDs, checker-private markers, public attack data, artificial flag fields, and raw source case blobs.
- Network-room participation is not private case, note, EDD, audit, export, or checker visibility.
- Cross-owner and non-participant access remains fail-closed.

## Known Gaps

- Live PostgreSQL export/network-room end-to-end validation is not required by W10-T05 and remains separate from the default offline branch gate.
- Historical prior-wave gate scripts may reject intentional later-wave migrations and routes. Current branch validation authority is `scripts/check_wave10_gate.py`.

## Ready for Orchestrator Review

yes
