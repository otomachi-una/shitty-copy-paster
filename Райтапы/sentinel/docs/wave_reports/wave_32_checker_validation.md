# Wave 32 Checker Validation

## Summary

W32-T02 makes final checker execution evidence explicit for both flag stores,
CHECK/HAVOC coverage, public attack-data safety, and deterministic timeout
handling. The executable scenario inventory lives in
`checker_lib.checker_scenario_inventory()` and is asserted by
`tests/test_checker_scenario_inventory.py`.

## Scenario Inventory

| Scenario | Evidence |
| --- | --- |
| `place1_put` | Stores the place 1 flag only through owner `POST /api/cases/{case_id}/notes`. |
| `place1_get` | Reads place 1 only through owner `GET /api/cases/{case_id}/notes`; GET remains owner-view only. |
| `place2_put` | Stores the place 2 flag only through owner `POST /api/customers/{customer_id}/edd`. |
| `place2_get` | Reads place 2 only through owner `GET /api/customers/{customer_id}/edd`; GET remains owner-view only. |
| `health` | CHECK/HAVOC liveness via `GET /healthz`. |
| `check_basic` | CHECK/HAVOC auth, customer, account, transaction, alert, and readback flow. |
| `check_case_notes` | CHECK/HAVOC non-flag owner case-note create/readback. |
| `check_edd` | CHECK/HAVOC non-flag owner EDD create/readback. |
| `check_dedup` | CHECK/HAVOC public-only duplicate and merge-preview projection. |
| `check_audit` | CHECK/HAVOC owner audit timeline with redacted sensitive changes. |
| `check_graph` | CHECK/HAVOC public-only graph entity and related-case projection. |
| `check_export` | CHECK/HAVOC public-redacted export create/readback. |
| `check_network_room` | CHECK/HAVOC references-only network-room list/dossier projection. |
| `check_retention` | CHECK/HAVOC retention smoke for `case_notes` and `edd_records`. |
| `putnoise` | Deterministic non-flag business object creation with locator-only public data. |
| `getnoise` | MAC-state noise readback through normal owner and public-redacted APIs. |

## Public Data Boundary

No checker-private state in public attack data. Public attack data contains only
attack-locator fields and must not include usernames, passwords, bearer tokens,
sessions, raw flags, checker secrets, private state, or
`confidential_comment`. Public noise data applies the same boundary and also
rejects private note bodies, source-of-funds text, and risk rationale text.

## Timeout Evidence

Checker HTTP requests use deterministic per-request timeouts. The default
client timeout remains `5.0` seconds, optional per-call overrides are forwarded
to `urlopen`, and timeout failures map to `ServiceDownError`.

## Stability-Gate Inclusion

`make ad-stability-gate` runs `python -B -m unittest discover -s tests -p
"test_checker_*.py"`, so the checker scenario inventory, CHECK/HAVOC matrix,
PUT/GET owner flows, public attack-data leak checks, and timeout checks are
included in the archive-free stability gate.

## Invariants

- Checker PUT/GET uses only normal owner APIs.
- Checker GET does not use dedup, audit, graph, export, network-room, or other
  side-view paths to recover flags.
- Both flag stores remain active: `CaseNote.body` and
  `EDDRecord.confidential_comment`.
- CHECK/HAVOC includes basic, case notes, EDD, dedup, audit, graph, export,
  network-room, and retention scenarios.
- `putnoise` and `getnoise` remain supported and non-flag.
