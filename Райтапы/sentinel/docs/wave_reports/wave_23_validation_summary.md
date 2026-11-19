# Wave 23 Validation Summary

## Status

Wave 23 is implemented under review. It is not accepted until orchestrator
review. Wave 22 is accepted, Wave 24 is not started, and W24-W28 reference fix
waves remain locked.

## Scope

Wave 23 adds the fifth and final planned reference exploit:
`sploits/sentinel_aml/aml_network_room.py`.

The current reference exploit set is exactly:

- `sploits/sentinel_aml/aml_dedup_preview.py`
- `sploits/sentinel_aml/aml_audit_timeline.py`
- `sploits/sentinel_aml/aml_related_graph.py`
- `sploits/sentinel_aml/aml_export_redaction.py`
- `sploits/sentinel_aml/aml_network_room.py`

No reference fix artifacts are implemented. `fixes/sentinel_aml/` remains
README-only.

## W23-T01 Evidence

W23-T01 implemented the AML-5 reference exploit. The exploit uses public place
2 `EDDRecord` attack data, normal registration/login APIs, attacker-owned
workflow setup, normal network-room discovery/join behavior, and only
`GET /api/network/rooms/{room_id}/dossier`. It extracts flags only from
`foreign_private_notes[].body` and
`foreign_edd_comments[].confidential_comment`.

Recorded W23-T01 checks:

- `python -B -m py_compile sploits/sentinel_aml/aml_network_room.py`
- `python -m unittest tests/test_wave23_gate.py`

## W23-T02 Evidence

W23-T02 added the Wave 23 gate and competition matrix alignment. The gate
requires exactly five reference exploits, rejects extra exploit files, rejects
reference fixes beyond `fixes/sentinel_aml/README.md`, validates AML-5 exploit
scope and import safety, and verifies `wave23-gate` target coverage. The
competition matrix marks AML-1 through AML-5 vulnerable-checker and
exploit-success cells concrete while every fix cell remains pending.

Recorded W23-T02 checks:

- `python -B scripts/check_wave23_gate.py`: exit 0; status `pass`
- `python -B scripts/check_competition_matrix_gate.py`: exit 0; status `pass`
- `python -B -m unittest discover -s tests -p "test_wave23_gate.py"`: exit 0;
  17 tests passed
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 27 tests passed
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: exit 0;
  97 tests passed
- no-repo-cache `python -B -m py_compile` for all five exploits: exit 0
- release/offline `go test ./...`: exit 0
- release/offline `go vet ./...`: exit 0
- release/offline `python -B scripts/run_aml5_tagged_tests.py`: exit 0; 22
  tagged packages passed
- `python -B scripts/check_docs_tree.py`: exit 0; status `pass`
- `python -B scripts/validate_forcad_config.py`: exit 0
- `python -B scripts/check_archive_hygiene.py`: exit 0; status `pass` after
  local bytecode cache cleanup

`make wave23-gate` was not claimed as accepted evidence in W23-T02 because
`make` was not installed in the local Windows shell.

## W23-T03 Documentation Alignment

W23-T03 aligns documentation only. It records Wave 23 as implemented under
review, updates status ledgers for Wave 22 acceptance and Wave 23 review
status, records exactly five reference exploits and zero reference fixes, and
keeps W24-W28 locked until Wave 23 acceptance.

## CTF Invariants

- Place 1 checker GET remains `GET /api/cases/{case_id}/notes`.
- Place 2 checker GET remains `GET /api/customers/{customer_id}/edd`.
- CHECK/HAVOC remains release-blocking through the Wave 23 gate.
- Public attack data remains credential-free and flag-free.
- Reference fixes remain pending and README-only.

## Security Invariants

- AML-5 exploit wording is bounded to network-room dossier side-view behavior.
- Direct DB access, raw SQL, shell/subprocess execution, debug/admin routes,
  credential/session lookup, owner-private API abuse, graph/audit path reuse,
  export/dispute path reuse, and broad network-room serialization remain
  forbidden.

## Known Limitations

- Wave 23 is not accepted by this summary; orchestrator review must perform
  acceptance.
- W24-W28 reference fix artifacts remain locked and must not be added before
  Wave 23 acceptance and each fix wave opening.
- Exact aggregate `make wave23-gate` evidence still requires a make-capable
  review environment.
