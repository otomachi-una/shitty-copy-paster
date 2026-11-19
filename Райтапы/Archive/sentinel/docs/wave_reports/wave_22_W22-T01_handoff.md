# W22-T01 Handoff - AML-4 Export Redaction Reference Exploit

## 1. Summary

Implemented `sploits/sentinel_aml/aml_export_redaction.py` as the Wave 22
AML-4 reference exploit. The exploit is bounded to the `aml4_vulnerable`
dispute export redaction gap and extracts a flag-like token only from linked
case private note material exposed as `bundle.linked_private_notes[].body`.

Wave 22 is not marked accepted by this handoff. AML-5 remains locked and
`fixes/sentinel_aml/` remains README-only.

## 2. Implementation Details

- Added a stdlib-only CLI:
  `aml_export_redaction.py <host> <port> <attack_info_json_or_file> [--timeout SECONDS]`.
- Accepts raw JSON, file-path JSON, and nested `attack_data` objects.
- Validates Sentinel AML place 1 `CaseNote.body` public attack data with
  `case_id`, `dedup_hint`, and locator metadata.
- Rejects credential-like, checker-private, confidential, session/token/
  password, and flag-like values in public attack data.
- Registers/logs in as an attacker using deterministic non-secret credentials
  derived from public locator data.
- Creates attacker-owned customer/account/transaction/alert/case state with the
  public victim `dedup_hint` so the vulnerable export can link to the victim
  case through normal duplicate discovery.
- Creates a normal dispute with `POST /api/disputes`.
- Creates a normal dispute export with
  `POST /api/disputes/{dispute_id}/export`.
- Reads the stored export with `GET /api/exports/{export_id}`.
- Extracts and prints only a flag-like token from
  `bundle.linked_private_notes[].body`.
- Exits non-zero and prints no flag when the export response is secure,
  redacted, malformed, or missing the intended AML-4 leak field.
- Remains import-safe; no HTTP request is performed at import time.

## 3. Files Changed

- `sploits/sentinel_aml/aml_export_redaction.py`
- `sploits/sentinel_aml/README.md`
- `tests/test_wave22_gate.py`
- `docs/wave_reports/wave_22_W22-T01_handoff.md`

## 4. Tests Added

- CLI/help behavior without service requests.
- Import safety with network calls mocked to fail at import time.
- Raw JSON, nested `attack_data`, and file-path attack-info loading.
- Public attack-data rejection for wrong service, wrong store, missing
  `case_id`, missing `dedup_hint`, missing locator metadata, credentials,
  sessions/tokens, checker-private fields, confidential fields, and flag-like
  values.
- Fake vulnerable export readback prints exactly the flag from
  `linked_private_notes[].body`.
- Fake secure/redacted export readback exits non-zero and prints no stdout flag.
- Static source restrictions for DB drivers, SQL, shell/subprocess,
  debug/admin routes, owner notes, owner EDD, audit timeline, graph EDD
  summaries, network-room dossier paths, and generic framework overreach.

## 5. Tests Run

Executed locally on Windows PowerShell from
`C:\Users\2005g\GolandProjects\Sentinel_AML`:

```sh
python -B -m py_compile sploits\sentinel_aml\aml_export_redaction.py
python -B -m unittest discover -s tests -p "test_wave22_gate.py"
python -B scripts\check_docs_tree.py
python -B scripts\check_archive_hygiene.py
```

Results:

| Command | Result |
| --- | --- |
| `python -B -m py_compile sploits\sentinel_aml\aml_export_redaction.py` | exit 0 |
| `python -B -m unittest discover -s tests -p "test_wave22_gate.py"` | exit 0; 8 tests passed |
| `python -B scripts\check_docs_tree.py` | exit 0 |
| `python -B scripts\check_archive_hygiene.py` before cleanup | exit 1; failed on `.idea/` and `sploits/sentinel_aml/__pycache__/` |
| `python -B scripts\check_archive_hygiene.py` after removing generated Python bytecode | exit 1; still fails on pre-existing `.idea/` |

The generated `sploits/sentinel_aml/__pycache__/` from `py_compile` was removed
after verifying the resolved path was inside the workspace. The remaining
`.idea/` directory is a local IDE artifact outside the W22-T01 file scope and
needs separate archive-hygiene cleanup authorization or a packaging cleanup
task before final acceptance.

## 6. Documentation Updated

- Updated `sploits/sentinel_aml/README.md` to list
  `aml_export_redaction.py` as the Wave 22 AML-4 reference exploit.
- Kept `aml_network_room.py` locked as the only future exploit script name.
- Added this W22-T01 handoff.

## 7. CTF Invariants Checked

- Public attack data remains credential-free and locator-only.
- The exploit is outside checker code.
- Checker PUT/GET behavior was not changed.
- Checker place 1 GET remains owner case notes.
- Checker place 2 GET remains owner EDD.
- No reference fix artifacts were added.
- AML-5 exploit remains absent.

## 8. Security Invariants Checked

- AML-4 exploit is bounded to the linked-case dispute export redaction gap.
- No direct DB access, SQL, shell/subprocess, debug/admin route, credential
  theft, session theft, checker-private data, owner private-note API, owner EDD
  API, audit timeline, graph, or network-room path is used.
- Secure/redacted export responses fail closed without stdout flag material.

## 9. Self-Review

The exploit follows the intended AML-4 business chain with normal HTTP APIs:
attacker account, attacker-owned duplicate-linked case, attacker-owned dispute,
dispute export creation, stored export readback, and extraction only from
`linked_private_notes[].body`. The focused tests cover both vulnerable and
secure fake responses plus public-data and static-surface guardrails.

## 10. Risks / Open Questions

- Archive hygiene remains blocked by a pre-existing `.idea/` directory outside
  the W22-T01 file scope.
- W22-T02 still needs to add the aggregate Wave 22 gate and competition matrix
  update so AML-4 exploit-success becomes concrete in the gate layer.
- Live vulnerable-profile execution was not run in this task; fake-service
  coverage proves the reference exploit shape and parser behavior.

## 11. Ready for Orchestrator Review

No. The AML-4 exploit implementation and focused tests are ready, but archive
hygiene currently fails on `.idea/`, which requires separate cleanup before a
clean orchestrator review package.
