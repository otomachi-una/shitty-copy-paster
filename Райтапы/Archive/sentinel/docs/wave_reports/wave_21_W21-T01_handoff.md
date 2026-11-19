# W21-T01 Handoff - AML-3 Related Graph Reference Exploit

## 1. Summary

Implemented the AML-3 reference exploit at
`sploits/sentinel_aml/aml_related_graph.py`. The exploit uses only public place
2 `EDDRecord` attack data and the related graph EDD summary side view to recover
`EDDRecord.confidential_comment` when the `aml3_vulnerable` profile exposes it.

Wave 21 is implemented for this task only; it is not accepted, and W21-T02 still
needs to add the aggregate Wave 21 gate and competition matrix update.

## 2. Implementation Details

- Added a stdlib-only CLI:
  `aml_related_graph.py <host> <port> <attack_info_json_or_file> [--timeout SECONDS]`.
- Accepts attack-info as raw JSON or a JSON file path, including nested
  `attack_data` objects.
- Validates locator-only public data for `service=sentinel_aml`,
  `store=EDDRecord`, positive `customer_id`, and non-empty `entity_hint`.
- Rejects credential-like, checker-private, confidential, and flag-like public
  attack data.
- Registers/logs in with deterministic non-secret attacker credentials derived
  from public attack data.
- Creates only attacker-owned graph participation state with the victim
  `entity_hint`.
- Requests only
  `GET /api/graph/entities/{entity_hint}/edd-summaries` as the leak source.
- Extracts a flag-like token only from `summaries[].confidential_comment`.
- Fails cleanly with non-zero exit and no stdout flag when the secure graph
  response is metadata-only or redacted.
- Remains import-safe; all execution is under the `main()` guard.

## 3. Files Changed

- `sploits/sentinel_aml/aml_related_graph.py`
- `sploits/sentinel_aml/README.md`
- `tests/test_wave21_gate.py`
- `docs/wave_reports/wave_21_W21-T01_handoff.md`

## 4. Tests Added

- Added fake-service tests for vulnerable graph EDD summary extraction and
  secure metadata-only failure.
- Added attack-data validation tests for missing `entity_hint`, wrong service,
  wrong store, missing `customer_id`, place 1-only data, and credential-like or
  flag-like public data.
- Added static source checks that reject owner EDD, case notes, audit timeline,
  export, network room, DB, SQL, shell, debug/admin, and checker-private
  markers.
- Added CLI/help and import-safety coverage.

## 5. Tests Run

Executed locally on Windows PowerShell from
`C:\Users\2005g\GolandProjects\Sentinel_AML`:

```sh
python -B -m py_compile sploits\sentinel_aml\aml_related_graph.py
python -B -m unittest discover -s tests -p "test_wave21_gate.py"
python -B scripts\check_docs_tree.py
python -B scripts\check_archive_hygiene.py
```

Results:

| Command | Result |
| --- | --- |
| `python -B -m py_compile sploits\sentinel_aml\aml_related_graph.py` | exit 0 |
| `python -B -m unittest discover -s tests -p "test_wave21_gate.py"` | exit 0; 7 tests passed |
| `python -B scripts\check_docs_tree.py` | exit 0; pass |
| `python -B scripts\check_archive_hygiene.py` | exit 0; pass after removing the local `__pycache__` produced by `py_compile` |

## 6. Documentation Updated

- Updated `sploits/sentinel_aml/README.md` to list `aml_related_graph.py` as
  the Wave 21 AML-3 reference exploit.
- Kept AML-4 and AML-5 exploit script names locked.
- Added this W21-T01 handoff.

## 7. CTF Invariants Checked

- Checker GET for place 2 remains the owner EDD path; the exploit does not use
  `/api/customers/{customer_id}/edd`.
- Public attack data remains locator-only and credential-free.
- Exploit lives under `sploits/sentinel_aml/` and is not a checker dependency.
- No reference fixes were added.
- AML-4 and AML-5 exploit scripts remain absent.

## 8. Security Invariants Checked

- Exploit is bounded to AML-3 related graph EDD summary leakage.
- No direct database access, SQL, shell execution, subprocess, debug/admin
  routes, credential theft, session theft, or checker-private state is used.
- No export, network-room, audit timeline, case-note, or owner EDD leak path is
  treated as AML-3 evidence.
- Secure metadata-only graph responses return non-zero and do not print a flag.

## 9. Self-Review

The implementation follows the planned AML-3 business chain: attacker account,
attacker-owned graph participation via normal customer creation, related graph
EDD summary request, and flag extraction only from the vulnerable confidential
comment field. The tests exercise both vulnerable and secure fake responses and
guard against broadening the exploit surface.

## 10. Risks / Open Questions

- W21-T02 must update the Wave 21 aggregate gate and competition matrix; until
  then, existing Wave 20 gates may intentionally reject the new AML-3 exploit
  artifact.
- The fake service proves exploit shape and parser behavior, but live vulnerable
  profile evidence remains an orchestrator/environment responsibility.

## 11. Ready for Orchestrator Review

Yes. W21-T01 is ready for W21-T02 validation work and later orchestrator review;
Wave 21 is not marked accepted by this handoff.
