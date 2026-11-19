# W22-T02 Handoff - Wave 22 Gate and Competition Matrix Update

## 1. Summary

Implemented the Wave 22 validation layer for the AML-4 reference exploit. The
new gate requires exactly four Sentinel AML reference exploit scripts, keeps
AML-5 locked, and rejects any reference fix artifacts beyond the README
skeleton.

Wave 22 is not marked accepted by this handoff.

## 2. Implementation Details

- Added `scripts/check_wave22_gate.py` with JSON output and non-zero failure on
  scope violations.
- Required these exploit scripts exactly:
  `aml_dedup_preview.py`, `aml_audit_timeline.py`, `aml_related_graph.py`, and
  `aml_export_redaction.py`.
- Rejected premature `aml_network_room.py`.
- Rejected all `fixes/sentinel_aml/` artifacts except `README.md`.
- Added static AML-4 exploit checks for CLI/import-safe shape, stdlib HTTP
  client markers, attacker auth flow markers, dispute export routes, linked
  private note extraction, and flag extraction.
- Added forbidden marker scans for DB drivers, SQL, shell/subprocess, debug or
  admin endpoints, owner notes, owner EDD, audit timeline, graph EDD summaries,
  network-room paths, and public attack-data secret lookups.
- Updated the competition matrix gate to make AML-4 exploit-success concrete
  while keeping AML-5 exploit-success and all fix cells pending.
- Added `wave22-gate` to `Makefile` with checker tests, Wave 22 tests, matrix
  tests, no-repo-cache py_compile for all four exploits, Go test/vet, Wave 22
  gate, competition matrix, docs tree, ForcAD validation, and archive hygiene.

## 3. Files Changed

- `scripts/check_wave22_gate.py`
- `tests/test_wave22_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/wave_reports/wave_22_W22-T02_handoff.md`

## 4. Tests Added

- Current-branch Wave 22 gate pass test.
- Missing AML-4 exploit rejection.
- Premature AML-5 exploit rejection.
- Premature fix artifact rejection.
- Forbidden primitive and wrong side-view marker rejection.
- Public attack-data secret lookup rejection.
- Import-time side-effect rejection.
- Makefile `wave22-gate` closure and archive-hygiene requirement.
- Competition matrix tests for four exploit scripts, AML-4 exploit-success
  concrete, AML-4 fixes pending, AML-5 pending.

## 5. Tests Run

Executed locally on Windows PowerShell from
`C:\Users\2005g\GolandProjects\Sentinel_AML`:

```sh
python -B -m unittest discover -s tests -p "test_wave22_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B scripts\check_wave22_gate.py
python -B scripts\check_competition_matrix_gate.py
python -B scripts\check_archive_hygiene.py
```

Results:

| Command | Result |
| --- | --- |
| `python -B -m unittest discover -s tests -p "test_wave22_gate.py"` | exit 0; 16 tests passed |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; 25 tests passed |
| `python -B scripts\check_wave22_gate.py` | exit 0; status `pass` |
| `python -B scripts\check_competition_matrix_gate.py` | exit 0; status `pass` |
| `python -B scripts\check_archive_hygiene.py` | exit 1; fails on pre-existing `.idea/` |

## 6. Documentation Updated

- Added this W22-T02 handoff report.

## 7. CTF Invariants Checked

- Existing checker/HAVOC tests remain part of `wave22-gate`.
- Exploits remain outside checker code.
- Public attack data remains credential-free by gate policy.
- No reference fixes were added or unlocked.
- AML-5 remains locked.

## 8. Security Invariants Checked

- Gate rejects direct DB, SQL, shell/subprocess, debug/admin, credential or
  session lookup through public attack data, checker-private state, and wrong
  side-view paths.
- AML-4 remains scoped to dispute export linked private-note leakage.

## 9. Self-Review

The gate follows the Wave 19-21 pattern and advances only the Wave 22 evidence
state. It does not alter product behavior, checker behavior, migrations,
deployment, exploit runtime behavior, or fixes.

## 10. Risks / Open Questions

- Archive hygiene still fails on pre-existing `.idea/`, which is outside the
  W22-T02 allowed file scope.
- Full `timeout 300 make wave22-gate` is expected to be run by the aggregate
  review path; this task's required command list covers the Python gate layer.

## 11. Ready for Orchestrator Review

No. Wave 22 gate and matrix validation pass, but archive hygiene still fails on
the local `.idea/` artifact until a cleanup/package-hygiene task removes it.
