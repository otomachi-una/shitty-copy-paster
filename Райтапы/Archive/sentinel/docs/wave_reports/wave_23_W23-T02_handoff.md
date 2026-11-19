# W23-T02 Handoff - Wave 23 Gate and Competition Matrix Update

## 1. Summary

Added the Wave 23 validation layer for the final Sentinel AML reference exploit
set. The gate now expects exactly five exploit scripts, treats AML-5
exploit-success as concrete in the competition matrix, and keeps every reference
fix cell pending.

## 2. Implementation Details

- Added `scripts/check_wave23_gate.py` with JSON pass/fail output and non-zero
  failure exit.
- Required exactly these exploit files under `sploits/sentinel_aml/`:
  `aml_dedup_preview.py`, `aml_audit_timeline.py`, `aml_related_graph.py`,
  `aml_export_redaction.py`, and `aml_network_room.py`.
- Rejected extra exploit files and all `fixes/sentinel_aml/` artifacts beyond
  `README.md`.
- Added static AML-5 checks for normal CLI/import-safe shape, standard-library
  HTTP usage, public attack-data validation, network-room discovery/join/dossier
  flow, extraction from `foreign_private_notes[].body` and
  `foreign_edd_comments[].confidential_comment`, and absence of direct DB,
  shell, debug/admin, graph/audit/export/dispute, owner-private, and
  public-data credential/session lookup primitives.
- Updated the competition matrix gate so AML-1 through AML-5 vulnerable-checker
  and exploit-success cells are concrete while all fixed checker,
  exploit-blocked, and anti-coarse-fix cells remain pending.
- Added `wave23-gate` to `Makefile` with checker tests, Wave 23 tests, matrix
  tests, no-repo-cache `py_compile` for all five exploits, release/offline Go
  test and vet, AML-5 tagged test runner, docs-tree validation, ForcAD
  validation, and archive hygiene.

## 3. Files Changed

- `scripts/check_wave23_gate.py`
- `tests/test_wave23_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/wave_reports/wave_23_W23-T02_handoff.md`

## 4. Tests Added

- Wave 23 gate happy path.
- Missing AML-5 exploit rejection.
- Extra exploit rejection.
- Premature reference-fix artifact rejection.
- Forbidden primitive rejection.
- Wrong network-room side-view path rejection.
- Public attack-data secret lookup rejection.
- Import-time execution rejection.
- Makefile target coverage.
- Competition matrix AML-5 exploit-success concrete and AML-5 fixes pending.

## 5. Tests Run

| Command | Result |
| --- | --- |
| `python -B scripts/check_wave23_gate.py` | exit 0; status `pass` |
| `python -B scripts/check_competition_matrix_gate.py` | exit 0; status `pass` |
| `python -B -m unittest discover -s tests -p "test_wave23_gate.py"` | exit 0; 17 tests passed |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; 27 tests passed |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; 97 tests passed |
| no-repo-cache `python -B -m py_compile` for all five exploits | exit 0 |
| release/offline `go test ./...` | exit 0 |
| release/offline `go vet ./...` | exit 0 |
| release/offline `python -B scripts/run_aml5_tagged_tests.py` | exit 0; 22 tagged packages passed |
| `python -B scripts/check_docs_tree.py` | exit 0; status `pass` |
| `python -B scripts/validate_forcad_config.py` | exit 0 |
| `python -B scripts/check_archive_hygiene.py` | exit 0; status `pass` after local bytecode cache cleanup |
| `make wave23-gate` | not runnable in this Windows shell; `make` is not installed in PATH |

## 6. Documentation Updated

This handoff records the Wave 23 gate and competition matrix update for
orchestrator review. It does not claim Wave 23 acceptance.

## 7. CTF Invariants Checked

- Checker Python tests remain part of `wave23-gate`.
- Strong CHECK/HAVOC coverage remains included through `test_checker_*.py`.
- Public attack data remains credential-free under the AML-5 exploit static and
  unit tests.
- Reference fixes remain locked and README-only.

## 8. Security Invariants Checked

- The AML-5 exploit is bounded to network-room discovery, join, and dossier
  readback.
- The gate blocks direct DB clients, SQL markers, shell/subprocess use,
  debug/admin routes, export/dispute paths, graph/audit paths, owner-private
  case/EDD paths, and credential/session lookups from public attack data.
- No product behavior, checker behavior, migrations, deploy config, prior
  exploits, or reference-fix artifacts were modified by W23-T02.

## 9. Self-Review

The implementation makes the final reference exploit inventory concrete while
preserving the fix-wave lock. The matrix gate now represents the intended
competition state: AML-1 through AML-5 vulnerable-checker and exploit-success
evidence are concrete, and W24-W28 fix work remains future/pending.

## 10. Risks / Open Questions

- Full aggregate `make wave23-gate` depends on a make-capable shell and clean
  archive hygiene state.
- The Wave 23 gate is static by design; it validates exploit shape and matrix
  contracts but does not execute the exploit against a live service.

## 11. Ready for Orchestrator Review

Yes.
