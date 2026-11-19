# Wave 28 Validation Summary

## Status

Wave 28 is implemented under review. It is not accepted by this documentation
update, and Sentinel AML is not competition-ready until Wave 29+ full
regression/final matrix and packaging validation pass.

## Scope

Wave 28 completes the individual reference-fix set by adding the AML-5
network-room reference fix artifact:

- `fixes/sentinel_aml/aml_network_room.patch`
- `scripts/check_wave28_gate.py`
- `tests/test_wave28_gate.py`
- `wave28-gate`

The repository now represents two active checker flag stores, five planned
vulnerabilities, five accepted reference exploits, and five reference fix
patches. Wave 29 remains locked until orchestrator acceptance of Wave 28.

## Evidence

- W28-F01 adds the missing AML-5 patch artifact and fix README documentation.
- W28-F01 verifies the patch applies cleanly and, in a temporary patched copy,
  focused AML-5 tagged network-room tests pass.
- W28-F02 adds the Wave 28 gate, unit tests, Makefile target, and competition
  matrix final fix-cell alignment.
- `scripts/check_wave28_gate.py` validates five exploits, exactly five standard
  patch artifacts, patch applicability, AML-5 patch scope, exploit-blocked
  markers, anti-coarse-fix markers, docs, and Makefile coverage.
- `scripts/check_competition_matrix_gate.py` now validates all five
  vulnerable-checker cells, all five exploit-success cells, and all five
  fixed-checker/exploit-blocked/anti-coarse-fix cells as concrete.
- W28-F03 documentation recovery verifies `python -B scripts/check_docs_tree.py`
  and `python -B scripts/check_archive_hygiene.py` exit 0 after the status
  ledger updates.

## Limitations

- Local Windows execution could not run the exact GNU command
  `timeout 300 make wave28-gate` because Windows `TIMEOUT.EXE` rejected the GNU
  syntax with exit 1 before Make execution. W28-F02 records component-command
  evidence and leaves exact wrapper acceptance to an orchestrator environment
  with GNU `timeout` and `make`.
- Wave 28 does not claim final competition readiness. Wave 29 must run the full
  regression/final matrix and anti-coarse-fix validation after Wave 28
  orchestrator acceptance.

## CTF And Security Invariants

- Checker PUT/GET remains owner-only for place 1 `CaseNote.body` and place 2
  `EDDRecord.confidential_comment`.
- Public attack data remains credential-free and raw-flag-free.
- CHECK/HAVOC remains release-blocking gate evidence.
- Fixed AML-5 network-room dossiers must remain reference/public-only for
  foreign cases and must not expose foreign private notes, EDD confidential
  comments, evidence internals, audit diffs, hashes, credentials, sessions,
  checker-private state, raw DB rows, debug/admin data, or sensitive-field
  rename leaks.
