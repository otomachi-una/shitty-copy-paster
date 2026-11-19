# W19-T01 Handoff — AML-1 Reference Exploit Script

## 1. Summary

Implemented the Wave 19 AML-1 reference exploit at
`sploits/sentinel_aml/aml_dedup_preview.py`. The exploit uses public place 1
attack data and normal Sentinel AML HTTP APIs to trigger the accepted
`aml1_vulnerable` dedup merge-preview leak, then prints only the extracted
flag.

## 2. Implementation Details

- Added a standalone Python stdlib HTTP client with host, port, attack-info
  JSON/path, and timeout parsing.
- The exploit validates public attack data for `service`, `store:
  CaseNote.body`, `case_id`, and `dedup_hint`.
- The exploit registers and logs in as an attacker, creates an attacker-owned
  customer/account/transaction/alert/case chain with the victim `dedup_hint`,
  lists duplicate candidates, and requests merge-preview.
- Success extracts a flag-like token only from
  `candidate.private_notes[].body`; failure exits non-zero with concise stderr.
- Added Wave 19 static and fake-service tests plus a gate script checking
  script scope, later exploit locks, reference-fix locks, docs, and Makefile
  wiring.
- Validated the competition matrix so only the AML-1 exploit-success cell is
  concrete and later exploit/fix cells remain locked.

## 3. Files Changed

- `sploits/sentinel_aml/aml_dedup_preview.py`
- `sploits/sentinel_aml/README.md`
- `scripts/check_wave19_gate.py`
- `tests/test_wave19_gate.py`
- `Makefile`
- `docs/09_vulnerability_matrix.md`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/waves.md`
- `docs/wave_reports/wave_19_W19-T01_handoff.md`

## 4. Tests Added

- Wave 19 current-branch gate pass test.
- Fake vulnerable AML-1 service test proving stdout contains only the leaked
  flag.
- Secure/default merge-preview test proving the exploit fails safely when
  `private_notes` is absent.
- Static guard tests for attack-data requirements, forbidden DB/shell markers,
  public attack-data secret lookups, later exploit files, fix files, and
  missing Makefile wiring.
- Wave 19 gate coverage for the AML-1 exploit-success matrix integration while
  AML-1 fix cells remain locked.

## 5. Tests Run

All final W19-T01 validation commands passed:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: 97 tests
  passed.
- `python -B -m unittest discover -s tests -p "test_wave19_gate.py"`: 12 tests
  passed.
- `python -B scripts/check_wave19_gate.py`: passed.
- `python -B scripts/check_competition_matrix_gate.py`: passed.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`:
  passed after rerun outside the sandbox because the Windows Go build cache was
  denied under sandboxed execution.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`: passed
  after rerun outside the sandbox for the same Go build-cache access issue.
- `timeout 300 make wave19-gate`: passed through WSL with temporary `/tmp`
  shims mapping `python` to `python3` and `go` to the Windows Go 1.24.2 binary,
  because native Windows `make` was unavailable and WSL's default Go was
  `go1.18 gccgo`.

## 6. Documentation Updated

- Vulnerability matrix documents the implemented AML-1 exploit and keeps the
  AML-1 fix locked to Wave 24.
- Testing strategy documents `wave19-gate` and the exploit guardrails.
- Roadmap and waves mark Wave 19 implemented under review and keep Wave 20+
  locked.
- Risk register adds AML-1 reference exploit scope mitigation.
- Execution log records the Wave 19 implementation.
- Sploit README lists only `aml_dedup_preview.py` as implemented.

## 7. CTF Invariants Checked

- Checker PUT/GET remains unchanged for both places.
- CHECK/HAVOC remains unchanged.
- Public attack data remains credential-free.
- The exploit uses side-view behavior only and does not require owner
  credentials or private checker state.
- No direct database dependency appears in the exploit.

## 8. Security Invariants Checked

- The exploit is limited to the intended AML-1 merge-preview path.
- No service leak, debug/admin endpoint, broad serializer, EDD leak, audit
  leak, graph leak, export leak, network-room leak, credential leak, session
  leak, or checker-private-state exposure was introduced.

## 9. Self-Review

The implementation keeps the exploit outside checker code, uses only normal
HTTP product APIs, validates the public place 1 attack-data shape, and avoids
importing product packages or database drivers. The gate rejects later exploit
files and all fix artifacts.

## 10. Risks / Open Questions

The exploit expects the vulnerable service to return a recognizable flag-like
token in the leaked private note body. Wave 24 remains responsible for the
reference fix and exploit-blocked evidence.

## 11. Ready for Orchestrator Review

Yes.
