# W20-T02 Handoff - Wave 20 Exploit Gate and Competition Matrix

## 1. Summary

Wave 20 validation now accepts exactly the AML-1 and AML-2 reference exploits,
keeps AML-3 through AML-5 exploit scripts locked, rejects all reference fix
artifacts beyond `fixes/sentinel_aml/README.md`, and makes the AML-2
exploit-success matrix cell concrete. Wave 20 is not marked accepted by this
handoff.

## 2. Implementation Details

- Strengthened `scripts/check_wave20_gate.py` to require both accepted exploit
  scripts, reject later exploit scripts and fixes, scan the AML-2 exploit for
  forbidden DB/shell/debug/admin/checker-private primitives, require import-safe
  CLI structure, require W20 handoff evidence, and require `wave20-gate`.
- Updated `scripts/check_competition_matrix_gate.py` so AML-1 and AML-2
  exploit-success cells are concrete while AML-2 fix cells and AML-3 through
  AML-5 exploit/fix cells remain pending.
- Added `wave20-gate` to the Makefile with checker tests, Wave 20 tests,
  competition matrix tests, exploit py_compile checks, Go test/vet, Wave 20
  gate, matrix gate, docs tree, and ForcAD validator.

## 3. Files Changed

- `scripts/check_wave20_gate.py`
- `tests/test_wave20_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/wave_reports/wave_20_W20-T02_handoff.md`

## 4. Tests Added

- Wave 20 gate rejects missing AML-2 exploit files.
- Wave 20 gate rejects later AML-3 through AML-5 exploit files.
- Wave 20 gate rejects reference fix artifacts.
- Wave 20 gate rejects direct DB, shell, owner note route, public secret lookup,
  and import-time execution markers.
- Competition matrix tests now require AML-2 exploit-success evidence and keep
  AML-2 fix cells pending.
- Wave 20 gate requires the `wave20-gate` Makefile closure target.

## 5. Tests Run

Executed locally on Windows PowerShell from
`C:\Users\2005g\GolandProjects\Sentinel_AML`:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave20_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
timeout 300 make wave20-gate
```

Results:

| Command | Result |
| --- | --- |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; pass; 97 tests |
| `python -B -m unittest discover -s tests -p "test_wave20_gate.py"` | exit 0; pass; 12 tests |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; pass; 21 tests |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...` | initial sandbox run hit Windows Go cache access denied under `AppData\Local\go-build`; rerun outside sandbox exited 0 and passed |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` | initial sandbox run hit Windows Go cache access denied under `AppData\Local\go-build`; rerun outside sandbox exited 0 and passed |
| `timeout 300 make wave20-gate` | exit 0; pass via WSL `/usr/bin/make` with temporary `/tmp/w20gate-bin/python` and `/tmp/w20gate-bin/go` shims for this Windows host |

Additional component checks run by `wave20-gate` also passed:

- `python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py`
- `python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py`
- `python -B scripts/check_wave20_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_docs_tree.py`
- `python -B scripts/validate_forcad_config.py`

## 6. Documentation Updated

This handoff records Wave 20 validation and matrix evidence. No status ledger
marks Wave 20 accepted.

## 7. CTF Invariants Checked

- Both checker flag stores remain active.
- CHECK/HAVOC coverage remains in the Wave 20 gate wrapper.
- Reference exploits remain outside the checker.
- Public attack data remains credential-free.
- Fixes remain locked and README-only.

## 8. Security Invariants Checked

- AML-2 remains scoped to audit timeline/diff exposure only.
- AML-3 graph, AML-4 export, and AML-5 network-room exploit paths remain
  locked.
- No runtime/debug/admin variant toggle was added.

## 9. Self-Review

The validation layer now matches the Wave 20 acceptance shape: exactly two
exploit scripts, no fixes, AML-2 exploit-success concrete, and all later
exploit/fix cells pending. The gate checks static exploit hygiene and relies on
the W20-T01 fake-service tests for vulnerable and secure response behavior.

## 10. Risks / Open Questions

Full wrapper execution depends on local availability of `make`, Go, and the
same cache permissions used by prior wave gates. Any host-specific toolchain
issue should be treated separately from matrix semantics.

## 11. Ready for Orchestrator Review

Yes. Wave 20 gate and competition matrix validation are ready for orchestrator
review; Wave 20 is not marked accepted by this handoff.
