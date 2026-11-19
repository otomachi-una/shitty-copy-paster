# W21-T02 Handoff - Wave 21 Gate and Competition Matrix Update

## 1. Summary

Added Wave 21 validation for the AML-3 related graph reference exploit. The
branch now expects exactly three Sentinel AML reference exploits:
`aml_dedup_preview.py`, `aml_audit_timeline.py`, and `aml_related_graph.py`.
AML-4 and AML-5 exploit-success cells remain pending, and all reference fix
cells remain pending.

## 2. Implementation Details

- Added `scripts/check_wave21_gate.py` with JSON output and non-zero failure
  status.
- The Wave 21 gate requires exactly AML-1, AML-2, and AML-3 exploit scripts.
- The gate rejects AML-4/AML-5 exploit scripts and any reference fix artifact
  beyond `fixes/sentinel_aml/README.md`.
- The gate statically checks AML-3 CLI/import-safe shape and graph EDD summary
  scope.
- The gate rejects direct DB, SQL, shell/subprocess, debug/admin, owner EDD,
  case-note, audit timeline, export, network-room, credential, and
  checker-private markers.
- Updated the competition matrix gate so AML-3 exploit-success is concrete via
  `sploits/sentinel_aml/aml_related_graph.py` and
  `scripts/check_wave21_gate.py`.
- Added `wave21-gate` to `Makefile` with checker tests, Wave 21 tests, matrix
  tests, py_compile for all three exploit scripts using the no-repo cache
  prefix, Go test/vet, Wave 21 gate, competition matrix gate, docs tree,
  ForcAD validation, and archive hygiene.

## 3. Files Changed

- `scripts/check_wave21_gate.py`
- `tests/test_wave21_gate.py`
- `scripts/check_competition_matrix_gate.py`
- `tests/test_competition_matrix_gate.py`
- `Makefile`
- `docs/wave_reports/wave_21_W21-T02_handoff.md`

## 4. Tests Added

- Added Wave 21 gate tests for current-branch pass, missing AML-3 exploit,
  later exploit presence, premature fix artifacts, forbidden primitives,
  public attack-data secret lookup, import-time execution, and Makefile target
  closure.
- Updated competition matrix tests for exactly three exploit artifacts, AML-3
  exploit-success concrete evidence, AML-4/AML-5 pending state, and all fix
  cells pending.

## 5. Tests Run

Executed locally on Windows PowerShell from
`C:\Users\2005g\GolandProjects\Sentinel_AML`:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave21_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py
python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py
python -B -m py_compile sploits/sentinel_aml/aml_related_graph.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
timeout 300 make wave21-gate
```

Results:

| Command | Result |
| --- | --- |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; 97 tests passed |
| `python -B -m unittest discover -s tests -p "test_wave21_gate.py"` | exit 0; 14 tests passed |
| `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` | exit 0; 23 tests passed |
| `python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py` | exit 0 |
| `python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py` | exit 0 |
| `python -B -m py_compile sploits/sentinel_aml/aml_related_graph.py` | exit 0 |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...` | exit 0 via PowerShell-equivalent env assignment with `GOCACHE` and `APPDATA` under `$env:TEMP` |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` | exit 0 via PowerShell-equivalent env assignment with `GOCACHE` and `APPDATA` under `$env:TEMP` |
| `python -B scripts/check_wave21_gate.py` | exit 0; pass |
| `python -B scripts/check_competition_matrix_gate.py` | exit 0; pass |
| `python -B scripts/check_docs_tree.py` | exit 0; pass |
| `python -B scripts/validate_forcad_config.py` | exit 0; `config.yml ForcAD shape is valid` |
| `python -B scripts/check_archive_hygiene.py` | exit 0; pass |
| `timeout 300 make wave21-gate` | exit 1 in this Windows PowerShell environment because `timeout` resolves to `C:\Windows\System32\timeout.exe`, which rejects POSIX syntax |
| `make wave21-gate` | exit 1 in this Windows PowerShell environment because `make` is not installed in PATH |

Additional environment probe:

| Probe | Result |
| --- | --- |
| `where.exe make` | exit 1; no `make` in PATH |
| `where.exe timeout` | exit 0; only `C:\Windows\System32\timeout.exe` found |
| `bash --version` | exit 1; WSL/bash startup failed with `E_ACCESSDENIED` |

The Makefile target itself is present and is statically enforced by
`scripts/check_wave21_gate.py`. It uses `PYTHONPYCACHEPREFIX`, `GOCACHE`, and
`APPDATA` outside the repository so the aggregate gate can run without leaving
archive-hygiene artifacts in a make-capable POSIX environment.

## 6. Documentation Updated

- Added this W21-T02 validation handoff.
- Wave 21 remains not accepted; orchestrator review owns acceptance.

## 7. CTF Invariants Checked

- Matrix now treats AML-1, AML-2, and AML-3 exploit-success as concrete only
  after their artifacts exist.
- AML-4 and AML-5 exploit scripts remain locked.
- All reference fixes remain locked and README-only.
- Exploits remain outside checker code.

## 8. Security Invariants Checked

- Forbidden primitive scans remain active for DB, SQL, shell/subprocess,
  debug/admin, credential, checker-private, and wrong-side-view markers.
- AML-3 remains scoped to related graph EDD summary exposure only.

## 9. Self-Review

The validation additions layer Wave 21 on top of the accepted Wave 20 state
without modifying product or checker code. Existing AML-1/AML-2 evidence remains
required, AML-3 evidence becomes concrete, and later exploit/fix waves remain
blocked by explicit file checks.

## 10. Risks / Open Questions

- W21-T03 still needs to add the documentation/status validation summary and
  align status ledgers without marking Wave 21 accepted.
- The Wave 21 gate intentionally supersedes the Wave 20 two-exploit snapshot;
  older Wave 20 artifact-count gates are no longer expected to pass after AML-3
  is introduced.
- Exact `timeout 300 make wave21-gate` evidence still needs to be collected in
  an environment with GNU/coreutils `timeout` and `make` available.
- W21-T02 file scope does not include creating the W21-T03 handoff or Wave 21
  validation summary, so the T02 gate checks T01/T02 handoff evidence and leaves
  T03 documentation closure to W21-T03.

## 11. Ready for Orchestrator Review

No for final acceptance, because this Windows PowerShell environment cannot run
the exact `timeout 300 make wave21-gate` wrapper. Component validation is green
and the Makefile target is ready for a make-capable orchestrator run. Wave 21 is
not marked accepted by this handoff.
