# Wave 15 Validation Summary

## Scope Validated

Wave 15 introduces the AML-2 vulnerable audit timeline profile under the
`aml2_vulnerable` Go build tag. The default build remains the secure redacted
audit timeline profile. The tagged profile exposes only owner `CaseNote.body`
through `case_note.body` timeline change projection.

W15-F02 reconciliation marks Wave 15 as `needs fixes` in the roadmap and wave
ledger until the orchestrator re-runs `make wave15-gate` after W15-F01 and
accepts the result. `docs/09_vulnerability_matrix.md` remains the vulnerability
behavior source of truth, and the AML-2 exploit and fix stay scheduled for
future waves.

W15-F01 fixes the checker discovery liveness class reproduced by the
orchestrator. The checker fake HTTP services now close server sockets during
teardown before waiting on their serving threads, accepted fake-service sockets
have bounded read timeouts, and Wave 15 has its own subprocess regression that
runs full checker unittest discovery and fails if it prints `OK` but does not
return control.

## Commands Run

The W15-F01 validation set was run on Windows PowerShell from
`C:\Users\2005g\GolandProjects\Sentinel_AML`. Go commands used
`GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, `GOTELEMETRY=off`, and
workspace-local `GOCACHE`/`APPDATA` directories (`.gocache`, `.appdata`) to
avoid user-global cache/telemetry writes.

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave15_gate.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml2_vulnerable ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave15_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/validate_forcad_config.py
make wave15-gate
```

Results:

| Command | Result |
| --- | --- |
| `python -B -m unittest discover -s tests -p "test_checker_*.py"` | exit 0; pass; 97 tests in 4.793s; returned to shell |
| `python -B -m unittest discover -s tests -p "test_wave15_gate.py"` | exit 0; pass; 8 tests in 5.337s, including full checker discovery subprocess liveness regression |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...` | exit 0; pass |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml2_vulnerable ./...` | exit 0; pass |
| `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...` | exit 0; pass |
| `python -B scripts/check_docs_tree.py` | exit 0; pass |
| `python -B scripts/check_wave15_gate.py` | exit 0; pass |
| `python -B scripts/check_competition_matrix_gate.py` | exit 0; pass |
| `python -B scripts/validate_forcad_config.py` | exit 0; pass |
| `make wave15-gate` | exit 1 on this Windows host because `make` is not installed on PATH. `Get-Command make,make.exe,gmake,mingw32-make,nmake,bash` found only `bash.exe`; earlier `bash -lc "make wave15-gate"` failed with WSL access denied. The `wave15-gate` Makefile target is present and validated by `scripts/check_wave15_gate.py`, and its component commands above passed directly. A POSIX or make-equipped reviewer host must rerun this wrapper command for final closure evidence. |

W15-F02 reconciliation checks were run after updating the active status
ledgers:

| Command | Result |
| --- | --- |
| `python -B scripts/check_docs_tree.py` | exit 0; pass |
| `python -B scripts/check_wave15_gate.py` | exit 0; pass |
| `python -B scripts/check_competition_matrix_gate.py` | exit 0; pass |

Current review evidence:

- Wave 13 remains `needs fixes`; `docs/wave_reports/wave_13_review.md`
  requires an accepted orchestrator rerun of `make wave13-gate`.
- Wave 14 remains under review; this snapshot has Wave 14 validation and
  handoff reports but no accepted `docs/wave_reports/wave_14_review.md`
  artifact.
- Wave 15 remains `needs fixes` until orchestrator re-review accepts
  `make wave15-gate` after W15-F01.
- Wave 16 is execution-blocked until Wave 15 liveness re-review passes.

## CTF Invariants

- Checker PUT/GET owner paths for both flag stores remain unchanged.
- AML-2 is local to the `aml2_vulnerable` audit timeline profile.
- Public attack data remains credential-free and raw-flag-free.
- No reference exploit or reference fix artifact exists for AML-2.
- AML-3 through AML-5 remain locked.

## Security Invariants

- Default audit timeline responses remain redacted.
- AML-2 does not expose `EDDRecord.confidential_comment`.
- Graph, export, and network-room projections are not broadened by AML-2.
- No debug/admin runtime toggle or direct DB checker path was added.

## Known Gaps

- AML-2 reference exploit and reference fix remain future work.
- Customer/entity activity routes remain absent; AML-2 currently targets the
  implemented owner case timeline endpoint.
- The literal `make wave15-gate` wrapper could not be executed on this Windows
  host because no make-compatible executable is available on PATH. Component
  commands and Makefile target contents were validated directly.

## Status

W15-F01 checker discovery liveness is fixed and validated locally. Wave 15 is
`needs fixes` until orchestrator re-review proves the exact `make wave15-gate`
wrapper exits 0. This Windows host cannot run the wrapper because `make` is not
installed, so final closure requires rerunning it on a make-equipped POSIX or
equivalent review environment. Wave 16 remains execution-blocked until that
review passes.
