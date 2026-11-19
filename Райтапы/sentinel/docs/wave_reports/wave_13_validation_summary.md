# Wave 13 Validation Summary

## Scope Validated

Wave 13 validates the active two-place checker after Wave 12 and adds strong
CHECK/HAVOC coverage for business modules. The gate covers:

- place 1 PUT/GET through owner case-note APIs;
- place 2 PUT/GET through owner EDD APIs;
- CHECK/HAVOC dispatcher and failure redaction;
- basic, case-note, dedup, audit, graph, export, network-room, and retention
  subchecks;
- optional `putnoise`/`getnoise` parsing and safety tests;
- docs tree and ForcAD config shape;
- no early exploit or reference-fix implementation files;
- no current vulnerable behavior markers in product/checker/migration sources.

## Commands Run

W13-F01 reran the Wave 13 gate after fixing checker test-resource
lifecycle cleanup. The root cause was the fake checker HTTP services using
`ThreadingHTTPServer` with HTTP/1.1 keep-alive but without daemon request
threads or explicit connection close semantics. In orchestrator-like unittest
discovery this could leave handler threads alive after successful test dots and
prevent interpreter exit.

```sh
python -B -m unittest discover -s tests -p "test_checker_resource_lifecycle.py"
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave13_gate.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave13_gate.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_competition_matrix_gate.py
make wave13-gate
```

W13-F01 local result:

- `test_checker_resource_lifecycle.py`: pass, 2 tests.
- `test_checker_*.py`: pass, 97 tests, exited cleanly.
- `test_wave13_gate.py`: pass, 9 tests.
- `go test ./...`: pass when rerun with the Makefile's workspace-local
  `GOCACHE` and `APPDATA` settings; the initial direct PowerShell run without
  those writable paths failed on sandbox access to the default Windows Go cache
  and telemetry token directory.
- `go vet ./...`: pass when rerun with the Makefile's workspace-local
  `GOCACHE` and `APPDATA` settings; the initial direct PowerShell run without
  those writable paths failed on the same sandbox cache path.
- `check_docs_tree.py`: pass.
- `check_wave13_gate.py`: pass, overall status `pass`.
- `validate_forcad_config.py`: pass.
- `check_competition_matrix_gate.py`: pass.
- `make wave13-gate`: not runnable on this Windows host because no
  `make`, `mingw32-make`, or `nmake` executable is installed. The target
  remains wired in `Makefile`, and the component commands above passed.

Orchestrator close condition: rerun `make wave13-gate` in an environment with
`make` installed and record successful process exit. Wave 13 remains
`needs fixes` until that orchestrator gate completes.

Additional component commands used during Wave 13 closure:

```sh
python -B -m unittest discover -s tests -p "test_checker_foundation.py"
python -B -m unittest discover -s tests -p "test_checker_check_workflow.py"
python -B -m unittest discover -s tests -p "test_checker_*.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
```

Result: pass during W13-T01 through W13-T06 validation runs. W13-F01 supersedes
the latest checker-pattern count with 97 tests, including lifecycle cleanup
coverage.

`make wave13-gate` is wired in the Makefile. On this Windows shell, `make` may
be unavailable; on this host `make wave13-gate` could not start because `make`
is not installed. The direct component commands above are the equivalent gate
commands.

## CTF Invariants

- Checker traffic uses normal product HTTP APIs only.
- Place 1 remains `CaseNote.body`; place 2 remains
  `EDDRecord.confidential_comment`.
- Owner PUT/GET paths remain green and do not use side views for flag recovery.
- CHECK/HAVOC verifies business modules so teams cannot pass by disabling
  customer/account/transaction, notes, dedup, audit, graph, export, or
  network-room features.
- No planned vulnerable behavior is active yet.
- No reference exploit or reference-fix implementation is active yet.

## Security Invariants

- Public attack data remains credential-free and raw-flag-free.
- Private checker state remains MAC-protected and separate from public attack
  data.
- Checker errors redact flags, credentials, tokens, secrets, and private state.
- No debug/admin/checker-only endpoints or direct DB checker path are used.
- Side-view DTOs used by CHECK/HAVOC are validated as public/redacted only.

## Known Gaps

- Live deployment timing for async-like observations, especially network-room
  materialization, remains an integration concern for future full environment
  gates.
- Historical pre-Wave-12 gates may still encode older place-2 deferral
  expectations and should be treated as historical branch gates.

## Status

Wave 13 is implemented and W13-F01 fixes the checker discovery liveness
blocker, but the wave remains `needs fixes` until the orchestrator reruns and
accepts `make wave13-gate`. Wave 14 through Wave 18 AML vulnerability vertical
slices remain blocked until Wave 13 acceptance.
