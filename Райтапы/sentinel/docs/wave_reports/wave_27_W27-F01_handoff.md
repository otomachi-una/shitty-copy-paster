# Wave 27 W27-F01 Handoff

## 1. Summary

W27-F01 stabilizes the Wave 27 aggregate gate liveness path by replacing the
Go release runner's `subprocess.run(..., capture_output=True)` wrapper with an
owned `Popen` runner. The runner now creates a process group on POSIX and a
kill-on-close Job Object on Windows where available, terminates child process
trees on timeout, returns non-zero on package timeout/failure, and keeps package
names flushed before each package test.

No product behavior, checker behavior, exploit script, public attack-data
schema, or AML-1 through AML-4 patch semantics changed. AML-5 remains absent
from the fix inventory.

## 2. Implementation Details

- Updated `scripts/run_go_release_tests.py` to run commands with `Popen`,
  stdout/stderr reader threads, explicit deadline polling, and process-tree
  cleanup.
- Added Windows Job Object cleanup with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; if Job Object assignment is unavailable,
  the runner falls back to `taskkill /T /F` and then process kill.
- Added POSIX process-group cleanup using `start_new_session=True` and
  `os.killpg`.
- Preserved release/offline environment injection:
  `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, `GOTELEMETRY=off`, and per-command
  temporary `GOCACHE`/`APPDATA`.
- Added `tests/test_run_go_release_tests.py` with bounded stuck-process and
  package-timeout regression coverage.
- Added the runner regression test to `wave27-gate` and to
  `scripts/check_wave27_gate.py` static Makefile expectations.

## 3. Files Changed

- `scripts/run_go_release_tests.py`
- `tests/test_run_go_release_tests.py`
- `tests/test_wave27_gate.py`
- `scripts/check_wave27_gate.py`
- `Makefile`
- `docs/wave_reports/wave_27_W27-F01_handoff.md`

## 4. Tests Added

- `test_run_command_times_out_and_cleans_up_process_group`: verifies a sleeping
  process tree returns through `TimeoutExpired` in under 5 seconds.
- `test_release_runner_reports_stuck_package_as_bounded_failure`: verifies
  `run_release_tests` reports a stuck package as exit code 1 with the package
  name in diagnostics.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"`
  - Exit code: 0
  - Result: 2 tests passed.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`
  - Exit code: 0
  - Result: 97 tests passed.
- `python -B -m unittest discover -s tests -p "test_wave27_gate.py"`
  - Exit code: 0
  - Result: 23 tests passed.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`
  - Exit code: 0
  - Result: 31 tests passed.
- `python -B scripts/check_wave27_gate.py`
  - Exit code: 0
  - Result: pass.
- `python -B scripts/check_competition_matrix_gate.py`
  - Exit code: 0
  - Result: pass.
- `python -B scripts/check_docs_tree.py`
  - Exit code: 0
  - Result: pass.
- `python -B scripts/validate_forcad_config.py`
  - Exit code: 0
  - Result: `config.yml ForcAD shape is valid`.
- `python -B scripts/check_archive_hygiene.py`
  - Exit code: 0
  - Result: pass.
- `python -B scripts/run_go_release_tests.py --go go --package-timeout 120`
  - Exit code: 0
  - Result: all Go packages passed package-by-package with streamed package
    markers.
- Windows-compatible no-repo-cache release/offline `go test ./...`
  - Command used: `$env:GOTOOLCHAIN='local'; $env:GOFLAGS='-mod=vendor';
    $env:GOTELEMETRY='off'; $env:GOCACHE=...; $env:APPDATA=...; go test ./...`
  - Exit code: 0
  - Result: all Go packages passed.
- Windows-compatible no-repo-cache release/offline `go vet ./...`
  - Command used: `$env:GOTOOLCHAIN='local'; $env:GOFLAGS='-mod=vendor';
    $env:GOTELEMETRY='off'; $env:GOCACHE=...; $env:APPDATA=...; go vet ./...`
  - Exit code: 0
  - Result: no vet findings.
- No-repo-bytecode exploit compile:
  - Command: `python -B -m py_compile` for all five exploit scripts with
    `PYTHONPYCACHEPREFIX` under `%TEMP%`.
  - Exit code: 0.
- `git apply --check --whitespace=error` for AML-1 through AML-4 patches
  - Exit code: 0 for each patch.
- `timeout 300 make wave27-gate`
  - Exit code: 1 on this Windows host before project code executed.
  - Local reason: Windows `timeout.exe` rejected GNU-style syntax:
    `Invalid syntax. Default option is not allowed more than '1' time(s).`
- `make wave27-gate`
  - Exit code: 1 on this Windows host before project code executed.
  - Local reason: `make` is not installed on PATH.
- `bash -lc "cd /mnt/c/Users/2005g/GolandProjects/Sentinel_AML && timeout 300 make wave27-gate"`
  - Exit code: 1 on this Windows host before project code executed.
  - Local reason: WSL startup failed with
    `Bash/Service/CreateInstance/E_ACCESSDENIED`.
- Raw Windows `go test ./...` with only `GOTOOLCHAIN`, `GOFLAGS`, and
  `GOTELEMETRY` set
  - Exit code: 1.
  - Local reason: sandboxed host denied default Go telemetry/cache paths. The
    no-repo-cache release/offline form passed.

## 6. Documentation Updated

- Created this W27-F01 handoff with exact command evidence, exit codes, root
  cause, and runner behavior changes.

## 7. CTF Invariants Checked

- Checker PUT/GET logic was not edited.
- Strong CHECK/HAVOC remains in the aggregate Wave 27 gate path.
- AML-1 through AML-4 fix artifacts remain concrete and unchanged.
- AML-5 fix artifact remains absent and locked.
- No hidden debug endpoint, direct DB checker dependency, or public attack-data
  schema change was introduced.

## 8. Security Invariants Checked

- AML-4 export/dispute behavior and patch semantics were not changed.
- No private fields, credentials, raw audit diffs, hashes, sessions, or
  checker-private state were added to any service output.
- The runner change affects only local gate execution and child-process cleanup.

## 9. Self-Review

The non-termination root cause is runner/process infrastructure: the old
`subprocess.run(..., capture_output=True, timeout=...)` path bounds the direct
Go command, but it can leave descendant processes or inherited output handles
outside reliable cleanup. That is fragile for aggregate gates because one
stalled package test can keep the gate alive without clear package-level
diagnostics.

The new runner owns the launched command lifetime, prints the package under
test before running it, enforces a wall-clock parent timeout, and tears down the
process tree on timeout. Existing fake-runner injection remains compatible with
Wave 27 tests.

## 10. Risks / Open Questions

- The exact GNU-style `timeout 300 make wave27-gate` command could not be run on
  this Windows host because GNU `timeout`/`make` are unavailable and WSL is
  blocked. The fixed runner and all target-equivalent steps passed locally; the
  exact wrapper must be re-run by the POSIX orchestrator environment.
- Windows Job Object assignment can fail under unusual nested-job policies; the
  runner falls back to `taskkill /T /F` in that case.

## 11. Ready for Orchestrator Review: yes

The repository-side liveness fix and regression evidence are complete. The
remaining exact aggregate command verification is environment-specific and
should be performed by the orchestrator host that provides GNU `timeout` and
`make`.
