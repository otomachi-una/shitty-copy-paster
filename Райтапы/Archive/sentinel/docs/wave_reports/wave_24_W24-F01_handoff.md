# W24-F01 Handoff - Stabilize Wave 24 Aggregate Gate Liveness

## 1. Summary

Stabilized the Wave 24 aggregate gate by making its release/offline Go test
step isolated, serialized, uncached, and explicitly bounded. Product behavior,
checker behavior, reference exploits, and the AML-1 patch semantics were not
changed.

## 2. Root Cause

The orchestrator hang occurred after `make wave24-gate` reached the
release/offline `go test ./...` recipe. That recipe used shared
`${TMPDIR:-/tmp}/sentinel-aml-gocache` and
`${TMPDIR:-/tmp}/sentinel-aml-appdata` paths and had no Go-level timeout or
package-serialization guard. Standalone component runs passed, so the liveness
failure was isolated to aggregate gate execution shape rather than AML behavior.

## 3. Implementation Details

- Updated `GO_RELEASE_ENV` to allocate unique temporary `GOCACHE` and `APPDATA`
  paths with `mktemp -d` for release/offline gate commands.
- Updated `wave24-gate` to run `go test -p 1 -timeout 120s -count=1 ./...`.
- Updated `scripts/check_wave24_gate.py` so the static gate requires the
  bounded Wave 24 Go test line and unique release cache/appdata markers.
- Added Wave 24 gate tests that reject the old unbounded `go test ./...` line
  and reject shared release cache paths.

## 4. Files Changed

- `Makefile`
- `scripts/check_wave24_gate.py`
- `tests/test_wave24_gate.py`
- `docs/wave_reports/wave_24_validation_summary.md`
- `docs/wave_reports/wave_24_W24-F01_handoff.md`

## 5. Tests Added or Updated

- Added `test_makefile_target_rejects_unbounded_go_test_step`.
- Added `test_makefile_target_requires_unique_release_cache_paths`.
- Updated Wave 24 Makefile coverage expectations to require the bounded,
  serialized Go test command.

## 6. Tests Run

- `python -B -m unittest discover -s tests -p "test_wave24_gate.py"`: exit 0;
  17 tests passed.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 28 tests passed.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: exit 0;
  97 tests passed.
- `python -B scripts\check_wave24_gate.py`: exit 0; status `pass`.
- `python -B scripts\check_competition_matrix_gate.py`: exit 0; status `pass`.
- `python -B scripts\check_archive_hygiene.py`: exit 0; status `pass`.
- `python -B scripts\check_docs_tree.py`: exit 0; status `pass`.
- `python -B scripts\validate_forcad_config.py`: exit 0.
- No-repo-cache `py_compile` for all five exploits: exit 0.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch`:
  exit 0.
- Release/offline no-repo-cache `go test -p 1 -timeout 120s -count=1 ./...`:
  exit 0.
- Release/offline no-repo-cache `go vet ./...`: exit 0.
- Exact aggregate wrapper evidence remains pending on a POSIX make-equipped
  review host. Local `bash.exe -lc "timeout 300 make wave24-gate"` exited 1
  because WSL bash startup returned `E_ACCESSDENIED`.
- `where.exe make`: exit 1; no local `make` executable is installed on this
  Windows host.

## 7. Documentation Updated

Updated `docs/wave_reports/wave_24_validation_summary.md` with W24-F01
gate-liveness evidence and created this handoff report.

## 8. CTF Invariants Checked

- Checker PUT/GET behavior for both places was not changed.
- Strong CHECK/HAVOC remains part of `wave24-gate` through checker tests.
- The AML-1 fix artifact remains AML-1-only and still preserves dedup and
  merge-preview behavior.
- AML-2 through AML-5 fix artifacts remain absent.
- No checker DB shortcut, debug endpoint, or hidden backdoor was introduced.

## 9. Security Invariants Checked

- `CaseNote.body` fixed-profile visibility remains governed by the AML-1 patch,
  not by this liveness change.
- Merge-preview remains documented and gated as public-only.
- No sensitive fields were added to logs, audit side views, graph views,
  exports, or network-room dossiers.

## 10. Self-Review

The change is intentionally confined to gate liveness. I did not edit product
source behavior, checker behavior, public attack data, reference exploits, or
AML-2 through AML-5 fix artifacts. The updated static gate now prevents a
regression to the exact unbounded aggregate Go test line that timed out.

## 11. Risks / Open Questions

- The exact `timeout 300 make wave24-gate` command could not be executed on
  this local Windows host because `make` is not installed and WSL bash startup
  is denied. The Makefile semantics are prepared for the orchestrator's POSIX
  make host.
- If a future Go test itself deadlocks, the new `-timeout 120s` will fail fast
  inside Go instead of waiting for the outer 300-second wrapper.

## 12. Ready for Orchestrator Review

Yes.
