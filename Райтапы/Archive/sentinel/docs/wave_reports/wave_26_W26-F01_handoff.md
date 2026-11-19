# W26-F01 Handoff - Wave 26 Aggregate Gate Liveness Stabilization

## 1. Summary

Stabilized the Wave 26 aggregate gate by replacing the opaque all-package Go
test step with a deterministic package-by-package release/offline runner. Wave
26 remains implemented under review; this handoff does not mark it accepted or
unlock Wave 27.

## 2. Implementation Details

- Added `scripts/run_go_release_tests.py`.
- The helper runs `go list ./...`, sorts packages, prints each package before
  testing, and then runs every package individually with `GOTOOLCHAIN=local`,
  `GOFLAGS=-mod=vendor`, `GOTELEMETRY=off`, isolated temporary `GOCACHE` and
  `APPDATA`, `go test -timeout 120s -count=1`, and an outer per-package timeout.
- Updated only the `wave26-gate` Go test line in `Makefile`.
- Updated `scripts/check_wave26_gate.py` so Wave 26 rejects the old opaque Go
  test line and requires the helper.
- Added Wave 26 tests proving the Makefile invokes the helper and that the
  helper preserves deterministic package coverage.

## 3. Files Changed

- `Makefile`
- `scripts/check_wave26_gate.py`
- `scripts/run_go_release_tests.py`
- `tests/test_wave26_gate.py`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/source_of_truth_map.md`
- `docs/waves.md`
- `docs/wave_reports/wave_26_validation_summary.md`
- `docs/wave_reports/wave_26_W26-F01_handoff.md`

## 4. Tests Added

- Added a Wave 26 Makefile coverage test requiring
  `scripts/run_go_release_tests.py`.
- Added a runner unit test proving package sorting, per-package invocation,
  release/offline environment, isolated cache/appdata paths, and timeout
  propagation.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_wave26_gate.py"`:
  exit 0; 22 tests passed.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 30 tests passed.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`:
  exit 0; 97 tests passed.
- No-repo-cache `python -B -m py_compile` for all five Sentinel AML exploits
  and `scripts/run_go_release_tests.py`: exit 0.
- `python -B scripts/check_wave26_gate.py`: exit 0; status `pass`.
- `python -B scripts/run_go_release_tests.py --go go --package-timeout 120`:
  exit 0.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0; status
  `pass`.
- `python -B scripts/check_docs_tree.py`: exit 0; status `pass`.
- `python -B scripts/validate_forcad_config.py`: exit 0.
- `python -B scripts/check_archive_hygiene.py`: exit 0; status `pass`.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch`:
  exit 0.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_audit_timeline.patch`:
  exit 0.
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_related_graph.patch`:
  exit 0.
- Release/offline no-repo-cache `go vet ./...`: exit 0.
- Raw local `go vet ./...`: exit 1 because default Windows Go telemetry/cache
  paths were access denied; release/offline no-repo-cache vet passed.
- Intermediate `python -B scripts/check_archive_hygiene.py`: exit 1 after raw
  local py-compile created generated `__pycache__` directories; those generated
  caches were removed and the final archive-hygiene run passed.
- Local `timeout 300 make wave26-gate`: exit 1 before invoking project code
  because Windows `timeout.exe` does not execute commands.
- Local `make wave26-gate`: exit 1 because no make-compatible executable is
  installed on PATH.

## 6. Documentation Updated

- Updated the Wave 26 validation summary with W26-F01 evidence.
- Updated testing strategy, roadmap, waves, source-of-truth map, risk register,
  and execution log to describe the package-by-package runner and retained
  under-review status.

## 7. CTF Invariants Checked

- Both checker places remain active in the gate.
- Place 1 GET remains owner case-note API only.
- Place 2 GET remains owner EDD API only.
- CHECK/HAVOC remains release-blocking through checker tests.
- Public attack data remains credential-free.
- All five reference exploits remain present and importable.
- AML-1, AML-2, and AML-3 fixes remain checkable.
- AML-4 and AML-5 fixes remain absent.

## 8. Security Invariants Checked

- No product, checker, exploit, or fix patch semantics were changed.
- No debug/admin routes, direct DB shortcuts, product shell helpers, broad
  domain-model serialization, graph-side confidential comments, case-note
  bodies, audit diffs, hashes, credentials, sessions, or checker-private state
  were introduced.

## 9. Self-Review

The liveness fix is scoped to the Wave 26 aggregate gate and its validation.
The new runner preserves all package coverage from `go test ./...` by deriving
packages from `go list ./...`, while making future stalls bounded and
diagnosable by package. The existing checker, exploit, matrix, docs, ForcAD,
archive, patch-apply, and Go vet checks remain in the gate.

## 10. Risks / Open Questions

- Exact `timeout 300 make wave26-gate` still needs re-review on a POSIX or
  make-equipped orchestrator host; this Windows host lacks GNU `timeout`
  semantics and a `make` executable.
- Local generated Python bytecode caches were removed after the raw compile
  check; final archive hygiene passes.
- Wave 26 remains under review until orchestrator acceptance.
- Wave 27 remains locked until that acceptance occurs.

## 11. Ready for Orchestrator Review

Yes.
