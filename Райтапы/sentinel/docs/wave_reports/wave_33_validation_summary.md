# Wave 33 Validation Summary

Status: ready for orchestrator review.

Wave 33 now has an archive-free regression gate for the packaging/productization
split. The gate validates player/admin candidate generation, player hygiene,
checker behavior, the five-sploit/five-fix matrix, vulnerable profile builds,
release-profile Go tests, `go vet`, service builds, docs-tree validation, and
ForcAD config validation. It does not build final release archives, player
release archives, final manifests, or checksum files.

## Gate Coverage

- Player-service candidate tree generation:
  `scripts/build_player_bundle.py --output-dir tmp/wave33-player-service-candidate
  --allowlist-out tmp/wave33-player-service-candidate.hygiene-allowlist.json`.
- Admin/checker candidate tree generation:
  `scripts/build_admin_bundle.py --output-dir tmp/wave33-admin-checker-candidate`.
- Strict repository-submission hygiene before any local candidate generation,
  followed by local-staging repository hygiene after candidate generation with
  `--allow-wave33-local-candidates`.
- Player hygiene scanner on the generated candidate and participant docs.
- Checker tests: both checker flag stores and CHECK/HAVOC inventory remain in
  `test_checker_*.py` discovery.
- Competition matrix: AML-1 through AML-5 vulnerable profile, sploit path, fix
  patch, exploit-blocked, checker-green, and CHECK/HAVOC evidence remains
  concrete.
- Sploit syntax/import checks for all five reference sploits.
- Fix patch checks for all five reference fixes using
  `git apply --check --whitespace=error`.
- Vulnerable profile runner for all five compatibility build tags.
- Release-profile Go package tests, `go vet ./...`, and
  `go build ./cmd/aml-api ./cmd/aml-worker`.
- `scripts/check_docs_tree.py` and `scripts/validate_forcad_config.py`.
- Cleanup of the known ignored Wave 33 generated candidate paths before the
  gate exits.

## Timing Evidence

- `/usr/bin/timeout 300 make wave33-gate` - exit 0 on 2026-09-10 through the
  WSL GNU-timeout/make path after W33-F05 repository-submission hygiene
  integration; Make selected `python3` and `go.exe`; host elapsed `139.731s`;
  `wave33-gate: pass elapsed=139.245s` across 28 bounded phases.
- `python -B -m unittest discover -s tests -p "test_wave33_gate.py"` - exit 0,
  9 tests in 2.655s after W33-F05 added phase-order and cleanup coverage.
- `python -B -m unittest discover -s tests -p "test_repository_submission_hygiene.py"` -
  exit 0, 6 tests in 0.053s.
- `python -B scripts/check_repository_submission_hygiene.py` - exit 0 on the
  cleaned repository workspace before local candidate staging; scanned 864
  members.
- `python -B scripts/check_repository_submission_hygiene.py --allow-wave33-local-candidates` -
  exit 0 after staging `tmp/wave33-player-service-candidate`,
  `tmp/wave33-player-service-candidate.hygiene-allowlist.json`, and
  `tmp/wave33-admin-checker-candidate`; scanned 1262 members.
- `/usr/bin/timeout 300 make wave33-gate` - exit 0 on 2026-09-10 through the
  WSL GNU-timeout/make path after W33-F04 process-tree cleanup hardening; Make
  selected `python3` and `go.exe`; host elapsed `157.304s`;
  `wave33-gate: pass elapsed=156.520s`.
- `python -B scripts/check_wave33_gate.py --run --go go --python python` -
  exit 0 on the Windows host after W33-F04; host elapsed `139.490s`;
  `wave33-gate: pass elapsed=139.281s`.
- `/usr/bin/timeout 300 make wave33-gate` - exit 0 on 2026-09-08 through the
  WSL GNU-timeout/make path after W33-F02/F03 updates; Make selected `python3`
  and `go.exe`; `wave33-gate: pass elapsed=99.817s`.
- `python -B scripts/check_wave33_gate.py --run --go go --python python` -
  exit 0 on the Windows host; `wave33-gate: pass elapsed=119.500s`.
- `python -B scripts/check_ad_stability_gate.py --run --go go --python python` -
  exit 0 on the Windows host; `ad-stability-gate: pass elapsed=109.812s`.
- `python -B scripts/check_wave29_gate.py` - exit 0 after retargeting
  historical fix-scope validators to the Wave 33 neutral source names.
- `python -B -m unittest discover -s tests -p "test_wave33_gate.py"` - exit 0,
  8 tests in 3.669s.
- `python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"` -
  exit 0, 5 tests in 0.825s after W33-F04 added orphaned-pipe cleanup
  regression coverage.
- `python -B -m unittest discover -s tests -p "test_run_vulnerable_profile_tests.py"` -
  exit 0, 4 tests in 0.010s.
- `python -B -m unittest discover -s tests -p "test_repository_submission_hygiene.py"` -
  exit 0, 6 tests in 0.022s.
- `python -B -m unittest discover -s tests -p "test_player_bundle_build.py"` -
  exit 0, 11 tests in 0.956s.
- `python -B -m unittest discover -s tests -p "test_player_bundle_hygiene.py"` -
  exit 0, 15 tests in 0.202s.
- `python -B -m unittest discover -s tests -p "test_archive_hygiene.py"` -
  exit 0, 14 tests in 0.139s after generated artifacts were cleaned from the
  repository workspace.
- `python -B scripts/check_repository_submission_hygiene.py` - exit 0 on the
  cleaned repository workspace; scanned 853 members.
- `python -B scripts/check_repository_submission_hygiene.py --allow-wave33-local-candidates` -
  exit 0 with generated Wave 33 candidates present; scanned 945 members.
- `python -B scripts/check_player_bundle_hygiene.py tmp/wave33-player-service-candidate --allowlist tmp/wave33-player-service-candidate.hygiene-allowlist.json --require-runtime-ready` -
  expected exit 1 for the current staged candidate: runtime readiness is not
  final and no successful runtime proof is recorded.
- `python -B -m unittest discover -s tests -p "test_player_bundle*.py"` -
  exit 0, 26 tests during the exact Wave 33 gate.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` -
  exit 0, 40 tests.
- `python -B scripts/check_competition_matrix_gate.py` - exit 0.

Environment note: non-escalated WSL access on this desktop host initially
failed before target execution with `Wsl/Service/CreateInstance/E_ACCESSDENIED`.
After running the exact command on the WSL review path, the first attempt
reached the gate but failed because one nested unit test invoked `python` while
the POSIX host exposed only `python3`. W33-F01 adds a temporary gate-local
`python` shim on child PATH when needed; no repository source, product
behavior, checker behavior, sploit behavior, or fix semantics changed for that
compatibility fix.

## Candidate Inventory

- Player-service candidate: 311 source/runtime/dependency files generated under
  `tmp/wave33-player-service-candidate`; hygiene scan passed across 385
  candidate members using the generated allowlist. The added
  `PACKAGING_STATUS.json` marks the tree as staged, not final, and not
  runtime-ready.
- Admin/checker candidate: 7 files generated under
  `tmp/wave33-admin-checker-candidate`: `PACKAGING_STATUS.json`, `README.md`,
  `config.yml`, operator env example, checker source files, and checker
  requirements.
- Participant docs candidate: 2 files under `packaging/player`; hygiene scan
  passed.

## Regression Fixes During Validation

Wave 33 source productization renamed player-visible profile files and symbols.
The older Wave 24 through Wave 29 fix validators and reference patches still
expected the pre-productization names. This validation retargeted those
organizer-only evidence artifacts to the neutral names without changing service
behavior, checker behavior, sploit behavior, or vulnerable/fixed semantics.

The competition matrix debug/admin scanner also had a false positive for the
new `admin-candidate` Makefile target. The scan still covers service code,
configuration, and route surfaces, but no longer treats that packaging target
name as an HTTP admin endpoint.

W33-F01 stabilizes aggregate gate liveness. `make wave33-gate` and
`make ad-stability-gate` now delegate to a single process-tree-bounded Python
runner instead of duplicating static tests in Make before the bounded phase
runner. The static tests remain named phases inside the runners. Both runners
use one shared out-of-repository Go cache/appdata pair for the vulnerable
profile runner, release-profile Go tests, `go vet`, and `go build`, reduce
nested Go package timeouts to 60 seconds, enforce a 285-second aggregate
deadline, and emit per-phase remaining time and elapsed time. The helper
runners accept aggregate-provided cache paths and still create isolated
temporary paths when run standalone.

W33-F02 adds repository-submission hygiene. The new
`scripts/check_repository_submission_hygiene.py` scans submitted repository
archives or extracted submission trees for `__pycache__/`, `.pyc`, `.gocache*`,
`.appdata*`, and generated `tmp/*candidate*` entries. It has an explicit
`--allow-wave33-local-candidates` mode so local Wave 33 gates can stage ignored
candidate trees during validation while strict submission scans still fail on
those paths.

W33-F03 adds the player source runtime-readiness guard. The staged player
candidate now carries `PACKAGING_STATUS.json` with `final_package: false` and
`source_runtime_ready: false`; `check_player_bundle_hygiene.py
--require-runtime-ready` fails this candidate until a later packaging wave
proves either runnable source delivery with dependencies/deploy files or
binary/image delivery with no source leakage.

W33-F04 hardens the shared process-tree runner used by Wave 33, vulnerable
profile tests, release-profile Go tests, and later package/runtime gates. The
runner now force-cleans the process tree even after the root child has exited,
then closes stdout/stderr streams so a descendant cannot keep pipes open after
the parent has printed successful unittest output. `tests/test_run_go_release_tests.py`
adds a regression where a parent exits while a child keeps stdout open; the
bounded runner returns promptly and reaps the root process without leaking the
handle.

W33-F05 integrates repository-submission hygiene into the Wave 33 aggregate
closure path. `wave33-gate` now runs strict
`scripts/check_repository_submission_hygiene.py` before player/admin candidate
generation, then runs the same checker with `--allow-wave33-local-candidates`
after the known ignored candidate trees are staged. The final gate phase removes
only `tmp/wave33-player-service-candidate`,
`tmp/wave33-player-service-candidate.hygiene-allowlist.json`, and
`tmp/wave33-admin-checker-candidate`; strict submission hygiene remains
fail-closed for generated candidate/cache artifacts in submitted repository
archives or extracted review trees.

## Invariants

- Organizer repository still retains two checker flag stores, five reference
  sploits, five reference fixes, CHECK/HAVOC evidence, vulnerable profile
  compatibility tags, and exploit-blocking fix evidence.
- Player-service candidate excludes checker, sploits, fixes, tests, internal
  gates, wave docs, final archives, final manifests, and checksums.
- Review submission hygiene excludes generated `tmp/*candidate*` trees,
  candidate allowlist sidecars, Python bytecode, Go caches, and appdata caches
  from repository submissions.
- Wave 33 aggregate closure now proves that repository-submission hygiene before
  candidate generation is clean, that only the known local candidate staging
  paths are tolerated during the gate, and that generated Wave 33 candidates
  are cleaned before gate exit.
- The staged player source candidate is not marked final and cannot pass the
  final runtime-readiness guard without future source-build/start or
  binary/image-delivery proof.
- Candidate source strips legacy vulnerable compatibility build tags from the
  generated player tree. W34 follow-up hardening also rewrites remaining
  source-visible build-profile helper/file names to product-neutral policy names
  and leaves the generated hygiene allowlist empty.
- Checker GET remains owner-view only through normal APIs; no DB/debug/admin
  checker shortcut was introduced.
- Public attack data remains locator-only; checker-private credentials/state are
  not exposed in public attack data.
- No new debug routes, hidden admin helpers, direct DB access paths, public flag
  fields, or external nondeterministic dependencies were introduced.

## Risks

- Exact `/usr/bin/timeout 300 make wave33-gate` evidence remains green on the
  WSL GNU-timeout/make path after W33-F05. The desktop host still requires WSL
  escalation to exercise that path from PowerShell.
- If an outer orchestrator kills the gate mid-run before Python can handle
  cleanup, stale ignored `tmp/wave33-*candidate*` paths can still make a later
  strict repository-submission hygiene check fail. Rerunning
  `python -B scripts/check_wave33_gate.py --cleanup-only` removes only the known
  Wave 33 generated candidate paths.
- Final packaging has not started; Wave 33 produces candidate trees and hygiene
  evidence only.
- Player source runtime readiness remains intentionally open until a later
  packaging wave proves source build/start with dependencies and deploy files or
  chooses binary/image delivery.
- Wave 34 has reduced player source vocabulary leakage, but it does not change
  the Wave 33 conclusion that the Wave 33 staged source candidate was not a
  final runnable player package. W34-T02 adds a separate source-runtime proof in
  `docs/wave_reports/wave_34_player_package_runtime_proof.md`.
