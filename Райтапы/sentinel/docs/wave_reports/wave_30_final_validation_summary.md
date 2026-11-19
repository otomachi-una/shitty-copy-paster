# Wave 30 Final Validation Summary

## Status

Wave 30 final validation evidence is implemented under review and updated by
W30-F01 after orchestrator review reproduced an aggregate gate timeout. W30-F02
adds `wave30-gate` as the Wave 30 final release gate so acceptance evidence is
owned by a Wave 30 command rather than only by `wave29-gate`. This summary does
not claim final competition readiness; orchestrator release review remains the
acceptance authority.

## Command Evidence

- `timeout 300 make wave29-gate` - exit 0, elapsed 3m39.837s on the WSL
  GNU-timeout/make path after W30-F01 shared-cache liveness changes.
- `timeout 300 make wave30-gate` - exit 0, elapsed 4m3.712s on the WSL
  GNU-timeout/make path after W30-F02 added the final release target.
- `make competition-matrix-gate` - exit 0, elapsed 0m0.914s on WSL with a
  temporary `/tmp` `python` shim to `python3` because the WSL image lacks a
  `python` command.
- `python -B scripts/validate_forcad_config.py` - exit 0, elapsed about
  0.221s.
- `python -B scripts/check_archive_hygiene.py` - exit 0, elapsed about 0.298s.
- `make release-archive` - exit 0, elapsed 0m5.956s on the WSL make path
  after the W30-T03 report files were added.

The W30-F02 `wave30-gate` run produced
`/tmp/sentinel-aml-release/sentinel_aml_release.tar.gz` with 668 files and
SHA-256 `7ee8026ce68da3ca1f59507b19ec077151d06d1229bfafc7b1688cafa43b2fa5`.
The builder validated required release inventory and archive-member hygiene.

## Matrix Evidence

- AML-1 dedup preview: vulnerable-checker, exploit-success, fixed-checker,
  exploit-blocked, and anti-coarse-fix cells are concrete.
- AML-2 audit timeline: vulnerable-checker, exploit-success, fixed-checker,
  exploit-blocked, and anti-coarse-fix cells are concrete.
- AML-3 related graph: vulnerable-checker, exploit-success, fixed-checker,
  exploit-blocked, and anti-coarse-fix cells are concrete.
- AML-4 export redaction: vulnerable-checker, exploit-success, fixed-checker,
  exploit-blocked, and anti-coarse-fix cells are concrete.
- AML-5 network room: vulnerable-checker, exploit-success, fixed-checker,
  exploit-blocked, and anti-coarse-fix cells are concrete.

Wave 29 aggregate evidence also confirmed all five reference sploits compile
with repository bytecode disabled and all five reference patches apply cleanly.

## W30-F01 Liveness Update

The orchestrator review environment reproduced the old aggregate gate exiting
124 after AML-1 completed and AML-2 tagged Go testing began. W30-F01 replaces
the five cache-cold tagged Go test Makefile lines with
`scripts/run_vulnerable_profile_tests.py`, which runs AML-1 through AML-5
focused vulnerable-profile packages with one shared out-of-repository
GOCACHE/APPDATA pair for the aggregate invocation. It also updates
`scripts/run_go_release_tests.py` to reuse one shared out-of-repository
GOCACHE/APPDATA pair across the untagged package-by-package release/offline
runner.

Evidence preserved:

- checker unittest discovery;
- competition matrix gate;
- Wave 29 regression gate;
- exactly five sploit compile checks with repository bytecode disabled;
- exactly five `git apply --check --whitespace=error` fix checks;
- vulnerable-profile coverage for AML-1 through AML-5;
- untagged release/offline Go tests;
- Go vet;
- docs tree validation;
- ForcAD config validation;
- archive hygiene.

## W30-F02 Final Gate Target

`wave30-gate` is the Wave 30 final release gate. It runs Wave 30 target tests,
delegates to the stabilized Wave 29 aggregate matrix/regression evidence,
reruns the competition matrix gate, validates the Wave 30 gate wiring, checks
ForcAD config, checks archive hygiene, and builds the release archive. Wave 30
acceptance is allowed only after exact `timeout 300 make wave30-gate` success
under orchestrator review. It does not claim final competition readiness. No
future feature waves are unlocked; only final release-candidate handoff/package
promotion remains after acceptance.

## W31-F01 Final Gate Liveness Update

Orchestrator review later reported `/usr/bin/timeout 300 make wave30-gate`
stalling inside `scripts/run_vulnerable_profile_tests.py`. W31-F01 changes that
runner from plain `subprocess.run` timeout handling to the shared
process-tree-aware runner used by `scripts/run_go_release_tests.py`, while
retaining all five focused vulnerable-profile scenarios and the shared
out-of-repository Go cache/appdata design. Each vulnerable-profile child
command now has a bounded outer cap of `min(package_timeout + 30, 45)` seconds
and prints the profile name, package list, exit code, elapsed time, and timeout
diagnostic.

W31-F01 exact command evidence is recorded in
`docs/wave_reports/final_release_candidate.md`: `/usr/bin/timeout 300 make
wave30-gate` exited 0 in 3m49.270s on 2026-09-05 and produced
`/tmp/sentinel-aml-release/sentinel_aml_release.tar.gz` with 671 files and
SHA-256 `bb6b37097cf4739a9c5a8edbdfb650a95ce5763372bb5f3aaa5a3e4e29fa26a7`.
Final release candidate issuance and final competition readiness remain blocked
until orchestrator acceptance is recorded.

## CTF Invariants Checked

- ForcAD checker type remains `pfr`.
- Two active checker places remain configured.
- Place 1 stores flags in `CaseNote.body`.
- Place 2 stores flags in `EDDRecord.confidential_comment`.
- Checker GET remains owner-view only.
- CHECK/HAVOC remains release-blocking across dedup, audit, graph, export,
  network room, case notes, and EDD.
- Public attack data remains credential-free and raw-flag-free.

## Security Invariants Checked

- Fixed-profile side views remain projection/redaction/reference-only.
- Reference fixes reject endpoint removal, module disablement, docs-only or
  gate-only fixes, sensitive-field renames, direct DB shortcuts, and
  debug/admin shortcuts.
- No hidden debug endpoint, direct DB checker path, credentials, sessions,
  checker-private state, raw audit diffs, hashes, or raw DB rows are normalized
  as acceptable fixed behavior.

## Known Limitations

- Final competition readiness is still pending orchestrator Wave 30 acceptance.
