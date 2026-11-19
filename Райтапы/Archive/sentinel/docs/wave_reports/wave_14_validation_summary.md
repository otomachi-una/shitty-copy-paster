# Wave 14 Validation Summary

## Scope Validated

Wave 14 introduces AML-1 as a controlled vulnerable source profile for dedup
merge-preview. The default profile remains secure. The `aml1_vulnerable` build
tag changes only
`GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview` so a
matching duplicate candidate may include duplicate `private_notes[].body`.
W14-T03 aligns the source-of-truth docs so `docs/09_vulnerability_matrix.md`
controls AML-1 behavior, protected fields, and exploit/fix sequencing.
W14-F01 hardens checker fake HTTP server shutdown and adds a subprocess
regression proving checker unittest discovery returns control after printing
`OK`.
W14-F02 adds the missing dedicated W14-T02 and W14-T03 handoff reports and
extends the Wave 14 gate so task handoff evidence is required.

## Commands Run

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml1_vulnerable ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave14_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B -m unittest discover -s tests -p "test_*.py"
python -B scripts/check_docs_tree.py
python -B scripts/check_wave13_gate.py
python -B scripts/check_wave14_gate.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_competition_matrix_gate.py
make wave14-gate
```

Result: pass for the Wave 14 current-branch component gates. Go commands were
run with workspace-local `GOCACHE` and `APPDATA` paths in this Windows sandbox,
matching the repository offline settings used by existing Makefile gates.

`python -B -m unittest discover -s tests -p "test_checker_*.py"` completed 97
tests in 34.598s and exited cleanly. `python -B -m unittest discover -s tests
-p "test_wave14_gate.py"` completed 8 tests in 34.952s; one test runs checker
discovery as a child process and fails if the child prints `OK` but does not
return. Full Python discovery completed 224 tests.

`make wave14-gate` is now present in the Makefile and runs checker tests, Wave
14 gate tests, default Go tests, tagged `aml1_vulnerable` Go tests, Go vet, docs
tree, Wave 14 gate, competition matrix gate, and ForcAD config validation. The
literal `make wave14-gate` command could not execute on this Windows host
because no `make` executable is installed; the target's component commands were
run directly and passed.

`python -B scripts/check_wave13_gate.py` was run as requested and fails only on
the historical pre-Wave-14 `wave13-no-vulnerable-behavior-yet` check because the
AML-1 build-tag profile now exists. All checker/HAVOC baseline checks inside the
Wave 13 gate pass. The Wave 13 gate was not weakened.

## Handoff Evidence

- `docs/wave_reports/wave_14_W14-T01_handoff.md`: AML-1 vulnerable profile
  implementation evidence.
- `docs/wave_reports/wave_14_W14-T02_handoff.md`: Wave 14 gate and competition
  matrix integration evidence.
- `docs/wave_reports/wave_14_W14-T03_handoff.md`: AML-1 documentation and risk
  alignment evidence.

The Wave 14 gate now fails if any of those reports are missing or lack standard
self-review markers.

## Competition Matrix Status

- AML-1 vulnerable checker gate: concrete via `scripts/check_wave14_gate.py`,
  default Go tests, tagged `aml1_vulnerable` Go tests, and checker unittest
  discovery.
- AML-1 exploit-success gate: pending until the scheduled reference exploit
  wave.
- AML-1 fixed checker gate: pending until the scheduled reference-fix wave.
- AML-1 exploit-blocked gate: pending until the scheduled reference-fix wave.
- AML-1 anti-coarse-fix gate: pending until the scheduled reference-fix and
  matrix waves.
- AML-2 through AML-5: still not active; Wave 14 gates scan production source
  and config files for accidental activation markers.
- Next unlocks: Wave 19 may add the AML-1 reference exploit only after Wave 14
  acceptance; Wave 15 may proceed with AML-2 only if the orchestrator chooses
  to continue the vulnerability-profile sequence.

## CTF Invariants

- Checker PUT/GET owner paths remain unchanged for both places.
- CHECK/HAVOC remains independent of side-view flag recovery.
- Public attack data remains credential-free and raw-flag-free.
- No reference exploit script is added in Wave 14.
- No reference fix implementation is added in Wave 14.

## Security Invariants

- AML-1 is local to dedup merge-preview in the `aml1_vulnerable` profile.
- The duplicate list remains public-only.
- `EDDRecord.confidential_comment`, EDD narrative fields, audit diffs,
  credentials, sessions, checker-private state, debug/admin toggles, and direct
  database checker access remain out of scope.

## Status

Wave 14 AML-1 documentation, gate, competition-matrix integration, checker
discovery liveness fix, and handoff evidence reconciliation are ready for
W14-F02 orchestrator review. Wave 14 remains under review until orchestrator
acceptance; this summary does not mark the wave complete.
