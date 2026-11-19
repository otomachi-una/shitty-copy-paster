# Wave 18 Validation Summary

## Status

Wave 18 is accepted and complete. W18-T01 implemented AML-5 only under the
`aml5_vulnerable` Go build tag, W18-T02 added `wave18-gate` and
competition-matrix evidence, W18-F01 replaced the non-terminating aggregate
tagged Go sweep with deterministic package-by-package AML-5 tagged execution,
W18-F02 integrated archive hygiene into the Wave 18 closure gate, and W18-F03
reconciled the status ledgers using that evidence. Wave 19 is the only next
unlocked wave. Wave 20 and later, including Wave 23, remain locked until the
staged exploit/fix sequence advances.

## Scope Validated

- Default network-room dossiers remain references-first and public/redacted.
- The tagged AML-5 profile is local to
  `GET /api/network/rooms/{room_id}/dossier`.
- The intended tagged leak fields are `foreign_private_notes` and
  `foreign_edd_comments`.
- The tagged path requires normal authentication, room materialization, and
  participant-scoped dossier access.
- Checker PUT/GET remains on normal owner note and owner EDD APIs.
- AML-5 reference exploit `sploits/sentinel_aml/aml_network_room.py` remains
  locked until Wave 23.
- AML-5 reference fix work remains locked until Wave 28 after exploit evidence.

## Protected Exclusions

AML-5 validation rejects credentials, sessions, checker-private state, public
attack data, raw database rows, audit raw diffs, value hashes, debug/admin
controls, direct DB checker paths, broad source-case blobs, EDD
`source_of_funds`, EDD `risk_rationale`, own-case dossier private note leaks,
unrelated private note leaks, reference exploit files, and reference fix files.

## Gate Evidence

W18-F01 recorded the authoritative wrapper after replacing the aggregate tagged
AML-5 sweep:

```sh
timeout 300 make wave18-gate
```

Exit code: 0.

The wrapper ran:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"`
- `python -B -m unittest discover -s tests -p "test_wave18_gate.py"`
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off python -B scripts/run_aml5_tagged_tests.py`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`
- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave18_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/validate_forcad_config.py`
- `python -B scripts/check_archive_hygiene.py`

The AML-5 tagged sweep now runs package-by-package. The runner first executes
`go list -tags aml5_vulnerable ./...`, then runs
`go test -tags aml5_vulnerable -count=1 -timeout 60s <package>` for each
discovered package with an outer 90 second subprocess timeout.

W18-F02 also moved the Wave 18 wrapper's Go cache and application-data scratch
paths outside the repository and made archive hygiene a required final
`wave18-gate` step. The hygiene script rejects `.gocache*/`, `.appdata*/`,
Python bytecode/cache directories, IDE metadata, local coverage outputs, and
temporary archive files in the deliverable tree.

Direct W18-F01 runner evidence:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off python -B scripts/run_aml5_tagged_tests.py
```

Exit code: 0. Output began with `go list -tags aml5_vulnerable ./...`,
reported `aml5 tagged package count: 22`, then ran each discovered package
with `go test -tags aml5_vulnerable -count=1 -timeout 60s <package>`.
All 22 package commands returned `ok` or `[no test files]`.

## Competition Matrix

`scripts/check_competition_matrix_gate.py` now marks AML-1 through AML-5
vulnerable-checker cells as concrete. All exploit-success, fixed checker,
exploit-blocked, and anti-coarse-fix cells remain pending until their planned
waves.

## Documentation Alignment

W18-T03 aligned:

- `docs/09_vulnerability_matrix.md`
- `docs/06_visibility_and_projections.md`
- `docs/network_room_model.md`
- `docs/10_workers_and_async_flows.md`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/source_of_truth_map.md`
- `docs/15_risk_register.md`
- `docs/14_agent_execution_log.md`

W18-F03 reconciled the status ledgers after W18-F01/W18-F02 evidence:

- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/source_of_truth_map.md`
- `docs/15_risk_register.md`
- `docs/14_agent_execution_log.md`

## Current Required Checks

```sh
python -B scripts/check_docs_tree.py
```

Exit code: 0.

```sh
python -B scripts/check_wave18_gate.py
```

Exit code: 0.

```sh
python -B scripts/check_competition_matrix_gate.py
```

Exit code: 0.

```sh
python -B scripts/validate_forcad_config.py
```

Exit code: 0.

```sh
timeout 300 make wave18-gate
```

Exit code: 0.

```sh
python -B scripts/check_archive_hygiene.py
```

Exit code: 0.

```sh
python -B -m unittest discover -s tests -p "test_archive_hygiene.py"
```

Exit code: 0. Ran 7 tests.

## Remaining Locks

- Wave 19 is unlocked as the only next allowed wave.
- Wave 20 and later remain locked until the staged exploit/fix sequence
  advances.
- `sploits/sentinel_aml/aml_network_room.py` remains absent.
- AML-5 reference fix artifacts remain absent until Wave 28.
