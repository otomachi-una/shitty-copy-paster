# Wave 17 W17-F01 Handoff

## 1. Summary

Made `wave17-gate` deterministic by serializing the AML-4 vulnerable-profile
all-package sweep. The gate now uses `go test -p 1 -tags aml4_vulnerable ./...`
for the tagged profile while leaving the default secure sweep package-parallel.
No AML-4 business vulnerability semantics were changed.

## 2. Root Cause / Deterministic Policy

The orchestrator review host observed `timeout 300 make wave17-gate` timing out
while running `go test -tags aml4_vulnerable ./...`, and the diagnostic
serialized run `go test -p 1 -tags aml4_vulnerable ./...` passed. Local
inspection did not identify a narrow AML-4 lifecycle bug in production code or
tests, and local sandbox runs of both tagged forms terminated once Go cache and
profile paths were writable. Because the review-host failure is isolated to
default package parallelism and the serialized tagged sweep is stable, Wave 17
now treats serialized package execution as the authoritative deterministic
policy for the vulnerable-profile closure sweep.

## 3. Implementation Details

- Updated `wave17-gate` to run the AML-4 tagged all-package sweep with `-p 1`.
- Updated `scripts/check_wave17_gate.py` to require the serialized tagged
  command in the Makefile target.
- Added a Wave 17 gate unit test that fails if the Makefile regresses to the
  non-serialized tagged sweep.
- Updated the testing strategy and validation summary to document the
  deterministic policy and wrapper evidence.

## 4. Files Changed

- `Makefile`
- `scripts/check_wave17_gate.py`
- `tests/test_wave17_gate.py`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_17_validation_summary.md`
- `docs/wave_reports/wave_17_W17-F01_handoff.md`

## 5. Tests Added

- `Wave17GateTest.test_wave17_requires_serialized_tagged_sweep`

## 6. Tests Run

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
```

Exit code: 0. Ran 97 tests.

```sh
python -B -m unittest discover -s tests -p "test_wave17_gate.py"
```

Exit code: 0. Ran 9 tests.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
```

Exit code: 0.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -p 1 -tags aml4_vulnerable ./...
```

Exit code: 0.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
```

Exit code: 0.

```sh
python -B scripts/check_docs_tree.py
python -B scripts/check_wave17_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/validate_forcad_config.py
```

Exit code: 0 for each command.

```sh
timeout 300 make wave17-gate
```

Exit code: 0 under WSL POSIX `timeout`/`make` semantics with temporary PATH
shims for `python` and the compatible Go toolchain. Native Windows PowerShell
cannot run the literal command because `make` is not installed on PATH and
`timeout` is Windows `timeout.exe`.

## 7. Documentation Updated

- `docs/12_testing_strategy.md` now documents the serialized AML-4 tagged
  sweep as the Wave 17 deterministic gate policy.
- `docs/wave_reports/wave_17_validation_summary.md` now includes W17-F01
  wrapper evidence instead of component-only evidence.
- This handoff records the root-cause evidence, deterministic policy, tests,
  invariants, and remaining risks.

## 8. CTF Invariants Checked

- Checker remains HTTP-only and uses normal product APIs.
- Place 1 and place 2 PUT/GET remain active.
- Public attack data remains locator-only and credential-free.
- AML-4 remains a build-tag profile only.
- No reference exploit or reference fix was added.
- AML-5 remains locked.

## 9. Security Invariants Checked

- No debug/admin endpoints or runtime vulnerability toggles were added.
- No direct database checker path was added.
- Default secure export redaction semantics were not changed.
- AML-4 leaked field semantics were not changed.
- No broad export serialization was added.
- No EDD confidential-comment, network-room dossier, credential, session,
  checker-private-state, or public credential exposure was added.

## 10. Self-Review

The fix is intentionally scoped to deterministic gate execution. It changes the
review wrapper and the validator that enforces it, adds a regression test for
the serialized strategy, and updates Wave 17 docs. AML-4 implementation files,
checker PUT/GET behavior, ForcAD config semantics, public attack-data schema,
exploit/fix artifacts, AML-5 scope, and debug/admin/runtime toggles were left
untouched.

## 11. Risks / Open Questions

- The exact package-parallel interaction on the orchestrator host was not
  narrowed to a single Go package because the local host did not reproduce the
  hang once Go cache/profile paths were writable.
- The accepted policy relies on serialized package execution for the tagged
  vulnerable-profile closure sweep. This is explicit in Makefile and validated
  by `scripts/check_wave17_gate.py`.
- Orchestrator should still rerun `timeout 300 make wave17-gate` on its clean
  make-enabled review host for independent acceptance evidence.

## 12. Ready for Orchestrator Review

yes
