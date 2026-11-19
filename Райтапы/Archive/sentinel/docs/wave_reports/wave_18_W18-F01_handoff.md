# Wave 18 W18-F01 Handoff

## 1. Summary

Replaced the non-terminating aggregate AML-5 tagged Go sweep in
`make wave18-gate` with a deterministic package-by-package runner. Tagged
AML-5 coverage remains over the full `go list -tags aml5_vulnerable ./...`
package set, but each package now runs in its own subprocess with readable
output and per-package timeout handling.

## 2. Implementation Details

- Added `scripts/run_aml5_tagged_tests.py`.
- The runner discovers packages with `go list -tags aml5_vulnerable ./...`.
- Each package runs as
  `go test -tags aml5_vulnerable -count=1 -timeout 60s <package>`.
- The runner applies an outer 90 second subprocess timeout per package and
  reports the package command that timed out or failed.
- Updated `make wave18-gate` to call the runner instead of
  `go test -p 1 -tags aml5_vulnerable ./...`.
- Updated `scripts/check_wave18_gate.py` and Wave 18 gate tests to reject
  reverting the wrapper to aggregate tagged `./...` testing or removing the
  deterministic tagged runner.

## 3. Files Changed

- `Makefile`
- `scripts/run_aml5_tagged_tests.py`
- `scripts/check_wave18_gate.py`
- `tests/test_wave18_gate.py`
- `docs/wave_reports/wave_18_validation_summary.md`
- `docs/wave_reports/wave_18_W18-F01_handoff.md`

## 4. Tests Added

- Wave 18 gate regression requiring the deterministic tagged runner in
  `make wave18-gate`.
- Wave 18 gate regression rejecting a weakened runner that does not enumerate
  the AML-5 tagged package set.
- Wave 18 gate regression requiring the deterministic runner file.

## 5. Tests Run

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off python -B scripts/run_aml5_tagged_tests.py
```

Exit code: 0. Output began with `go list -tags aml5_vulnerable ./...`,
reported `aml5 tagged package count: 22`, and ran:

- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/cmd/aml-api`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/cmd/aml-worker`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/account`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/alert`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/audit`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/auth`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/authz`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/casework`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/config`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/customer`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/db`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/edd`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/exporting`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/graph`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/httpapi`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/logging`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/networkroom`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/projection`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/risk`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/internal/transaction`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/scripts/migrate`
- `go test -tags aml5_vulnerable -count=1 -timeout 60s sentinel-aml/tests`

All package commands returned `ok` or `[no test files]`.

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
```

Exit code: 0. Ran 97 tests.

```sh
python -B -m unittest discover -s tests -p "test_wave18_gate.py"
```

Exit code: 0. Ran 9 tests.

```sh
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
```

Exit code: 0. Ran 16 tests.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
```

Exit code: 0.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
```

Exit code: 0.

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

Exit code: 0. Executed through WSL GNU `timeout`/`make` on this Windows host;
the wrapper completed after the deterministic AML-5 package runner and all
remaining vet/docs/matrix/ForcAD checks.

## 6. Documentation Updated

Updated the Wave 18 validation summary and added this W18-F01 handoff.

## 7. CTF Invariants Checked

- Both checker places remain active.
- Checker PUT/GET still uses normal owner APIs only.
- CHECK/HAVOC remains strong.
- Public attack data remains credential-free.
- AML-5 vulnerable-checker cell remains concrete.
- AML-5 exploit and fix cells remain pending.

## 8. Security Invariants Checked

- Default build remains secure.
- AML-5 remains compile-time tagged only.
- No credentials, sessions, checker-private state, raw DB rows, audit diffs,
  value hashes, or unrelated private fields are exposed.

## 9. Self-Review

The change is limited to release-gate execution and validation checks. Product
behavior, checker behavior, ForcAD config, AML-5 vulnerable code/tests,
reference sploits, reference fixes, competition-matrix requirements, and
runtime visibility controls were intentionally untouched.

## 10. Risks / Open Questions

- The runner is intentionally more verbose than the aggregate command so
  package-level failures and timeouts are reviewable.
- A future gate may tune per-package timeout values if package runtimes grow,
  but coverage should remain package-by-package rather than returning to the
  aggregate tagged `./...` command.

## 11. Ready for Orchestrator Review

yes
