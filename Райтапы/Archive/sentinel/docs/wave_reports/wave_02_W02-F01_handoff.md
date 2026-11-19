# Wave 02 W02-F01 Handoff — Go Toolchain and Dependency Reproducibility

## 1. Summary

Restored reproducible offline Go test/vet behavior for Wave 02 by lowering the module language directive from `go 1.25.0` to `go 1.22.0`, removing the implicit toolchain-download path, and pinning database/auth dependencies to Go 1.22-compatible versions.

## 2. Implementation Details

- Set `go.mod` to `go 1.22.0`.
- Removed the `toolchain` directive introduced by newer dependency resolution.
- Pinned `github.com/jackc/pgx/v5` to `v5.6.0`, whose module metadata declares Go 1.20.
- Pinned `golang.org/x/crypto` to `v0.31.0`, whose module metadata declares Go 1.20.
- Kept auth behavior, DTOs, repository contracts, migrations, checker, and sploit placeholders unchanged.
- Added `make toolchain-gate`, which checks the Go directive and runs local-toolchain test/vet.
- Updated deployment/testing docs and README with local/offline Go commands.

## 3. Files Changed

- `go.mod`
- `go.sum`
- `Makefile`
- `README.md`
- `docs/11_deployment.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_02_W02-F01_handoff.md`

## 4. Tests Added

- Added a Makefile gate target, `toolchain-gate`, to catch accidental `go.mod` drift from `go 1.22.0` and to run `GOTOOLCHAIN=local` test/vet commands.

## 5. Tests Run

- `GOTOOLCHAIN=local go test ./...` was attempted in PowerShell form and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go test ./...` successfully.
- `GOTOOLCHAIN=local go vet ./...` was attempted in PowerShell form and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go vet ./...` successfully.
- `python -B scripts/check_wave02_gate.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- The `make toolchain-gate` target could not be executed on this Windows host because `make` is not installed.
- The `toolchain-gate` directive check was run directly with Python and printed `go 1.22.0`.
- `GOTOOLCHAIN=local go env GOVERSION GOTOOLCHAIN` reported local Go execution with `GOTOOLCHAIN=local`.

## 6. Documentation Updated

- Deployment docs now state the Go 1.22+ offline baseline and `GOTOOLCHAIN=local` commands.
- Testing strategy now lists the toolchain gate and local-toolchain commands.
- README now lists local/offline Go review commands.
- Risk register now tracks toolchain reproducibility as mitigated.
- Agent execution log updated.

## 7. CTF Invariants Checked

- No checker direct DB dependency was added.
- No hidden debug endpoint was added.
- No public attack data or flag stores were added.
- No planned vulnerabilities or reference exploits were added.

## 8. Security Invariants Checked

- Password hashes and token hashes remain out of HTTP DTOs and logs.
- Raw tokens are still only returned at session creation.
- DB models are still not directly serialized.

## 9. Self-Review

The change is limited to build metadata, dependency pins, and documentation. The dependency pins preserve existing imports and behavior while avoiding Go 1.23+ or Go 1.25+ module directives that would force network toolchain resolution in review.

## 10. Risks / Open Questions

- On this Windows host, the default Go build cache can return access denied errors. The local-toolchain commands pass when `GOCACHE` is pointed at a writable temp directory.
- The live PostgreSQL integration environment gap from W02-T03 remains unchanged.

## 11. Ready for Orchestrator Review

Yes.
