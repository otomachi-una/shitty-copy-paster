# W03-F01 Handoff — Clean/Offline Go Dependency Reproducibility

## 1. Summary

Implemented source-controlled Go dependency reproducibility for Wave 03 by vendoring the accepted dependency set and making vendor mode the canonical test/vet path. Clean reviewers no longer need network access or a pre-populated module cache to compile tests.

## 2. Implementation Details

- Ran `go mod vendor` with the existing pinned dependency set.
- Committed the generated `vendor/` tree, including `github.com/jackc/pgx/v5`, `golang.org/x/crypto`, and required transitive modules.
- Kept `go.mod` at `go 1.22.0` with no `toolchain` directive.
- Updated Makefile Go gates to use `GOTOOLCHAIN=local GOFLAGS=-mod=vendor`.
- Updated live PostgreSQL targets to use vendor mode.
- Extended `scripts/check_wave03_gate.py` with `offline-vendor-tree-present` and `offline-go-mod-and-makefile-policy` checks.
- Added regression tests that fail when vendored modules or vendor-mode Makefile policy are missing.

## 3. Files Changed

- `vendor/`
- `Makefile`
- `scripts/check_wave03_gate.py`
- `tests/test_wave03_gate.py`
- `README.md`
- `docs/11_deployment.md`
- `docs/12_testing_strategy.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_03_W03-F01_handoff.md`

## 4. Tests Added

- Wave 03 gate regression test for missing vendored modules.
- Wave 03 gate regression test for missing vendor-mode Makefile policy.

## 5. Tests Run

- `go mod vendor` was attempted first and failed on the current Windows host because the default Go build cache and telemetry path were not writable.
- `go mod vendor` completed successfully with `GOCACHE` pointed at a writable temp directory; the host still printed a telemetry-token warning, but the command exited successfully.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` was attempted exactly and did not attempt module downloads, but failed because the current Windows host's default Go build cache returned access denied errors before package tests ran.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` was attempted exactly and did not attempt module downloads, but failed because the current Windows host's default Go build cache returned access denied errors before diagnostics ran.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off` with fresh empty `GOMODCACHE` and fresh writable `GOCACHE` completed `go test ./...` successfully.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off` with fresh empty `GOMODCACHE` and fresh writable `GOCACHE` completed `go vet ./...` successfully.
- `python -B scripts/check_docs_tree.py` completed successfully and reported status `pass`.
- `python -B scripts/check_wave03_gate.py` completed successfully and reported status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 34 tests.
- `docker compose up -d postgres` started the local PostgreSQL service; a first health poll briefly hit a Docker pipe permission hiccup, and a retry reported the service healthy on `localhost:54329`.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresMigrationAuthIntegration -count=1 -v` completed successfully.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresWave03OwnerAPIIntegration -count=1 -v` completed successfully.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./tests -run TestWave03LivePostgresDomainRepositories -count=1 -v` completed successfully.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test -p 1 ./...` completed successfully.
- `docker compose down` completed successfully after live validation.

## 6. Documentation Updated

- README now documents `GOTOOLCHAIN=local GOFLAGS=-mod=vendor` as the canonical offline Go test/vet mode.
- `docs/11_deployment.md` now documents the source-controlled vendor dependency policy.
- `docs/12_testing_strategy.md` now documents clean/offline vendor-mode gate expectations.
- `docs/15_risk_register.md` now tracks dependency reproducibility as mitigated.
- `docs/14_agent_execution_log.md` now records W03-F01.

## 7. CTF Invariants Checked

- Checker remains HTTP-only and unimplemented.
- No public attack data or flag stores were introduced.
- ForcAD layout was not changed.
- No exploit or reference-fix scripts were added.

## 8. Security Invariants Checked

- Password hashing remains backed by `golang.org/x/crypto/bcrypt`.
- Session token hashing/storage behavior was unchanged.
- No credential or token material logging was added.
- No debug/admin endpoint was added.

## 9. Self-Review

The implemented dependency strategy is source-controlled vendoring plus explicit vendor-mode Go commands. The gate checks the presence of required vendored modules and Makefile policy so future drift fails quickly.

## 10. Risks / Open Questions

- This repository is not a Git checkout in the current workspace, so file status was inspected through the filesystem rather than `git status`.
- The current Windows host still prints a Go telemetry-token warning because its telemetry directory is not writable, but vendor-mode test/vet commands exit successfully.
- The current Windows host still needs a writable `GOCACHE`; this is independent of module reproducibility and remains documented.

## 11. Ready for Orchestrator Review: yes
