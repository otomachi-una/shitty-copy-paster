# W04-T04 Handoff — Wave 04 Gate, Docs, and Validation Summary

## 1. Summary

Added a strict Wave 04 validation gate and documentation package for deterministic risk, owner alerts, owner cases, and private owner-only case notes. The gate validates the expanded Wave 04 contract while keeping planned vulnerabilities, checker behavior, public attack data, and side-view leaks out of scope.

## 2. Implementation Details

- Added `scripts/check_wave04_gate.py`.
- Added Wave 04 gate regression tests under `tests/`.
- Added `make wave04-gate`.
- Added `make live-wave04-integration`.
- Updated README command and current-scope descriptions.
- Updated roadmap/waves status ledger:
  - Wave 03 is complete;
  - Wave 04 is `needs fixes` pending W04-T04 orchestrator review;
  - Waves 05-30 remain planned.
- Added `docs/wave_reports/wave_04_validation_summary.md`.
- Updated testing strategy and risk register.

Wave 04 gate coverage includes:

- expected Wave 04 migrations and tables;
- previous-wave auth/customer/account/transaction routes;
- Wave 04 alert/case/private-note routes;
- auth wrapping for product and investigation routes;
- absence of checker, public attack-data, EDD, graph, export, network-room, debug, admin, and planned-vulnerability routes;
- DTO guardrails against owner/auth/session/checker-private fields;
- `CaseNote.body` containment to private note create/read owner paths;
- non-owner note-body leak regression tests;
- no exploit scripts;
- live PostgreSQL risk and investigation API gate hooks;
- Wave 04 handoff and validation summary presence;
- docs tree, ForcAD config, Wave 01 scope, and retained Wave 03 invariants.

## 3. Files Changed

- `scripts/check_wave04_gate.py`
- `tests/test_wave04_gate.py`
- `Makefile`
- `README.md`
- `docs/12_testing_strategy.md`
- `docs/13_roadmap.md`
- `docs/waves.md`
- `docs/14_agent_execution_log.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_04_validation_summary.md`
- `docs/wave_reports/wave_04_W04-T04_handoff.md`

## 4. Tests Added

- Wave 04 gate current-branch pass test.
- Migration fail test for future out-of-scope tables.
- Route fail test for missing auth wrapping and future export route drift.
- DTO/note containment fail test for note body in alert/case projections.
- Live target fail test for missing Wave 04 live integration hooks.

## 5. Tests Run

- `GOTOOLCHAIN=local go test ./...` - passed.
- `GOTOOLCHAIN=local go vet ./...` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/check_wave03_gate.py` - expected historical-gate failure on the current Wave 04 branch:
  - `wave03-migrations-present-ordered`;
  - `wave03-tables-only`;
  - `wave03-routes-present`;
  - `no-side-view-or-later-routes`.
- `python -B scripts/check_wave04_gate.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` - passed, 40 tests.
- `docker compose up -d postgres` - started the local PostgreSQL service for live integration.
- Initial parallel live PostgreSQL attempt exposed the documented shared-schema reset race between live tests.
- Serial live PostgreSQL reruns passed:
  - `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test ./tests -run TestWave04LivePostgresRiskAlertGeneration -count=1 -v`;
  - `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test ./tests -run TestWave04LivePostgresInvestigationRepositories -count=1 -v`;
  - `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test ./internal/httpapi -run TestLivePostgresWave04InvestigationAPIIntegration -count=1 -v`.
- `docker compose down` - stopped and removed the live integration database container/network.

`GOTELEMETRY=off` and a writable local `GOCACHE` under `%TEMP%` were set for Go commands on this Windows host.

## 6. Documentation Updated

- README now identifies Wave 04 as the current branch state and lists Wave 04 commands.
- `docs/12_testing_strategy.md` documents the Wave 04 gate and live integration targets.
- `docs/13_roadmap.md` records Wave 03 complete and Wave 04 needs fixes pending review.
- `docs/waves.md` records Wave 03 complete and Wave 04 needs fixes pending review.
- `docs/14_agent_execution_log.md` records W04-T04.
- `docs/15_risk_register.md` records Wave 04 gate drift as mitigated.
- `docs/wave_reports/wave_04_validation_summary.md` summarizes Wave 04 validation.

## 7. CTF Invariants Checked

- Future checker place 1 owner path is prepared but checker PUT/GET is not implemented.
- No public attack data was added.
- No planned vulnerability was added.
- No exploit or reference-fix script was added.
- ForcAD config and checker/sploit separation remain valid.
- Private note bodies survive normal owner read/write tests.

## 8. Security Invariants Checked

- Private note body is confined to owner-authorized note endpoints.
- Alert queue and case shell DTOs do not include note bodies.
- Cross-owner denial remains fail-closed.
- Gate detects route drift and serializer drift.
- Logs do not include credential fields or note bodies.

## 9. Self-Review

- The Wave 04 gate is intentionally separate from the historical Wave 03 gate because Wave 03 correctly rejects the Wave 04 alert/case/note expansion.
- The gate checks structure and source-controlled test hooks; behavioral coverage remains in Go unit tests and live PostgreSQL integration tests.
- Documentation changes describe validation state and do not mask failing code tests.
- No product behavior was changed in this gate task.

## 10. Risks / Open Questions

- `python -B scripts/check_wave03_gate.py` remains a historical Wave 03 branch gate and fails on the current Wave 04 branch because Wave 04 intentionally adds alert/case/note migrations and routes. `scripts/check_wave04_gate.py` validates retained Wave 03 invariants while allowing the Wave 04 expansion.
- A dedicated future multi-wave gate may be useful to avoid asking orchestrator jobs to run historical gates directly on later branches.
- Live PostgreSQL tests share and reset the configured schema, so live gates should be run serially against the same database URL.

## 11. Ready for Orchestrator Review

yes.
