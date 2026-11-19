# Sentinel AML Agent Execution Log

## 2026-08-30 — W01-T01 Repository Skeleton

Status: completed.

Actions:

- created the Go module and minimal buildable API/worker entrypoints;
- reserved future internal boundaries for HTTP API, authz, config, and logging;
- added developer commands for format, test, vet, build, and placeholder process runs;
- added repository layout smoke tests and negative out-of-scope artifact checks;
- added a reserved field-name check for Wave 01 files;
- documented Wave 01 status and explicit exclusions in the README;
- added the W01-T01 handoff report.

Verification:

- `gofmt -w cmd internal tests` completed successfully.
- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.
- `go build ./cmd/aml-api ./cmd/aml-worker` completed successfully.
- `go test ./tests -run TestRepositorySkeleton -count=1` completed successfully.

Scope preserved:

- no product endpoints, database migrations, authentication logic, checker flows, planned vulnerabilities, exploits, reference fixes, debug endpoints, admin backdoors, or direct DB shortcuts were implemented.

## 2026-08-30 — W01-T02 ForcAD Layout and Config

Status: completed.

Actions:

- created the `sentinel_aml` ForcAD task fragment in `config.yml`;
- added inert checker placeholders under `checkers/sentinel_aml/`;
- added a documentation-only reference exploit directory under `sploits/sentinel_aml/`;
- added a standard-library config validator at `scripts/validate_forcad_config.py`;
- added Python layout tests for config shape, checker/sploit separation, and negative boundary checks;
- updated the existing Go repository layout smoke test so W01-T02's required checker/sploit skeleton is no longer treated as a W01-T01 out-of-scope artifact;
- added the W01-T02 handoff report.

Verification:

- `python --version` reported Python 3.11.6.
- `python scripts/validate_forcad_config.py` completed successfully.
- `python -m unittest discover -s tests -p test_forcad_layout.py` completed successfully.
- `python -m py_compile scripts\validate_forcad_config.py checkers\sentinel_aml\checker.py checkers\sentinel_aml\checker_lib.py tests\test_forcad_layout.py` completed successfully; generated `__pycache__` artifacts were removed after verification.
- `python checkers\sentinel_aml\checker.py` printed the Wave 11 placeholder message and exited non-zero as intended for fail-closed placeholder behavior.
- `python -m unittest tests.test_forcad_layout` was attempted but collided with an unrelated installed `tests` package in this Python environment, so local unittest discovery was used instead.
- `gofmt -w tests\repository_layout_test.go` completed successfully.
- `go test ./...` completed successfully after the W01-T01 layout test was updated for W01-T02's newly allowed checker/sploit skeleton.
- `go vet ./...` completed successfully.

Scope preserved:

- no real checker registration, login, PUT, GET, attack-data generation, private checker state format, exploit script, planned vulnerability, debug endpoint, or direct DB access was implemented.

## 2026-08-30 — W01-T03 Documentation Gate and Validation

Status: completed.

Actions:

- added a documentation-tree validator that reports pass, pending, or fail status for required docs and directories;
- added a Wave 01 scope validator for repository layout, ForcAD config shape, checker/sploit separation, handoff report presence, and negative boundary checks;
- added Python unittest coverage for both validators;
- added `docs/agent_packets/README.md` to reference the Wave 01 prompt pool and handoff expectations;
- added `docs/wave_reports/wave_01_validation_summary.md`;
- added the W01-T03 handoff report.

Verification:

- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pending`.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported overall status `pass`.
- `python -B -m unittest discover -s tests -p "test_docs_tree.py"` completed successfully.
- `python -B -m unittest discover -s tests -p "test_wave01_scope.py"` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 12 tests.
- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.

Scope preserved:

- no authoritative requirement doc, source-of-truth map, product API, DB schema, checker lifecycle behavior, public attack-data implementation, private checker state format, vulnerability, exploit, fix, debug endpoint, or direct DB shortcut was implemented or modified.

## 2026-08-30 — W01-F01 Canonical Sentinel Docs Cleanup

Status: completed.

Actions:

- restored exact canonical Sentinel AML documentation paths required for Wave 02 readiness;
- quarantined foreign legacy exchange material under `docs/archive/foreign_voltax/`;
- updated `docs/agent_packets/README.md` to point to canonical Wave 01 prompt/fix prompt pools and future Wave 02 prompt pool;
- tightened `scripts/check_docs_tree.py` to require exact canonical docs and fail on active legacy filenames or content markers;
- updated `tests/test_docs_tree.py` to require docs-tree status `pass`;
- updated `docs/wave_reports/wave_01_validation_summary.md` from pending to pass;
- added the W01-F01 handoff report.

Verification:

- `python3 -B scripts/check_docs_tree.py` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_docs_tree.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_*.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python --version` reported Python 3.11.6.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B -m unittest discover -s tests -p "test_docs_tree.py"` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 13 tests.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported overall status `pass`.
- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.

Scope preserved:

- no product API, DB schema, auth/session logic, checker PUT/GET behavior, public attack-data implementation, private checker state format, planned vulnerability, exploit, reference fix, debug endpoint, admin endpoint, or direct DB shortcut was implemented or modified.

## 2026-08-30 — W01-F02 ForcAD Config and Sploit Placeholder Alignment

Status: completed.

Actions:

- updated `config.yml` to the source-aligned task-list shape with `name: sentinel_aml`;
- updated the ForcAD config validator to require the list shape and reject the old mapping shape;
- updated ForcAD layout tests for task name and config shape regression coverage;
- updated reference exploit placeholder documentation to list the five planned future exploit filenames;
- updated Wave 01 scope validation to check the future exploit README contract and F01/F02 handoff reports;
- added the W01-F02 handoff report.

Verification:

- `python3 -B scripts/validate_forcad_config.py` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B scripts/check_wave01_scope.py` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_forcad_layout.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_wave01_scope.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python3 -B -m unittest discover -s tests -p "test_*.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python --version` reported Python 3.11.6.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported overall status `pass`.
- `python -B -m unittest discover -s tests -p "test_forcad_layout.py"` completed successfully with 7 tests.
- `python -B -m unittest discover -s tests -p "test_wave01_scope.py"` completed successfully with 4 tests.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 15 tests.
- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.

Scope preserved:

- no real checker CHECK, PUT, GET, exploit script, product API, database migration, vulnerability, reference fix, debug endpoint, admin endpoint, backdoor endpoint, credential, sensitive field, artificial flag field, or direct DB checker dependency was implemented.

## 2026-08-30 — W02-T01 Database and Migration Foundation

Status: completed.

Actions:

- added PostgreSQL-specific initial migration SQL for `users` and `sessions`;
- added context-aware database open/close and migration runner helpers using the `pgx` standard-library PostgreSQL driver;
- added a minimal auth repository for user/session persistence needed by W02-T02;
- added a migration command at `go run ./scripts/migrate`;
- added tests for migration ordering/schema, duplicate username handling, token-hash session storage, context cancellation, and out-of-scope field/table guards;
- added ADR `docs/decisions/0001_database_migration_foundation.md`;
- updated database, deployment, and testing docs;
- added the W02-T01 handoff report.

Verification:

- `go get github.com/jackc/pgx/v5/stdlib` initially failed under restricted network access, then succeeded with approved escalation.
- `go mod tidy` completed successfully with `GOCACHE` pointed at the temp directory because the default Windows Go build cache returned access denied errors.
- `gofmt -w internal\config internal\db internal\auth scripts\migrate tests` completed successfully.
- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 15 tests.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `go run ./scripts/migrate` with empty `DATABASE_URL` failed closed with `database url is required`, as expected.

Scope preserved:

- no customer, account, transaction, alert, case, note, EDD, checker lifecycle, public attack-data, flag-store, retention cleanup, vulnerability, exploit, reference fix, debug endpoint, admin endpoint, or direct DB checker behavior was implemented.

## 2026-08-30 — W02-T02 Auth and Session API

Status: completed.

Actions:

- added a bcrypt-backed auth service for normal analyst registration and login;
- added secure random session token creation with hash-only persistence;
- added bearer-token current-user lookup and an `internal/authz` principal boundary;
- added HTTP routes for `POST /api/auth/register`, `POST /api/auth/login`, and `GET /api/auth/me`;
- kept health endpoints operational-only;
- added auth service and HTTP API tests for successful and negative paths;
- updated auth API, authorization, visibility, and testing documentation;
- added the W02-T02 handoff report.

Verification:

- `go get golang.org/x/crypto/bcrypt` initially failed under restricted network access, then succeeded with approved escalation.
- `go mod tidy` initially failed because the default Windows Go build cache returned access denied errors; rerun with `GOCACHE` pointed at the temp directory and completed successfully.
- `go test ./...` initially exposed a production constructor mismatch for `auth.NewRepository(*sql.DB)`; fixed with a SQL adapter and reran successfully.
- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.
- `python3 -B -m unittest discover -s tests -p "test_*.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 15 tests.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.

Scope preserved:

- no AML domain endpoint, checker logic, planned vulnerability, exploit, reference fix, debug endpoint, admin endpoint, public attack data, flag store, or direct DB checker behavior was implemented.

## 2026-08-30 — W02-T03 Auth Integration and Wave Gate

Status: completed.

Actions:

- added a Wave 02 integration gate script for migrations, auth routes, sensitive-response boundaries, logs, exploit absence, Wave 02 handoffs, docs, and ForcAD config;
- added Python tests for the Wave 02 gate and negative table/route/response/exploit cases;
- added Go HTTP surface gate tests from the external `tests` package;
- added `make wave02-gate`;
- updated README, testing strategy, risk register, and Wave 02 validation summary;
- added the W02-T03 handoff report.

Verification:

- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.
- `python3 -B scripts/check_docs_tree.py` was attempted but the Windows `python3` launcher only printed `Python` and exited with code 1.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python3 -B scripts/check_wave01_scope.py` was attempted but the Windows `python3` launcher only printed `Python` and exited with code 1.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported overall status `pass`.
- `python3 -B -m unittest discover -s tests -p "test_*.py"` was attempted but the Windows `python3` launcher only printed `Python` and exited with code 1.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 21 tests.
- `python -B scripts/check_wave02_gate.py` completed successfully and reported overall status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.

Scope preserved:

- no product implementation, AML domain entity, checker flow, vulnerability, exploit, reference fix, debug endpoint, admin endpoint, public attack data, flag store, or direct DB checker behavior was added.

## 2026-08-30 — W02-F01 Go Toolchain and Dependency Reproducibility

Status: completed.

Actions:

- lowered `go.mod` from `go 1.25.0` to `go 1.22.0`;
- removed the toolchain-download directive introduced by newer dependency resolution;
- pinned `github.com/jackc/pgx/v5` to `v5.6.0`;
- pinned `golang.org/x/crypto` to `v0.31.0`;
- added `make toolchain-gate` to check the Go directive and run local-toolchain test/vet;
- updated README, deployment docs, testing strategy, and risk register for offline Go review;
- added the W02-F01 handoff report.

Verification:

- `GOTOOLCHAIN=local go test ./...` was attempted in PowerShell form and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go test ./...` successfully.
- `GOTOOLCHAIN=local go vet ./...` was attempted in PowerShell form and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go vet ./...` successfully.
- `python -B scripts/check_wave02_gate.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `make toolchain-gate` could not be executed on this Windows host because `make` is not installed.
- The `toolchain-gate` directive check was run directly with Python and printed `go 1.22.0`.
- `GOTOOLCHAIN=local go env GOVERSION GOTOOLCHAIN` reported local Go execution with `GOTOOLCHAIN=local`.

Scope preserved:

- no auth behavior, API route, DB schema, checker, sploit, planned vulnerability, reference fix, AML domain model, debug endpoint, admin endpoint, public attack data, flag store, or direct DB checker behavior was changed.

## 2026-08-30 — W02-F02 Live PostgreSQL Migration/Auth Integration Gate

Status: completed.

Actions:

- added a Docker Compose PostgreSQL service for a dedicated local `sentinel_aml_test` database;
- added an opt-in live integration test that applies migrations to a clean PostgreSQL schema and exercises register, login, authenticated `/api/auth/me`, unauthenticated `/api/auth/me`, and sensitive-response exclusion through the real DB-backed stack;
- added `make postgres-up` and `make live-auth-integration`;
- extended the Wave 02 gate to require the live integration test, compose service, Makefile target, and F01/F02 handoffs;
- added Python gate regression coverage for the live integration target;
- updated deployment docs, testing strategy, and risk register;
- added the W02-F02 handoff report.

Verification:

- `docker compose up -d postgres` completed successfully; the postgres service became healthy on `localhost:54329`.
- `SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local go test ./internal/httpapi -run TestLivePostgresMigrationAuthIntegration -count=1 -v` completed successfully.
- `GOTOOLCHAIN=local go test ./...` was attempted in PowerShell form and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go test ./...` successfully.
- `GOTOOLCHAIN=local go vet ./...` was attempted in PowerShell form and did not attempt a toolchain download, but failed because the default Windows Go build cache returned access denied errors.
- `GOTOOLCHAIN=local` with `GOCACHE` pointed at a writable temp directory completed `go vet ./...` successfully.
- `python -B scripts/check_wave02_gate.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 23 tests.
- `docker compose down` completed successfully after validation.

Scope preserved:

- no AML domain table or API, checker behavior, planned vulnerability, exploit, reference fix, debug endpoint, admin endpoint, public attack data, flag store, or direct DB checker behavior was added.

## 2026-08-30 — W02-F03 Roadmap, Waves, and Agent-Packet Canonicalization

Status: completed.

Actions:

- restored `docs/13_roadmap.md` with a dependency-aware W01-W30 roadmap;
- restored `docs/waves.md` with sequential secure feature, checker, vulnerability, exploit, fix, regression, and final validation waves;
- recorded Wave 02 as `needs fixes` with W02-F01 and W02-F02 passing local gates and W02-F03 under review;
- moved Wave 01 prompt pools from docs root to canonical `docs/agent_packets/` paths;
- updated the agent-packet README and source-of-truth map for canonical prompt-pool placement;
- tightened docs-tree validation to fail on misplaced prompt pools or collapsed roadmap/waves docs;
- added docs-tree regression tests for canonical packet placement and non-collapsed wave detail;
- updated the Wave 02 validation summary and risk register;
- added the W02-F03 handoff report.

Verification:

- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_wave02_gate.py` completed successfully and reported overall status `pass`.
- `python -B scripts/validate_forcad_config.py` completed successfully.
- `python -B -m unittest discover -s tests -p "test_docs_tree.py"` completed successfully with 8 tests.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 27 tests.

Scope preserved:

- no implementation code, migration, API behavior, checker file, sploit file, ForcAD config, vulnerability, exploit, reference fix, debug endpoint, admin endpoint, public attack data, flag store, or direct DB checker behavior was changed.

## 2026-08-30 — W03-T01 Domain Persistence for Customers, Accounts, and Transactions

Status: completed.

Actions:

- added the ordered Wave 03 migration for `customers`, `accounts`, and `transactions`;
- added owner-scoped repositories for customers, accounts, and transactions;
- added validation for required fields, status/type/direction enums, currency format, and deterministic risk-score bounds;
- added repository tests for create/get/list paths, cross-owner fail-closed behavior, required-field validation, and canceled contexts;
- extended migration tests for Wave 03 schema, ordering, indexes, constraints, and out-of-scope table/field guards;
- added an opt-in live PostgreSQL integration test that applies all migrations to a clean database and exercises auth plus domain repositories together;
- updated domain, database, testing, and risk documentation;
- added the W03-T01 handoff report.

Verification:

- `gofmt -w internal\customer internal\account internal\transaction tests\migration_sql_test.go tests\wave03_live_postgres_test.go` completed successfully.
- Final verification is recorded in `docs/wave_reports/wave_03_W03-T01_handoff.md`.

Scope preserved:

- no checker behavior, product HTTP endpoint, case, note, EDD record, alert, graph/export/network subsystem, worker, public attack data, checker storage, vulnerability, exploit, reference fix, debug endpoint, admin endpoint, or direct DB checker behavior was implemented.

## 2026-08-30 — W03-T02 Owner-Scoped Customer, Account, and Transaction APIs

Status: completed.

Actions:

- added authenticated Wave 03 product API routes for customer onboarding, customer reads, account creation/listing/reads, transaction ingestion/listing/reads;
- updated auth middleware so non-GET product endpoints can authenticate while handlers still enforce their own methods;
- added explicit request/response DTOs for Wave 03 owner APIs;
- wired `cmd/aml-api` to use the real customer, account, and transaction repositories;
- added HTTP handler tests for unauthenticated rejection, happy paths, cross-owner fail-closed behavior, malformed IDs, clean DTOs, and absent side-view endpoints;
- added an opt-in live PostgreSQL owner API integration test through the real auth/repository/HTTP stack;
- updated API contract, authentication/authorization, visibility/projection, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_03_W03-T02_handoff.md`.

Scope preserved:

- no alert, case, EDD, graph, export, network-room, public side-view, checker-only API, direct DB checker path, planned vulnerability, exploit, reference fix, debug endpoint, or admin endpoint was implemented.

## 2026-08-30 — W03-T03 Wave 03 Integration Gate and Documentation Guardrails

Status: completed.

Actions:

- added `scripts/check_wave03_gate.py` for Wave 03 migration, API, owner-scope, DTO, live-gate, docs, ForcAD, Wave 01, and Wave 02 invariant validation;
- added Python regression tests for Wave 03 gate pass/fail conditions;
- added `make wave03-gate` and `make live-wave03-integration`;
- updated README command/API status for Wave 03;
- added the Wave 03 validation summary;
- updated testing strategy and risk register;
- added the W03-T03 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_03_W03-T03_handoff.md`.

Scope preserved:

- no business logic, checker behavior, exploit, planned vulnerability, reference fix, public attack data, flag storage, alert/case/EDD/graph/export/network endpoint, side view, debug endpoint, admin endpoint, or direct DB checker behavior was implemented.

## 2026-08-30 — W03-F01 Clean/Offline Go Dependency Reproducibility

Status: completed.

Actions:

- generated and committed `vendor/` for the accepted Go dependency set;
- updated Makefile Go test/vet/build/live gate commands to use `GOTOOLCHAIN=local GOFLAGS=-mod=vendor`;
- extended `scripts/check_wave03_gate.py` to validate required vendored modules and Makefile vendor-mode policy;
- added Wave 03 gate regression tests for missing vendored modules and missing vendor-mode policy;
- updated README, deployment docs, testing strategy, and risk register for the offline dependency policy;
- added the W03-F01 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_03_W03-F01_handoff.md`.

Scope preserved:

- no auth behavior, session behavior, persistence schema, product API, checker behavior, public attack data, flag store, exploit, planned vulnerability, reference fix, debug endpoint, admin endpoint, or direct DB checker behavior was changed.

## 2026-08-30 — W03-F02 Transaction Input Contract Hardening

Status: completed.

Actions:

- removed client-supplied `risk_score` from transaction create DTOs and repository create params;
- changed transaction inserts to omit `risk_score` so PostgreSQL supplies the deterministic default `0`;
- added shared transaction amount validation for positive `numeric(18,2)` strings before database work;
- added repository and HTTP tests for rejected client risk scores, invalid amount classes, valid amounts, server-owned read responses, and retained owner denial;
- updated API, database, authz, visibility, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_03_W03-F02_handoff.md`.

Scope preserved:

- no risk engine, alert, case, note, checker behavior, public attack data, flag store, planned vulnerability, exploit, reference fix, debug endpoint, admin endpoint, direct DB checker path, or ForcAD config change was introduced.

## 2026-08-30 — W03-F03 Roadmap, Wave Ledger, and Duplicate-Error Debt Alignment

Status: completed.

Actions:

- updated the roadmap status ledger so Wave 02 is complete and Wave 03 remains `needs fixes` until W03-F01, W03-F02, and W03-F03 pass;
- corrected Wave 03 scope to the delivered customer/account/transaction slice;
- defined Wave 04 as conditional risk scoring, alerts, and owner case workflow;
- updated the source-of-truth map to bind roadmap status and wave decomposition expectations together;
- added explicit duplicate errors for customer registration numbers, account `iban_like` values, and transaction `trace_id` values;
- mapped duplicate domain errors to stable HTTP `409` JSON responses;
- added repository, HTTP, and docs-tree regression tests;
- updated API contract, testing strategy, risk register, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_03_W03-F03_handoff.md`.

Scope preserved:

- no checker behavior, public attack data, flag store, planned vulnerability, exploit, reference fix, alert/case/EDD/graph/export/network feature, debug endpoint, admin endpoint, or direct DB checker path was introduced.

## 2026-08-30 — W04-T01 Alert, Case, and Case-Note Persistence Foundation

Status: completed.

Actions:

- added ordered Wave 04 migration for `alerts`, `cases`, and `case_notes`;
- added owner-scoped alert repository create/get/list/claim/triage behavior;
- added owner-scoped case repository create-from-alert/get/list/status-update behavior;
- added owner-scoped case-note create/list behavior for private/internal notes;
- added status transition validation for alerts and cases;
- added repository and migration tests for Wave 04 happy paths, cross-owner denial, invalid transitions, duplicate mapping, and canceled contexts;
- updated domain, database, authorization, flag-store, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_04_W04-T01_handoff.md`.

Scope preserved:

- no checker PUT/GET path, public attack data, flag storage API, planned vulnerability, exploit, reference fix, EDD, graph, export, network-room, debug endpoint, admin endpoint, or direct DB checker path was introduced.

## 2026-08-30 — W04-T02 Deterministic Risk Scoring and Alert Generation Baseline

Status: completed.

Actions:

- added `internal/risk` deterministic scoring and alert-generation service;
- defined amount bucket, country, counterparty fingerprint, and typology-hint scoring weights;
- added owner-scoped transaction risk-score update behavior;
- wired `cmd/aml-api` to run synchronous in-process risk scoring after transaction creation;
- kept `cmd/aml-worker` as a no-op placeholder with no queue or background processing;
- added risk service tests for determinism, bucket boundaries, country/fingerprint impact, idempotent alert generation, non-suspicious suppression, suspicious alert creation, and cross-owner denial;
- added HTTP hook coverage and opt-in live PostgreSQL risk/alert integration coverage;
- updated worker/async, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_04_W04-T02_handoff.md`.

Scope preserved:

- no nondeterministic ML, external API, random scoring, timing-dependent worker, side view, graph/export/network-room behavior, checker logic, planned vulnerability, exploit, reference fix, private case-note exposure, EDD exposure, debug endpoint, admin endpoint, or direct DB checker path was introduced.

## 2026-08-30 — W04-T03 Owner Alert, Case, and Private-Note APIs

Status: completed.

Actions:

- added authenticated owner-scoped HTTP routes for alert queue, alert read, claim, triage, case creation, case read, case status update, private note creation, and private note listing;
- added explicit alert, case, and case-note request/response DTOs that omit persistence-only owner fields and auth/session internals;
- wired `cmd/aml-api` with real alert and casework repositories;
- mapped invalid investigation transitions and duplicate cases to stable JSON conflict responses;
- added HTTP tests for unauthenticated rejection, owner alert queue, claim/triage transitions, case creation/status, private note create/list, cross-owner fail-closed behavior, malformed path/input handling, absent checker/public/side-view routes, and note-body non-leakage;
- added an opt-in live PostgreSQL owner investigation API test covering the future checker place 1 product-normal path;
- updated API, authorization, visibility, flag-store, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_04_W04-T03_handoff.md`.

Scope preserved:

- no checker-specific route, hidden debug route, merge-preview, audit timeline, graph, export, network-room, EDD, planned vulnerability, exploit, reference fix, public attack data, foreign private-note exposure, admin endpoint, or direct DB checker path was introduced.

## 2026-08-30 — W04-T04 Wave 04 Gate, Docs, and Validation Summary

Status: completed.

Actions:

- added `scripts/check_wave04_gate.py` to validate Wave 04 migration, route, DTO, repository, private-note visibility, live-gate, handoff, docs, ForcAD, and retained prior-wave invariants;
- added regression tests for Wave 04 gate pass/fail conditions;
- added `make wave04-gate` and `make live-wave04-integration`;
- updated README command/status surface for Wave 04;
- updated roadmap and waves status ledger so Wave 03 is complete and Wave 04 is `needs fixes` pending orchestrator review;
- added Wave 04 validation summary;
- updated testing strategy and risk register.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_04_W04-T04_handoff.md`.

Scope preserved:

- no checker behavior, vulnerability, exploit, reference fix, public attack data, side-view leak, EDD, graph, export, network-room, debug endpoint, admin endpoint, or direct DB checker path was introduced.

## 2026-08-30 — W05-T01 EDD Persistence and Repository

Status: completed.

Actions:

- added ordered Wave 05 migration `000004_create_edd_records.sql`;
- added owner-scoped `internal/edd` repository create, get-by-owner/customer, and update-by-owner/customer methods;
- added EDD domain errors for not-found, duplicate current record, and invalid input;
- enforced one current EDD record per customer through a unique `customer_id` constraint;
- constrained `review_status` to `DRAFT`, `IN_REVIEW`, `APPROVED`, or `REJECTED`;
- added migration and repository tests for happy path, duplicate mapping, cross-owner denial, invalid status, cross-analyst rejection, canceled context, and confidential-comment storage;
- updated domain, database, authorization, visibility, flag-store, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_05_W05-T01_handoff.md`.

Scope preserved:

- no checker PUT/GET for place 2, public attack data, private checker state, artificial flag field, EDD HTTP API, planned vulnerability, exploit, reference fix, graph/export/network-room/audit endpoint, debug endpoint, admin endpoint, ForcAD config change, or direct DB checker path was introduced.

## 2026-08-30 — W05-T02 EDD Owner HTTP API and DTOs

Status: completed.

Actions:

- wired the EDD repository into `cmd/aml-api` and the HTTP server option set;
- added authenticated owner routes for `POST /api/customers/{customer_id}/edd`, `GET /api/customers/{customer_id}/edd`, and `PATCH /api/customers/{customer_id}/edd`;
- added explicit EDD create/update request DTOs and an EDD owner response DTO;
- mapped EDD duplicate, invalid-input, and not-found repository errors to stable JSON responses;
- added HTTP tests for unauthenticated rejection, owner create/get/patch, duplicate conflict, cross-owner fail-closed access, invalid status, malformed body, unknown fields, absent side-view routes, and non-EDD response body leak checks;
- updated API, authorization, visibility, flag-store, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_05_W05-T02_handoff.md`.

Scope preserved:

- no checker place 2 behavior, public attack data, hidden checker shortcut, planned vulnerability, exploit, reference fix, graph/export/network/entity/audit route, debug endpoint, admin endpoint, ForcAD config change, or direct DB checker path was introduced.

## 2026-08-30 — W05-T03 EDD Integration, Visibility Regression, and Documentation

Status: completed.

Actions:

- added an opt-in live PostgreSQL EDD API integration test using `SENTINEL_AML_INTEGRATION_DATABASE_URL`;
- exercised clean migration application plus real auth, customer, and EDD repositories through the HTTP server;
- strengthened EDD visibility regression coverage for non-EDD response bodies and absent public/checker/graph/export/network/audit side views;
- added docs-tree regression coverage for Wave 05 EDD route, visibility matrix, future checker, and worker no-op documentation;
- aligned domain/database/visibility/worker/testing docs with the owner EDD API now being present and checker/public/side-view behavior still deferred;
- updated the risk register and added the W05-T03 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_05_W05-T03_handoff.md`.

Scope preserved:

- no checker or flag placement behavior, public attack data, planned vulnerability, exploit, reference fix, graph/export/network/audit side view, debug endpoint, admin endpoint, ForcAD config change, or direct DB checker path was introduced.

## 2026-08-30 — W05-T04 Wave 05 Gate and Validation Summary

Status: completed.

Actions:

- added `scripts/check_wave05_gate.py` to validate Wave 05 migrations, EDD route/DTO/repository contracts, private-field visibility, live-gate wiring, handoff reports, docs status, ForcAD config, and absent checker/public/side-view behavior;
- added Python regression tests for Wave 05 gate pass/fail conditions;
- added `make wave05-gate` and `make live-wave05-integration`;
- updated README command/status surface for Wave 05;
- updated roadmap, waves, source-of-truth, testing, and risk documentation so Wave 04 is complete and Wave 05 remains `needs fixes` pending orchestrator review;
- added the Wave 05 validation summary and W05-T04 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_05_W05-T04_handoff.md`.

Scope preserved:

- no product behavior, checker PUT/GET path, public attack data, planned vulnerability, exploit, reference fix, graph/export/network/audit/dedup side view, debug endpoint, admin endpoint, ForcAD config change, or direct DB checker path was introduced.

## 2026-08-30 — W06-T01 Projection Allowlists and Presenter Boundaries

Status: completed.

Actions:

- added `internal/projection` with explicit allowlisted contracts for current owner customer/account/transaction, alert/case, owner case-note, owner EDD, and future safe public/side-view summary shapes;
- added projection reflection tests that fail when allowlisted JSON tags drift or private fields appear outside owner note/EDD contracts;
- added repository-level projection visibility tests that confirm current/future contract counts and guard against direct domain-model writes in HTTP handlers;
- updated API, authorization, visibility/projection, testing, and risk documentation;
- added the W06-T01 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_06_W06-T01_handoff.md`.

Scope preserved:

- no route surface expansion, checker PUT/GET path, public attack data, planned vulnerability, exploit, reference fix, graph/export/network/audit/dedup route, debug endpoint, admin endpoint, ForcAD config change, or direct DB checker path was introduced.

## 2026-08-30 — W06-T02 HTTP Visibility and Leak Regression Suite

Status: completed.

Actions:

- added a consolidated HTTP visibility regression test that plants high-entropy private case-note and EDD confidential-comment sentinel strings;
- verified those sentinels appear only in owner `GET /api/cases/{case_id}/notes` and owner `GET /api/customers/{customer_id}/edd` responses;
- added table-driven leak probes for unauthenticated routes, cross-owner routes, auth/me, customer/account/transaction responses, alert queue/detail, case shell, unsupported profile/risk routes, invalid-path/method errors, and absent graph/export/network/entities/checker/attack-data/duplicates/timeline routes;
- updated API, visibility/projection, testing, and risk documentation;
- added the W06-T02 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_06_W06-T02_handoff.md`.

Scope preserved:

- no graph/export/network/audit/dedup side-view route, checker PUT/GET path, public attack data, planned vulnerability, exploit, reference fix, debug endpoint, admin endpoint, ForcAD config change, or direct DB checker path was introduced.

## 2026-08-30 — W06-T03 Cross-Owner Fail-Closed Authorization Matrix

Status: completed.

Actions:

- added `internal/authz` owner-scope contracts for current customer, account, transaction, alert, case, case-note, and EDD resources;
- added a consolidated HTTP cross-owner authorization matrix covering object reads, lists, creates, claims, triage, status updates, case notes, and EDD operations;
- verified object-scoped cross-owner attempts return stable `404 not_found` without private note or EDD sentinel leakage;
- verified alert queue remains owner-filtered rather than broadly exposing alerts;
- added boundary checks for unauthenticated protected routes and malformed IDs;
- updated authorization, visibility, testing, and risk documentation;
- added the W06-T03 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_06_W06-T03_handoff.md`.

Scope preserved:

- no new roles, supervisor/auditor/admin behavior, side-view route, checker PUT/GET path, public attack data, planned vulnerability, exploit, reference fix, debug endpoint, admin endpoint, ForcAD config change, or direct DB checker path was introduced.

## 2026-08-30 — W06-T04 Wave 06 Gate, Documentation Alignment, and Validation Summary

Status: completed.

Actions:

- added `scripts/check_wave06_gate.py` to validate retained migrations/routes, projection allowlists, HTTP leak regression tests, Cross-Owner Authorization Matrix tests, DTO private-field boundaries, sensitive-log guardrails, absent exploit/fix scripts, docs status, docs tree, and ForcAD config;
- added Python regression tests for Wave 06 gate pass/fail conditions;
- added `make wave06-gate`;
- updated README, roadmap, waves, source-of-truth, API, authorization, visibility, testing, and risk documentation so Wave 05 is complete and Wave 06 is `needs fixes` pending orchestrator review;
- added the Wave 06 validation summary and W06-T04 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_06_W06-T04_handoff.md`.

Scope preserved:

- no product behavior, checker PUT/GET path, public attack data, planned vulnerability, exploit, reference fix, graph/export/network/audit/dedup side-view route, debug endpoint, admin endpoint, ForcAD config change, or direct DB checker path was introduced.

## 2026-08-30 — W07-T01 Dedup Metadata, Migration, and Repository Foundation

Status: completed.

Actions:

- resolved canonical dedup metadata placement as non-secret `cases.dedup_hint`;
- added ordered migration `000005_add_case_dedup_hint.sql` with a nonblank-when-set constraint and dedup indexes;
- extended `internal/casework` with normalized dedup hint persistence and owner-verified duplicate candidate discovery;
- added casework repository tests for normalized hints, same-hint candidates, source exclusion query shape, empty hints, cross-owner source denial, private-field exclusion, and canceled contexts;
- updated migration tests for Wave 07 order, dedup metadata, and continued absence of out-of-scope tables/private checker fields;
- updated domain, database, visibility/projection, vulnerability matrix, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_07_W07-T01_handoff.md`.

Scope preserved:

- no HTTP dedup endpoint, checker PUT/GET path, public attack data, planned vulnerability, exploit, reference fix, graph/export/network/audit route, debug endpoint, admin endpoint, ForcAD config change, private-note exposure, EDD confidential-comment exposure, or direct DB checker path was introduced.

## 2026-08-30 — W07-T02 Secure Dedup HTTP Endpoints and Projection Wiring

Status: completed.

Actions:

- added explicit `CaseDuplicatePreviewView`, list, and merge-preview HTTP response DTOs;
- added authenticated `GET /api/cases/{case_id}/duplicates` and `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`;
- wired routes through owner-verified casework duplicate candidate discovery;
- added `case_duplicate_preview` to projection allowlists with only case ID, public summary, public risk tags, overlap score, and match explanation;
- added HTTP tests for owner candidate listing, secure merge preview, non-candidate failure, unknown/malformed IDs, cross-owner source denial, and forbidden private markers;
- updated visibility leak regression to probe the new dedup endpoints for private note and EDD sentinel non-leakage;
- updated API, authorization, visibility/projection, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_07_W07-T02_handoff.md`.

Scope preserved:

- no planned AML-1 vulnerable behavior, checker PUT/GET path, public attack data, exploit script, reference fix, graph/export/network/audit behavior, debug endpoint, admin endpoint, ForcAD config change, private note body exposure, EDD confidential-comment exposure, or direct DB checker path was introduced.

## 2026-08-31 — W07-T03 Dedup Visibility Regression and Anti-AML-1 Tests

Status: completed.

Actions:

- added named anti-AML-1 HTTP tests that plant victim `CaseNote.body` and `EDDRecord.confidential_comment` sentinel values in duplicate candidates;
- added dedup list and merge-preview response-shape checks for `CaseDuplicatePreviewView`;
- expanded current side-view projection tests to reject private fields in dedup projections;
- added source guardrails that fail if dedup DTOs or presenters reference private note, EDD, audit/diff, auth/session, owner ID, raw DB row, checker-private, or artificial flag markers;
- updated visibility, vulnerability matrix, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_07_W07-T03_handoff.md`.

Scope preserved:

- no planned AML-1 vulnerable behavior, checker PUT/GET path, public attack data, exploit script, reference fix, graph/export/network/audit behavior, debug endpoint, admin endpoint, ForcAD config change, private note body exposure, EDD confidential-comment exposure, or direct DB checker path was introduced.

## 2026-08-31 — W07-T04 Wave 07 Gate, Docs Alignment, and Validation Summary

Status: completed.

Actions:

- added `scripts/check_wave07_gate.py` to validate dedup metadata, secure dedup routes, public-only DTO/projection fields, anti-AML-1 tests, absent exploit/fix scripts, absent checker/public attack-data routes, docs status, docs tree, and ForcAD config;
- added Python regression tests for Wave 07 gate pass/fail conditions;
- added `make wave07-gate`;
- updated README, roadmap, waves, source-of-truth, API, database, testing, vulnerability matrix, and risk documentation so Wave 06 is complete and Wave 07 is `needs fixes` pending orchestrator review;
- added the Wave 07 validation summary and W07-T04 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_07_W07-T04_handoff.md`.

Scope preserved:

- no product behavior beyond validation wiring, checker PUT/GET path, public attack data, planned vulnerability, exploit script, reference fix, graph/export/network/audit behavior, debug endpoint, admin endpoint, ForcAD config change, private note body exposure, EDD confidential-comment exposure, or direct DB checker path was introduced.

## 2026-08-31 — W08-T01 Audit Persistence and Redaction Primitives

Status: completed.

Actions:

- added ordered `000006_create_audit_events.sql` migration with normalized audit event fields, constraints, and indexes;
- added `internal/audit` repository primitives for appending events, redacting sensitive field diffs, and listing case timelines through an owner-scoped case join;
- added repository and migration tests proving raw private note and EDD sentinels are redacted before persistence;
- updated database, visibility, worker, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_08_W08-T01_handoff.md`.

Scope preserved:

- no audit HTTP route, checker PUT/GET path, public attack data, planned vulnerability, exploit script, reference fix, graph/export/network behavior, debug endpoint, admin endpoint, ForcAD config change, or direct DB checker path was introduced.

## 2026-08-31 — W08-T02 Audit Instrumentation and Owner Timeline API

Status: completed.

Actions:

- added optional HTTP audit repository wiring and explicit owner case timeline DTOs;
- instrumented successful case creation, case status changes, private note creation, and EDD create/update with redacted audit events;
- added `GET /api/cases/{case_id}/timeline` behind the existing authenticated case owner boundary;
- added projection allowlist coverage for owner case audit views and redacted audit change records;
- added HTTP tests for owner timeline happy path, cross-owner and unauthenticated fail-closed behavior, private sentinel non-leakage, audit DTO shape, EDD update redaction, and absent future routes;
- updated API, authorization, visibility/projection, audit invariant, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_08_W08-T02_handoff.md`.

Scope preserved:

- no AML-2 vulnerable behavior, checker PUT/GET path, public attack data, exploit script, reference fix, graph/export/network/entity activity, customer activity, raw audit endpoint, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, or direct DB checker path was introduced.

## 2026-08-31 — W08-T03 Anti-AML-2 Regression and Source Guards

Status: completed.

Actions:

- added named Anti-AML-2 HTTP tests that plant `CaseNote.body` and `EDDRecord.confidential_comment` sentinels and verify owner timeline/activity surfaces do not disclose them;
- added audit DTO and presenter source guard coverage for raw private fields, raw `diff_json`, hashes, credentials, sessions, checker-private markers, and artificial flag fields;
- added projection allowlist tests for `owner_case_audit` and redacted audit changes;
- updated visibility, vulnerability matrix, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_08_W08-T03_handoff.md`.

Scope preserved:

- no AML-2 vulnerable behavior, checker PUT/GET path, public attack data, exploit script, reference fix, graph/export/network/entity activity, raw audit endpoint, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, or direct DB checker path was introduced.

## 2026-08-31 — W08-T04 Wave 08 Gate, Documentation Alignment, and Validation Summary

Status: completed.

Actions:

- added `scripts/check_wave08_gate.py` to validate audit migration/repository contracts, secure owner timeline route wiring, audit DTO/projection allowlists, Anti-AML-2 tests, absent exploit/fix scripts, absent checker/public attack-data/graph/export/network/debug/admin routes, docs status, docs tree, and ForcAD config;
- added Python regression tests for Wave 08 gate pass/fail conditions;
- updated historical W05/W06/W07 gate regression expectations so they remain strict historical validators after the intentional Wave 08 audit expansion;
- added `make wave08-gate`;
- updated README, roadmap, waves, source-of-truth, API, database, visibility/projection, vulnerability matrix, testing, and risk documentation so Wave 07 is complete and Wave 08 is `needs fixes` pending orchestrator review;
- added the Wave 08 validation summary and W08-T04 handoff report.

Verification:

- `make wave08-gate` could not run on this Windows host because `make` is not installed on `PATH`; its target exists and all underlying commands were run directly.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` initially hit the known default Windows Go build-cache access-denied issue, then passed with `GOCACHE` pointed at a writable workspace cache.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` passed with the same writable `GOCACHE`.
- `python -B -m unittest discover -s tests -p "test_*.py"` passed with 70 tests.
- `python -B -m unittest discover -s tests -p "test_wave08_gate.py"` passed with 9 tests.
- `python -B scripts/check_docs_tree.py` passed.
- `python -B scripts/check_wave08_gate.py` passed.
- `python -B scripts/validate_forcad_config.py` passed.

Scope preserved:

- no production behavior, checker PUT/GET path, public attack data, planned vulnerability, exploit script, reference fix, graph/export/network route, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, or direct DB checker path was introduced.

## 2026-08-31 — W09-T02 Secure Graph HTTP Endpoints and DTOs

Status: completed.

Actions:

- added `GraphRepository` injection and wired secure authenticated graph routes under `/api/graph/entities/{entity_hint}`;
- added explicit `GraphEntityView`, `GraphRelatedCaseView`, and `EDDGraphSummaryView` HTTP DTOs plus presenter functions;
- wired `cmd/aml-api` to use the Wave 09 graph repository;
- added graph HTTP tests for authentication, owned-hint access, fail-closed unauthorized hints, response shape, and private sentinel non-leakage;
- extended the consolidated visibility regression to probe graph entity, related-case, and EDD-summary responses;
- updated projection allowlist contracts to move graph summaries from future placeholder status into current secure side-view contracts;
- updated API, authorization, visibility/projection, audit/export/graph invariant, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_09_W09-T02_handoff.md`.

Scope preserved:

- no AML-3 vulnerable behavior, checker PUT/GET path, public attack data, exploit script, reference fix, export route, network route, `/api/entities` route, graph root route, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, raw audit diff exposure, or direct DB checker path was introduced.

## 2026-08-31 — W09-T03 Anti-AML-3 Regression and Visibility Matrix

Status: completed.

Actions:

- added named Anti-AML-3 HTTP tests that plant victim private note and EDD confidential-comment sentinels and verify graph entity, related-case, and EDD-summary responses never disclose them;
- added projection contract checks for graph DTO allowlists and forbidden private fields;
- added source-level graph repository, DTO, and presenter guards for private-store, audit, auth/session, owner, trace, checker-private, and artificial flag markers;
- updated visibility, vulnerability matrix, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_09_W09-T03_handoff.md`.

Scope preserved:

- no AML-3 vulnerable behavior, checker PUT/GET path, public attack data, exploit script, reference fix, export route, network route, graph root route, debug endpoint, admin endpoint, raw private note exposure, raw EDD confidential-comment exposure, raw audit diff exposure, or direct DB checker path was introduced.

## 2026-08-31 — W09-T04 Wave 09 Gate, Documentation Alignment, and Validation Summary

Status: completed.

Actions:

- added `scripts/check_wave09_gate.py` to validate graph migration/repository contracts, secure graph route wiring, graph DTO/projection allowlists, Anti-AML-3 tests, absent exploit/fix scripts, absent checker/public attack-data/export/network/debug/admin routes, docs status, docs tree, and ForcAD config;
- added Python regression tests for Wave 09 gate pass/fail conditions;
- added `make wave09-gate`;
- updated README, roadmap, waves, source-of-truth, testing, risk, validation summary, and handoff documentation so Wave 08 is complete and Wave 09 is `needs fixes` pending orchestrator review.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_09_W09-T04_handoff.md`.

Scope preserved:

- no production behavior, checker PUT/GET path, public attack data, planned vulnerability, exploit script, reference fix, export route, network route, graph root route, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, raw audit diff exposure, or direct DB checker path was introduced.

## 2026-08-31 — W10-T01 Export Persistence and Redaction Primitives

Status: completed.

Actions:

- added `migrations/000008_create_exports_disputes.sql` with `disputes`, `exports`, and `export_items`;
- added `internal/exporting` repository and recursive redaction primitives for public/redacted export bundles;
- added export projection allowlists and redaction tests for root and linked private note, EDD, and audit sentinels;
- updated API, database, visibility, audit/export/graph invariant, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_10_W10-T01_handoff.md`.

Scope preserved:

- no HTTP export route, checker PUT/GET path, public attack data, planned AML-4 behavior, exploit script, reference fix, network route/table, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, raw audit diff exposure, or direct DB checker path was introduced.

## 2026-08-31 — W10-T02 Secure Export HTTP APIs and DTOs

Status: completed.

Actions:

- added authenticated secure export/dispute routes for `POST /api/cases/{case_id}/exports`, `GET /api/exports/{export_id}`, `POST /api/disputes`, and `POST /api/disputes/{dispute_id}/export`;
- wired the HTTP server and `cmd/aml-api` to the export repository;
- added explicit export/dispute request and response DTOs plus redacted export bundle presenters;
- added owner-scoped export/dispute repository lookup methods used by production HTTP routes;
- added HTTP tests for authentication, owner export creation/retrieval, dispute export, cross-owner denial, invalid input, absent out-of-scope routes, and private sentinel non-leakage;
- updated API, authorization, visibility/projection, audit/export/graph invariant, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_10_W10-T02_handoff.md`.

Scope preserved:

- no checker PUT/GET path, public attack data, planned AML-4 vulnerable behavior, exploit script, reference fix, network-room route/table, raw export route, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, raw audit diff exposure, or direct DB checker path was introduced.

## 2026-08-31 — W10-T03 Network-Room Persistence and Safe Dossier Model

Status: completed.

Actions:

- added `migrations/000009_create_network_rooms.sql` with `network_rooms`, `network_room_cases`, and `network_room_participants`;
- added `internal/networkroom` repository primitives for deterministic room creation/finding, case-reference attachment, participant joins/listing, participant-scoped room listing, and safe dossier construction;
- added network-room safe projection contracts for room summary, case summary, and dossier output;
- added migration, repository, dossier, and projection tests that reject private data copying and AML-5-style exposure;
- updated database, visibility/projection, worker, network-room model, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_10_W10-T03_handoff.md`.

Scope preserved:

- no network-room HTTP route, checker PUT/GET path, public attack data, planned AML-5 vulnerable behavior, exploit script, reference fix, worker, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, raw audit diff exposure, value-hash exposure, or direct DB checker path was introduced.

## 2026-08-31 — W10-T04 Secure Network-Room HTTP APIs and DTOs

Status: completed.

Actions:

- added authenticated secure network-room routes for `GET /api/network/rooms`, `GET /api/network/rooms/{room_id}`, `POST /api/network/rooms/{room_id}/join`, and `GET /api/network/rooms/{room_id}/dossier`;
- wired the HTTP server and `cmd/aml-api` to the network-room repository;
- added participant-scoped room lookup and safe dossier case listing repository primitives;
- added explicit network-room HTTP DTOs for room summaries, room details, participants, dossier cases, and dossiers;
- added HTTP tests for authentication, join/list/detail/dossier happy paths, non-participant fail-closed behavior, malformed paths, absent out-of-scope routes, and private sentinel non-leakage;
- updated API, authorization, visibility/projection, network-room model, testing, risk, and handoff documentation.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_10_W10-T04_handoff.md`.

Scope preserved:

- no checker PUT/GET path, public attack data, planned AML-5 vulnerable behavior, exploit script, reference fix, graph root route, raw/private network-room route, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, raw audit diff exposure, value-hash exposure, raw source case blob, or direct DB checker path was introduced.

## 2026-08-31 — W10-T05 Wave 10 Gate, Documentation Alignment, and Validation Summary

Status: completed.

Actions:

- added `scripts/check_wave10_gate.py` to validate Wave 10 migration/table scope, secure export redaction, references-only network-room behavior, secure route registration, DTO/projection allowlists, Anti-AML-4/Anti-AML-5 test markers, absent exploit/fix scripts, docs status, docs tree, and ForcAD config;
- added Python regression tests for Wave 10 gate pass/fail conditions;
- added `make wave10-gate`;
- updated README, roadmap, waves, source-of-truth, testing, risk, validation summary, and handoff documentation so Wave 09 is complete and Wave 10 is `needs fixes` pending orchestrator review;
- updated the Wave 09 gate unittest to the existing historical-gate pattern now that Wave 10 migrations and routes are intentional current-branch scope.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_10_W10-T05_handoff.md`.

Scope preserved:

- no production behavior, checker PUT/GET path, public attack data, planned AML-4 behavior, planned AML-5 behavior, exploit script, reference fix, debug endpoint, admin endpoint, ForcAD config change, raw private note exposure, raw EDD confidential-comment exposure, raw audit diff exposure, value-hash exposure, raw network-room source blob, or direct DB checker path was introduced.

## 2026-08-31 — W11-T01 Checker Contract, HTTP Client, and Safe State Schemas

Status: completed.

Actions:

- replaced the fail-closed checker placeholder with Wave 11 checker foundation helpers;
- added explicit `check`, `put`, and `get` action parsing with place 2 fail-closed behavior;
- added standard-library HTTP JSON helpers with deterministic request timeout;
- defined MACed private checker state for place 1 and credential-free public attack data;
- added idempotency key derivation with HMAC-SHA256 over flag, place, and service name;
- added checker foundation tests and updated checker/CTF/flag-store docs.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_11_W11-T01_handoff.md`.

Scope preserved:

- no product Go code, migrations, direct DB checker path, hidden endpoint, place 2 lifecycle, HAVOC, vulnerability, exploit script, or reference fix was introduced.

## 2026-08-31 — W11-T02 Place 1 PUT Workflow Through Normal Case-Note APIs

Status: completed.

Actions:

- implemented place 1 PUT through normal HTTP business APIs: register, login, customer, account, suspicious transaction, alert queue, alert claim, case create, and private case-note create;
- added deterministic checker-owned fixture data derived from the idempotency key;
- added fake HTTP server tests proving route order, PFR output shape, response validation, public-data exclusions, and raw flag confinement to the private note API request;
- updated checker and flag-store docs.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_11_W11-T02_handoff.md`.

Scope preserved:

- no product behavior change, direct DB path, side-view read, public attack-data route, place 2 lifecycle, HAVOC, vulnerability, exploit script, or reference fix was introduced.

## 2026-08-31 — W11-T03 Place 1 GET Workflow Through Owner Case-Note View

Status: completed.

Actions:

- implemented place 1 GET verification through the owner case-note list endpoint only;
- preserved private state MAC validation and token-first owner access with login fallback;
- mapped missing owner case/note view and missing expected note to corrupt checker failures;
- prevented server-provided HTTP error text from being echoed by checker errors;
- added fake HTTP tests for success, re-authentication, wrong flag, tampered state, missing note/view, auth failure, no side-view calls, and place 2 deferral;
- updated checker and flag-store docs with owner-note-only GET behavior and failure mapping.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_11_W11-T03_handoff.md`.

Scope preserved:

- no direct DB read, side-view retrieval, public attack-data credential use, place 2 lifecycle, HAVOC, vulnerability, exploit script, reference fix, debug endpoint, or admin endpoint was introduced.

## 2026-08-31 — W11-T04 Checker Regression Tests and No-Bypass Guardrails

Status: completed.

Actions:

- added `scripts/check_wave11_gate.py` with checker source, PFR schema, public/private separation, no-bypass, no-side-view, no-place-2, no-exploit/fix, docs, handoff, Makefile, and ForcAD checks;
- added CLI PUT PFR output-shape regression coverage;
- added `make wave11-gate`;
- updated testing strategy docs with Wave 11 checker coverage and non-goals.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_11_W11-T04_handoff.md`.

Scope preserved:

- no product feature implementation, migration, vulnerability, exploit, reference fix, place 2 lifecycle, HAVOC, debug/admin route, public attack-data route, or direct DB checker path was introduced.

## 2026-08-31 — W11-T05 Documentation, Validation Summary, and Wave 11 Gate Closure

Status: completed.

Actions:

- aligned roadmap, waves, source-of-truth, testing strategy, and risk register so Wave 10 is complete and Wave 11 is `needs fixes` pending orchestrator review;
- extended the Wave 11 gate to require W11-T05, `wave_11_validation_summary.md`, source-of-truth status, risk entries, and workspace-local Go cache/profile Makefile settings;
- added `tests/test_wave11_gate.py` regression coverage for Wave 11 gate pass/fail behavior;
- added the Wave 11 validation summary and W11-T05 handoff report.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_11_W11-T05_handoff.md`.

Scope preserved:

- no product behavior, migration, place 2 checker lifecycle, CHECK/HAVOC, vulnerability, exploit, reference fix, debug/admin route, public attack-data route, reusable secret, live credential, or direct DB checker path was introduced.

## 2026-09-01 — W13-T06 Wave 13 Gate and Documentation

Status: completed.

Actions:

- extended `scripts/check_wave13_gate.py` to require checker PUT/GET tests,
  CHECK/HAVOC tests, no early exploit/fix implementation files, no current
  vulnerable behavior markers, Makefile gate wiring, docs markers, and ForcAD
  config validity;
- added `make wave13-gate`;
- extended `tests/test_wave13_gate.py` with negative coverage for early
  exploit/fix files, vulnerable markers, and incomplete Makefile wiring;
- updated roadmap and waves ledgers so Wave 12 is complete and Wave 13 is
  `needs fixes` pending orchestrator review, with AML vertical slices queued
  behind Wave 13 acceptance;
- added `docs/wave_reports/wave_13_validation_summary.md`.

Verification:

- Final verification is recorded in `docs/wave_reports/wave_13_validation_summary.md`.

Scope preserved:

- no product behavior, migration, planned vulnerability, exploit script,
  reference fix implementation, debug/admin route, public attack-data route,
  reusable secret, live credential, or direct DB checker path was introduced.

## 2026-09-01 — W13-F01 Checker Discovery Liveness Fix

Status: completed.

Actions:

- identified the checker discovery hang risk in fake HTTP services that used
  `ThreadingHTTPServer` with HTTP/1.1 keep-alive but no daemon request-thread
  or explicit connection-close policy;
- updated checker fake PUT, GET, and CHECK/HAVOC HTTP servers to use daemon
  handler threads, non-blocking close behavior, explicit `Connection: close`
  JSON responses, and named joined serving threads;
- added lifecycle regression coverage proving fake service contexts close their
  serving threads and do not leave new non-daemon threads behind after real
  requests;
- reran checker discovery and Wave 13 component gates.

Verification:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"` completed
  97 tests and exited successfully.
- Detailed command results are recorded in
  `docs/wave_reports/wave_13_validation_summary.md`.

Scope preserved:

- no checker PUT/GET semantics, product behavior, migration, planned
  vulnerability, exploit script, reference fix implementation, debug/admin
  route, side-view flag recovery, public credential exposure, or direct DB
  checker path was introduced.

## 2026-09-01 — W13-F02 Gate Evidence and Roadmap Status Cleanup

Status: completed.

Actions:

- aligned Wave 13 validation evidence with the W13-F01 liveness fix and the
  orchestrator-observed `make wave13-gate` timeout;
- added `docs/wave_reports/wave_13_review.md` recording Wave 13 as
  `needs fixes` until the orchestrator reruns and accepts `make wave13-gate`;
- kept roadmap and waves status at `needs fixes` for Wave 13 while adding the
  W13-F01 close condition;
- updated the source-of-truth map so Wave 13, not Wave 12, is the current
  branch validation authority;
- added a mitigated checker-discovery liveness risk entry while carrying
  forward live restart, retry/idempotency, retention, and HAVOC/noise
  environment risks.

Verification:

- Documentation-only gate commands are recorded in
  `docs/wave_reports/wave_13_validation_summary.md` and W13-F02 handoff
  output.

Scope preserved:

- no product behavior, checker behavior, migration, planned vulnerability,
  exploit script, reference fix implementation, debug/admin route, public
  attack-data route, reusable secret, live credential, or direct DB checker
  path was introduced.

## 2026-09-01 — W14-T01 AML-1 Vulnerable Dedup Preview Profile

Status: completed pending orchestrator review.

Actions:

- introduced the AML-1 `aml1_vulnerable` Go build-tag profile for dedup
  merge-preview;
- preserved the default secure profile where duplicate candidates and
  merge-preview remain public-only;
- added a targeted casework lookup for duplicate case private note bodies,
  scoped by requester-owned source case and shared `dedup_hint`;
- added tagged HTTP tests proving the intended duplicate
  `private_notes[].body` exposure and rejecting EDD, audit, credential,
  session, checker-private, and unrelated internal leaks;
- added `scripts/check_wave14_gate.py` and Wave 14 gate regression tests;
- updated vulnerability, projection, testing, risk, validation, and handoff
  documentation.

Verification:

- Final local validation is recorded in
  `docs/wave_reports/wave_14_W14-T01_handoff.md`.

Scope preserved:

- no checker PUT/GET owner-path change, reference exploit script, reference fix
  implementation, debug/admin route, direct DB checker access, public
  credential exposure, EDD leak, audit leak, or unrelated projection broadening
  was introduced.

## 2026-09-01 — W14-T03 AML-1 Documentation and Risk Alignment

Status: completed pending orchestrator review.

Actions:

- marked Wave 14 as the AML-1 `aml1_vulnerable` profile implementation under
  review in roadmap and wave ledgers;
- made `docs/09_vulnerability_matrix.md` the explicit source of truth for AML
  vulnerable behavior, exploit/fix sequencing, and protected-field boundaries;
- recorded the AML-1 endpoint/process:
  `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`
  exposes duplicate `private_notes[].body` only in the tagged vulnerable
  profile;
- kept AML-1 exploit and fix work locked to later waves and kept AML-2 through
  AML-5 future-only;
- updated checker, visibility, testing, risk, source-of-truth, and validation
  documentation to preserve secure/default-profile and owner checker GET
  invariants.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave14_gate.py`

Scope preserved:

- no product behavior, checker behavior, reference exploit script, reference fix
  implementation, debug/admin route, direct DB checker path, broad leakage, or
  AML-2 through AML-5 implementation was introduced.

## 2026-09-01 — W14-F01 Checker Unittest and Gate Liveness Fix

Status: completed pending orchestrator review.

Actions:

- hardened checker fake HTTP server contexts so JSON responses are flushed
  before `Connection: close`;
- changed fake-service cleanup to call shutdown, join the serving thread, close
  the server, and fail deterministically if the serving thread remains alive;
- added a Wave 14 subprocess regression that runs
  `python -B -m unittest discover -s tests -p "test_checker_*.py"` and fails
  if the child process prints `OK` but does not return control;
- updated Wave 14 gate checks, testing strategy, validation summary, and risk
  register to record the liveness guard.

Verification:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"` completed
  97 tests in 34.598s and exited with status 0.
- `python -B -m unittest discover -s tests -p "test_wave14_gate.py"`
  completed 8 tests in 34.952s and exited with status 0.
- Wave 14 component gates, default Go tests, tagged AML-1 Go tests, and Go vet
  passed with offline settings.

Scope preserved:

- no checker PUT/GET semantics, CHECK/HAVOC behavior, AML-1 vulnerable
  projection behavior, product route, debug/admin endpoint, direct DB checker
  path, reference exploit, reference fix, or AML-2 through AML-5 activation was
  introduced.

## 2026-09-01 — W14-F02 Wave 14 Gate and Handoff Evidence Completion

Status: completed pending orchestrator review.

Actions:

- added dedicated W14-T02 and W14-T03 handoff reports with self-review evidence;
- updated the Wave 14 validation summary to list W14-T01, W14-T02, and W14-T03
  handoff evidence explicitly;
- extended `scripts/check_wave14_gate.py` so the Wave 14 gate requires all
  three task handoff reports;
- added a Wave 14 gate regression that fails when W14-T03 handoff evidence is
  missing;
- updated testing strategy and risk register to record the handoff-evidence
  guard.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave14_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`

Scope preserved:

- no AML-1 behavior, checker behavior, product behavior, reference exploit,
  reference fix, AML-2 through AML-5 behavior, debug/admin route, public
  credential, or broad sensitive-field visibility change was introduced.

## 2026-09-01 — W15-T01 AML-2 Vulnerable Audit Timeline Profile

Status: implemented pending orchestrator review.

Actions:

- added the `aml2_vulnerable` Go build-tag profile for the audit timeline
  presenter while keeping the default audit profile redacted;
- routed owner case timeline responses through `caseAuditViewsForProfile`;
- implemented the tagged AML-2 projection so only `case_note.body` changes for
  owner `case_note` events expose `CaseNote.body`;
- added tagged AML-2 tests proving the intended timeline leak and graph/export/
  network-room non-leakage;
- added `scripts/check_wave15_gate.py`, Wave 15 gate tests, and
  `make wave15-gate`;
- updated the competition matrix gate so AML-1 and AML-2 vulnerable-checker
  cells are concrete while exploit/fix cells remain pending;
- updated vulnerability, visibility, audit/export/graph, testing, risk, and
  validation-summary docs for Wave 15.

Verification:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"`
- `python -B -m unittest discover -s tests -p "test_wave15_gate.py"`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml2_vulnerable ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`
- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave15_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/validate_forcad_config.py`
- `make wave15-gate`

Scope preserved:

- no checker PUT/GET owner path, AML-1 behavior, AML-3 through AML-5 behavior,
  reference exploit, reference fix, debug/admin endpoint, direct DB checker
  path, graph/export/network-room projection widening, or EDD confidential
  comment leak was introduced.

## 2026-09-01 — W15-T03 AML-2 Documentation and Risk Alignment

Status: completed pending orchestrator review.

Actions:

- aligned `docs/13_roadmap.md` and `docs/waves.md` so Wave 15 is under review
  for the implemented `aml2_vulnerable` profile instead of planned future work;
- added Wave 15 authority to `docs/source_of_truth_map.md`, with
  `docs/09_vulnerability_matrix.md` retained as the vulnerability behavior
  source of truth;
- clarified in `docs/08_checker_design.md` that AML-2 audit timeline exposure
  is not a checker GET path;
- corrected stale secure-baseline wording so the Wave 08 gate is historical
  after Wave 15;
- refreshed Wave 15 validation evidence for the documentation/gate checks.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave15_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`

Scope preserved:

- no AML-2 reference exploit, AML-2 reference fix, AML-3 through AML-5 active
  status, secure-baseline invariant removal, checker GET side-view dependency,
  debug/admin shortcut, or broad-leak documentation was introduced.

## 2026-09-01 — W15-F01 Checker Discovery Liveness Fix

Status: fixed locally; wrapper closure blocked on this Windows host by missing
`make`.

Actions:

- hardened fake checker HTTP server teardown for PUT, GET, and CHECK workflow
  tests by closing server sockets in a `finally` path before waiting on serving
  threads;
- bounded accepted fake-service socket reads and shortened `serve_forever`
  polling so shutdown is deterministic under full unittest discovery;
- added a Wave 15 subprocess liveness regression that runs
  `python -B -m unittest discover -s tests -p "test_checker_*.py"` and fails
  if the child process prints `OK` but does not return;
- extended `scripts/check_wave15_gate.py` so the Wave 15 gate requires that
  liveness regression marker;
- refreshed Wave 15 validation, testing strategy, and risk-register evidence.

Verification:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"` exited 0
  after 97 tests in 4.793s.
- `python -B -m unittest discover -s tests -p "test_wave15_gate.py"` exited 0
  after 8 tests in 5.337s.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`
  exited 0.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags
  aml2_vulnerable ./...` exited 0.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`
  exited 0.
- `python -B scripts/check_docs_tree.py`, `python -B
  scripts/check_wave15_gate.py`, `python -B
  scripts/check_competition_matrix_gate.py`, and `python -B
  scripts/validate_forcad_config.py` exited 0.
- `make wave15-gate` exited 1 on this Windows host because no make-compatible
  executable is installed on PATH; the target contents were statically
  validated and each component command passed directly.

Scope preserved:

- no checker PUT/GET semantics, CHECK/HAVOC behavior, AML-2 profile behavior,
  AML-3 through AML-5 activation, reference exploit, reference fix,
  debug/admin endpoint, direct DB checker path, or broad sensitive-field
  visibility change was introduced.

## 2026-09-01 — W15-F02 Wave Status and Validation Evidence Reconciliation

Status: documentation reconciled pending orchestrator re-review.

Actions:

- changed authoritative roadmap and wave ledgers so Wave 15 is `needs fixes`
  rather than `under review` after the orchestrator reproduced checker
  discovery liveness failure;
- preserved Wave 13 historical review state as `needs fixes` and appended a
  reconciliation note instead of rewriting the review record;
- kept Wave 14 under review because the active snapshot has Wave 14 validation
  and handoff evidence but no accepted `wave_14_review.md` artifact;
- marked Wave 16 and later execution as blocked until Wave 15 liveness
  re-review passes and upstream review state is reconciled;
- updated the source-of-truth map and Wave 15 validation summary so local
  component success is not treated as final `make wave15-gate` closure.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave15_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`

Scope preserved:

- no product behavior, checker behavior, migration, vulnerability scope,
  exploit script, reference fix, debug/admin shortcut, direct DB checker path,
  or broad sensitive-field visibility change was introduced.

## 2026-09-01 — W16-T03 AML-3 Documentation and Risk Alignment

Status: documentation aligned; Wave 16 remains under review.

Actions:

- updated the vulnerability matrix so AML-3 is implemented only in the
  `aml3_vulnerable` profile and remains under review rather than complete;
- documented the exact AML-3 endpoint,
  `GET /api/graph/entities/{entity_hint}/edd-summaries`, and the single tagged
  leak field, `confidential_comment`;
- aligned visibility/projection and audit/export/graph invariants so the
  default graph build stays metadata-only and the tagged vulnerable behavior is
  explicitly local to graph EDD summaries;
- updated testing strategy, roadmap, waves, and source-of-truth map so Wave 21
  unlocks only after Wave 16 acceptance and AML-3 exploit/fix artifacts remain
  locked;
- added Wave 16 validation-summary and W16-T03 handoff evidence;
- added AML-3 scope and Wave 16 gate-drift risks to the risk register.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave16_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`

Scope preserved:

- no product behavior, checker behavior, AML-4/AML-5 activation, reference
  exploit, reference fix, debug/admin shortcut, direct DB checker path, public
  credential exposure, checker-private state exposure, or broad graph/export/
  network/audit leak was introduced.

## 2026-09-02 — W16-F01 Status Ledger and Historical Gate Reconciliation

Status: reconciled after orchestrator Wave 16 aggregate gate acceptance.

Actions:

- added ADR-0003 to distinguish point-in-time historical wave gates from
  current-branch aggregate gates;
- updated roadmap, waves, and source-of-truth ledgers so Waves 13 through 16
  are complete after the orchestrator review host reported `make wave16-gate`
  exiting 0;
- preserved the missing standalone Wave 14 and Wave 15 accepted review
  artifacts as documented evidence gaps rather than inventing them;
- marked Wave 17 as ready, kept Wave 18 queued at that time, and exploit/fix
  waves as locked to the ADR-0002/ADR-0003 sequence;
- updated risk-register entries for status drift, AML-3 scope, Wave 16 gate
  drift, and historical-gate semantics;
- extended the Wave 16 gate with a status-ledger reconciliation check.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave16_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/validate_forcad_config.py`
- `python -B -m unittest discover -s tests -p "test_wave16_gate.py"`

Scope preserved:

- no product code, checker code, migrations, ForcAD config, AML-4/AML-5
  behavior, reference exploit, reference fix, debug/admin shortcut, direct DB
  checker path, broad serializer leak, public credential exposure, or
  checker-private state exposure was introduced.

## 2026-09-02 — W17-T03 AML-4 Documentation and Risk Alignment

Status: documentation aligned at the time; superseded by W17-F02, which marks
Wave 17 complete after W17-F01 wrapper evidence.

Actions:

- updated the vulnerability matrix so AML-4 is implemented only in the
  `aml4_vulnerable` profile; this entry predated the W17-F01 wrapper fix and
  W17-F02 status reconciliation;
- documented the exact AML-4 process,
  `POST /api/disputes/{dispute_id}/export`, and the tagged leak field,
  `linked_private_notes[].body`;
- aligned visibility/projection and audit/export/graph invariants so the
  default export build stays recursively redacted and the tagged vulnerable
  behavior is explicitly local to linked duplicate-case private notes;
- updated testing strategy, roadmap, waves, and source-of-truth map so Wave 22
  unlocks only after Wave 17 acceptance and AML-4 exploit/fix artifacts remain
  locked;
- added Wave 17 validation-summary and W17-T03 handoff evidence;
- added AML-4 scope and Wave 17 gate/AML-5 drift risks to the risk register.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave17_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`

Scope preserved:

- no product behavior, checker behavior, AML-5 activation, reference exploit,
  reference fix, debug/admin shortcut, direct DB checker path, public
  credential exposure, checker-private state exposure, EDD comment leak,
  network-room leak, or broad export serialization was introduced.

## 2026-09-02 — W17-F02 Status Reconciliation After Deterministic Gate Fix

Status: reconciled; Wave 17 is complete after W17-F01 wrapper evidence.

Actions:

- updated roadmap, waves, source-of-truth map, risk register, and Wave 17
  validation summary so they agree that Wave 17 is accepted/complete after
  `timeout 300 make wave17-gate` exited 0 with the AML-4 tagged sweep
  serialized as `go test -p 1 -tags aml4_vulnerable ./...`;
- kept Wave 18 queued as the next vulnerability wave at
  that point; this historical note is superseded by W18-T01/T02, which
  implemented and gated AML-5 under review;
- kept AML-4 exploit and fix waves locked to Wave 22 and Wave 27 sequencing;
- added the W17-F02 handoff report.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave17_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/validate_forcad_config.py`

Scope preserved:

- no product code, checker code, migrations, ForcAD config, vulnerable profile
  code, sploit file, fix file, AML-5 implementation, sensitive-field public
  reclassification, debug/admin toggle, or broad export leak documentation was
  introduced.

## 2026-09-02 — W18-T01 AML-5 Vulnerable Network-Room Profile

Status: implemented pending orchestrator review.

Actions:

- added the `aml5_vulnerable` Go build-tag profile for network-room dossiers
  while keeping the default dossier profile references-first and safe;
- routed the network-room dossier handler through secure/default and tagged
  profile hooks after the normal participant-scoped room access check;
- implemented bounded tagged dossier output for foreign source-case private
  note bodies and EDD confidential comments as `foreign_private_notes` and
  `foreign_edd_comments`;
- added tagged HTTP and repository tests proving the intended leak only after
  the normal room path and rejecting credentials, sessions, checker-private
  state, audit diffs, raw rows, public attack data, debug/admin controls, and
  unrelated private fields;
- added `scripts/check_wave18_gate.py`, Wave 18 gate tests, and W18-T01
  handoff evidence.

Verification:

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml5_vulnerable ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`
- `python -B -m unittest discover -s tests -p "test_wave18_gate.py"`
- `python -B scripts/check_wave18_gate.py`
- `python -B scripts/check_docs_tree.py`

Scope preserved:

- no checker PUT/GET logic, public attack data, ForcAD config, AML-1 through
  AML-4 behavior, reference exploit, reference fix, runtime vulnerability
  toggle, debug/admin shortcut, direct DB checker path, default secure
  network-room profile, or root owner API behavior was changed.

## 2026-09-02 — W18-T02 Wave 18 Gate and Competition Matrix Update

Status: gated pending orchestrator review.

Actions:

- added `make wave18-gate` with checker unittest discovery, Wave 18 gate tests,
  competition-matrix tests, default Go tests, serialized AML-5 tagged Go tests,
  Go vet, docs tree, Wave 18 gate, competition matrix, and ForcAD validation;
- updated `scripts/check_wave18_gate.py` so the gate validates the Makefile
  wrapper and deterministic `go test -p 1 -tags aml5_vulnerable ./...` policy;
- updated the competition matrix gate so AML-1 through AML-5 vulnerable-checker
  cells are concrete while exploit-success, fixed checker, exploit-blocked,
  and anti-coarse-fix cells remain pending;
- kept AML-5 reference exploit and fix artifacts locked and added regression
  tests that reject early `aml_network_room.py` and network-room fix files;
- added W18-T02 handoff evidence with `timeout 300 make wave18-gate` exiting 0.

Verification:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"`
- `python -B -m unittest discover -s tests -p "test_wave18_gate.py"`
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -p 1 -tags aml5_vulnerable ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`
- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave18_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/validate_forcad_config.py`
- `timeout 300 make wave18-gate`

Scope preserved:

- no product semantics, checker behavior, public attack data, ForcAD config,
  reference sploit, reference fix, AML-1 through AML-4 profile behavior,
  runtime vulnerability switch, debug/admin endpoint, direct DB checker path,
  broad serialization, credential/session leak, or checker-private leak was
  introduced.

## 2026-09-02 — W18-T03 Wave 18 Documentation and Status Alignment

Status: documentation aligned pending orchestrator review.

Actions:

- aligned the vulnerability matrix, visibility model, network-room model,
  worker boundary, testing strategy, roadmap, waves, source-of-truth map, risk
  register, execution log, and Wave 18 validation summary with W18-T01/T02
  results;
- recorded Wave 18 as under review, not accepted, after local
  `timeout 300 make wave18-gate` evidence;
- documented default secure network-room behavior, tagged AML-5 behavior,
  protected exclusions, and the intended `foreign_private_notes` /
  `foreign_edd_comments` dossier path;
- kept Wave 23 and `sploits/sentinel_aml/aml_network_room.py` locked pending
  Wave 18 acceptance.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave18_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`

Scope preserved:

- no code, checker logic, config, sploit, fix, or previous-wave behavior was
  changed.

## 2026-09-02 — W18-F03 Wave 18 Status Ledger Reconciliation

Status: reconciled; Wave 18 is complete and Wave 19 is the only next unlocked
wave.

Actions:

- updated roadmap, waves, source-of-truth map, risk register, and Wave 18
  validation summary so they agree that Wave 18 is accepted after W18-F01 and
  W18-F02 evidence;
- recorded that W18-F01 replaced the non-terminating aggregate AML-5 tagged Go
  sweep with deterministic package-by-package tagged execution;
- recorded that W18-F02 added archive hygiene to `make wave18-gate`, kept Go
  cache and application-data scratch outside the deliverable tree, and proved
  the tree clean;
- unlocked only Wave 19 for the AML-1 reference exploit and kept Wave 20 and
  later locked until the staged exploit/fix sequence advances;
- preserved the lock on `sploits/sentinel_aml/aml_network_room.py` until Wave
  23 opens in sequence.

Evidence:

- W18-F01 handoff and validation summary record `timeout 300 make wave18-gate`
  exiting 0 after deterministic package-by-package AML-5 tagged execution.
- W18-F02 handoff and validation summary record `timeout 300 make wave18-gate`
  exiting 0 with archive hygiene included, plus
  `python -B scripts/check_archive_hygiene.py` exiting 0 on the actual tree.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave18_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/validate_forcad_config.py`

Scope preserved:

- no code, tests, checker logic, config, sploit, fix, broad network-room
  access, debug/admin toggle, public credential exposure, or previous-wave
  behavior was changed.

## 2026-09-02 — W19-T01 AML-1 Reference Exploit Script

Status: implemented under review.

Actions:

- added `sploits/sentinel_aml/aml_dedup_preview.py` as the Wave 19 AML-1
  reference exploit;
- kept the exploit standalone and limited to stdlib HTTP, public place 1 attack
  data, attacker registration/login, attacker-owned customer/account/
  transaction/alert/case setup, duplicate candidate discovery, and
  merge-preview parsing;
- added `scripts/check_wave19_gate.py`, `tests/test_wave19_gate.py`, and
  `make wave19-gate`;
- validated the competition matrix so only AML-1 exploit-success is concrete
  while AML-1 fix cells and AML-2 through AML-5 exploit/fix cells remain
  pending;
- updated AML-1 docs, testing strategy, roadmap, waves, risk register, and
  sploit README wording.

Verification:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: 97 tests
  passed.
- `python -B -m unittest discover -s tests -p "test_wave19_gate.py"`: 12 tests
  passed.
- `python -B scripts/check_wave19_gate.py`: passed.
- `python -B scripts/check_competition_matrix_gate.py`: passed.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`:
  passed after rerun outside the sandbox because the Windows Go build cache was
  denied under sandboxed execution.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`: passed
  after rerun outside the sandbox for the same Go build-cache access issue.
- `timeout 300 make wave19-gate`: passed through WSL with temporary `/tmp`
  shims mapping `python` to `python3` and `go` to the Windows Go 1.24.2 binary,
  because native Windows `make` was unavailable and WSL's default Go was
  `go1.18 gccgo`.

Scope preserved:

- no checker code, product code, ForcAD config, public attack-data schema,
  AML-2 through AML-5 exploit, reference fix, direct DB path, debug/admin route,
  shell dependency, or checker-private-state dependency was introduced.

## 2026-09-02 - W19-T03 Wave 19 Documentation and Status Alignment

Status: historical documentation alignment; Wave 19 was under review at that
time and is now accepted by orchestrator review.

Actions:

- added `docs/wave_reports/wave_19_validation_summary.md` as the Wave 19
  status and evidence summary;
- added the W19-T03 handoff report;
- aligned the vulnerability matrix and source-of-truth map at that time so
  Wave 19 was implemented under review, not accepted;
- recorded at that time that Wave 20 remained queued/locked until Wave 19
  acceptance and all fix waves remained locked;
- recorded R-073 for Wave 19 status drift and early-unlock risk.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave19_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`

Scope preserved:

- no code, checker logic, exploit behavior, fix artifact, public attack-data
  schema, hidden debug route, or direct DB path was changed.

## 2026-09-02 - W20-T03 Wave 20 Documentation and Status Alignment

Status: documentation aligned; Wave 20 remains implemented under review.

Actions:

- added `docs/wave_reports/wave_20_validation_summary.md` as the Wave 20
  status and evidence summary;
- added the W20-T03 handoff report;
- aligned the vulnerability matrix, roadmap, waves, and source-of-truth map so
  Wave 19 is accepted and Wave 20 is implemented under review, not accepted;
- recorded that Wave 21 remains queued/locked until Wave 20 acceptance and all
  fix waves remain locked, including Wave 25 for AML-2;
- recorded R-074 for Wave 20 status drift, premature Wave 21/Wave 25 unlock,
  and AML-2 exploit overreach risk.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave20_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`

Scope preserved:

- no product code, checker logic, exploit behavior, fix artifact, migration,
  config, deployment, public attack-data schema, hidden debug route, or direct
  DB path was changed.

## 2026-09-02 - W20-F01 Gate Liveness and Archive Hygiene Fix

Status: fixed under review; orchestrator status remains `needs fixes` until
re-review accepts the fixed evidence.

Actions:

- removed generated Python bytecode/cache artifacts from the submitted
  repository snapshot;
- updated `wave20-gate` so exploit `py_compile` bytecode is written outside
  the repository and archive hygiene runs as the final closure check;
- strengthened Wave 20 validation to require W20-F01 handoff evidence and
  archive-hygiene wiring;
- recorded that the exact `timeout 300 make wave20-gate` wrapper exits 0
  without temporary command shims.

Verification:

- `python -B scripts/check_archive_hygiene.py`
- `python -B -m unittest discover -s tests -p "test_archive_hygiene.py"`
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`
- `python -B -m unittest discover -s tests -p "test_wave20_gate.py"`
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`
- `python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py`
- `python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`
- `timeout 300 make wave20-gate`

Scope preserved:

- no product code, checker behavior, exploit behavior, fix artifact, later
  exploit script, public attack-data schema, debug/admin endpoint, direct DB
  path, or shell behavior in exploits was changed.

## 2026-09-02 - W20-F02 Wave 20 Status-Ledger Reconciliation

Status: documentation reconciled; Wave 20 remains fixed under review and is
not accepted by this agent handoff.

Actions:

- reconciled roadmap, waves, source-of-truth map, risk register, execution log,
  and Wave 20 validation summary after W20-F01;
- recorded that the current orchestrator review status is `needs fixes` until
  re-review accepts the fixed gate/archive evidence;
- kept Wave 21 queued/conditional only and locked until Wave 20 acceptance;
- kept Wave 25 and all other reference fix waves locked until their scheduled
  sequence opens.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave20_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no code, checker logic, exploit behavior, gate behavior, Makefile behavior,
  fix artifact, later exploit script, migration, config, deployment, hidden
  debug/admin route, direct DB path, shell execution, or credential exposure was
  changed.

## 2026-09-02 - Wave 20 Acceptance Reconciliation

Status: Wave 20 complete; Wave 21 queued as the next allowed exploit wave.

Actions:

- reran the official Wave 20 aggregate gate after W20-F01/F02 fixes;
- updated roadmap, waves, vulnerability matrix, testing strategy,
  source-of-truth map, risk register, and Wave 20 validation summary so they
  agree that Wave 20 is accepted;
- queued only Wave 21 for the AML-3 related-graph reference exploit;
- kept Wave 22, Wave 23, and W24-W28 reference fix waves locked.

Verification:

- `timeout 300 make wave20-gate`: exit 0 in 19.0 seconds via WSL
  `/usr/bin/make` without temporary command shims.
- `python -B scripts/check_docs_tree.py`: exit 0.
- `python -B scripts/check_wave20_gate.py`: exit 0.
- `python -B scripts/check_competition_matrix_gate.py`: exit 0.
- `python -B scripts/check_archive_hygiene.py`: exit 0.

Scope preserved:

- no code, checker logic, exploit behavior, gate behavior, Makefile behavior,
  fix artifact, later exploit script, migration, config, deployment, hidden
  debug/admin route, direct DB path, shell execution, credential exposure, or
  cross-vulnerability chain was changed.

## 2026-09-02 - W21-T01 AML-3 Related Graph Reference Exploit

Status: implemented under review.

Actions:

- added `sploits/sentinel_aml/aml_related_graph.py` as the Wave 21 AML-3
  reference exploit;
- kept the exploit standalone and limited to stdlib HTTP, public place 2
  `EDDRecord` attack data, attacker registration/login, attacker-owned graph
  participation through `entity_hint`, graph EDD-summary retrieval, and
  `summaries[].confidential_comment` parsing;
- added focused Wave 21 fake-service tests for vulnerable graph leakage,
  secure metadata-only failure, CLI/import safety, public attack-data
  validation, and forbidden surface markers;
- updated `sploits/sentinel_aml/README.md` with AML-3 scope and kept AML-4/AML-5
  script names locked;
- added W21-T01 handoff evidence.

Verification:

- `python -B -m py_compile sploits\sentinel_aml\aml_related_graph.py`
- `python -B -m unittest discover -s tests -p "test_wave21_gate.py"`
- `python -B scripts\check_docs_tree.py`
- `python -B scripts\check_archive_hygiene.py`

Scope preserved:

- no product code, checker code, Go build tag, public attack-data schema,
  reference fix, AML-4/AML-5 exploit, owner EDD path use, direct DB path, SQL,
  shell/subprocess behavior, debug/admin route, credential/session theft, or
  checker-private dependency was introduced.

## 2026-09-02 - W21-T02 Wave 21 Gate and Competition Matrix Update

Status: validation implemented under review.

Actions:

- added `scripts/check_wave21_gate.py` to require exactly AML-1, AML-2, and
  AML-3 reference exploits and README-only fixes;
- updated the competition matrix gate so AML-3 exploit-success is concrete
  under Wave 21 review while AML-4/AML-5 exploit-success and all fix cells
  remain pending;
- added `wave21-gate` to the Makefile with checker tests, Wave 21 tests,
  competition matrix tests, py_compile for all three exploits using a no-repo
  cache prefix, Go test/vet, Wave 21 gate, matrix gate, docs tree, ForcAD
  validation, and archive hygiene;
- expanded Wave 21 and matrix tests for missing AML-3 exploit, premature
  AML-4/AML-5 exploits, premature fixes, forbidden primitives, public
  attack-data secret lookups, import-time execution, and Makefile closure;
- added W21-T02 handoff evidence.

Verification:

- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: 97 tests.
- `python -B -m unittest discover -s tests -p "test_wave21_gate.py"`: 14 tests.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`: 23 tests.
- `python -B scripts/check_wave21_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_docs_tree.py`
- `python -B scripts/validate_forcad_config.py`
- `python -B scripts/check_archive_hygiene.py`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...`
- `timeout 300 make wave21-gate` was not proven in the Windows PowerShell
  session because `timeout` resolved to Windows `timeout.exe`, `make` was not
  installed in PATH, and WSL/bash startup failed with `E_ACCESSDENIED`.

Scope preserved:

- no product code, checker code, migration, deployment config, reference fix,
  AML-4/AML-5 exploit, debug/admin toggle, direct DB path, credential exposure,
  or planned vulnerability behavior change was introduced.

## 2026-09-02 - W21-T03 Wave 21 Documentation and Status Alignment

Status: documentation aligned; Wave 21 remains implemented under review.

Actions:

- added `docs/wave_reports/wave_21_validation_summary.md`;
- aligned vulnerability matrix, testing strategy, roadmap, waves, source-of-
  truth map, risk register, and execution log so Wave 21 is implemented under
  review, not accepted;
- recorded AML-3 exploit-success as concrete under review through
  `sploits/sentinel_aml/aml_related_graph.py` and the bounded graph EDD-summary
  side view;
- kept Wave 22 and Wave 23 exploit waves locked until the staged sequence
  advances through orchestrator acceptance;
- kept W24-W28 reference fix waves locked;
- added R-077 for Wave 21 acceptance/unlock drift and AML-3 exploit overreach.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave21_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no code, checker logic, exploit behavior, gate behavior, Makefile behavior,
  fix artifact, later exploit script, migration, config, deployment,
  debug/admin shortcut, direct DB path, shell execution, credential exposure,
  owner EDD API abuse, or cross-vulnerability chain was changed.

## 2026-09-02 - W22-T01 AML-4 Export Redaction Reference Exploit

Status: implemented under review.

Actions:

- added `sploits/sentinel_aml/aml_export_redaction.py` as the Wave 22 AML-4
  reference exploit;
- kept the exploit standalone and limited to stdlib HTTP, public place 1
  `CaseNote.body` attack data, attacker registration/login, attacker-owned
  duplicate-linked case/dispute state, normal dispute export creation, stored
  export readback, and `bundle.linked_private_notes[].body` parsing;
- added focused Wave 22 fake-service tests for vulnerable export leakage,
  secure/redacted export failure, CLI/import safety, public attack-data
  validation, and forbidden surface markers;
- updated `sploits/sentinel_aml/README.md` with AML-4 scope and kept
  `aml_network_room.py` locked;
- added W22-T01 handoff evidence.

Verification:

- `python -B -m py_compile sploits\sentinel_aml\aml_export_redaction.py`: exit
  0.
- `python -B -m unittest discover -s tests -p "test_wave22_gate.py"`: exit 0;
  8 tests passed at W22-T01 time.
- `python -B scripts\check_docs_tree.py`: exit 0.
- `python -B scripts\check_archive_hygiene.py`: exit 1 on pre-existing
  `.idea/` after generated Python bytecode was removed.

Scope preserved:

- no product code, checker code, Go build tag, public attack-data schema,
  reference fix, AML-5 exploit, owner private-note API abuse, owner EDD API
  abuse, direct DB path, SQL, shell/subprocess behavior, debug/admin route,
  credential/session theft, or checker-private dependency was introduced.

## 2026-09-02 - W22-T02 Wave 22 Gate and Competition Matrix Update

Status: validation implemented under review.

Actions:

- added `scripts/check_wave22_gate.py` to require exactly the AML-1, AML-2,
  AML-3, and AML-4 reference exploits and README-only fixes;
- updated the competition matrix gate so AML-4 exploit-success is concrete
  under Wave 22 review while AML-5 exploit-success and all fix cells remain
  pending;
- added `wave22-gate` to the Makefile with checker tests, Wave 22 tests,
  competition matrix tests, py_compile checks for all four exploits, Go
  test/vet, docs tree, ForcAD validation, and archive hygiene;
- expanded Wave 22 and matrix tests for missing AML-4 exploit, premature AML-5
  exploit, premature fixes, forbidden primitives, wrong side-view paths,
  public attack-data secret lookups, import-time execution, and Makefile
  closure;
- added W22-T02 handoff evidence.

Verification:

- `python -B -m unittest discover -s tests -p "test_wave22_gate.py"`: exit 0;
  16 tests passed at W22-T02 time.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 25 tests passed.
- `python -B scripts\check_wave22_gate.py`: exit 0; status `pass`.
- `python -B scripts\check_competition_matrix_gate.py`: exit 0; status `pass`.
- `python -B scripts\check_archive_hygiene.py`: exit 1 on pre-existing
  `.idea/`.

Scope preserved:

- no product code, checker code, migration, deployment config, reference fix,
  AML-5 exploit, debug/admin toggle, direct DB path, credential/session
  exposure, broad export serialization, graph/audit/network path reuse, or
  planned vulnerability behavior change was introduced.

## 2026-09-02 - W22-T03 Wave 22 Documentation and Status Alignment

Status: documentation aligned; Wave 22 remained implemented under review at
that time.

Actions:

- added `docs/wave_reports/wave_22_validation_summary.md`;
- added the W22-T03 handoff report;
- aligned the vulnerability matrix, testing strategy, roadmap, waves,
  source-of-truth map, risk register, and execution log so Wave 22 is
  implemented under review, not accepted;
- recorded AML-4 exploit-success as concrete under review through
  `sploits/sentinel_aml/aml_export_redaction.py` and the bounded dispute export
  linked-case private-note side view;
- kept Wave 23, AML-5 exploit-success, and W24-W28 reference fix waves locked
  until orchestrator acceptance advances the sequence.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave22_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no code, checker logic, exploit behavior, gate behavior, Makefile behavior,
  fix artifact, later exploit script, migration, config, deployment,
  debug/admin shortcut, direct DB path, SQLi, shell/subprocess execution,
  credential/session exposure, owner private-note API abuse, owner EDD API
  abuse, graph/audit/network path reuse, broad export serialization, or
  checker-private/public attack-data boundary was changed.

## 2026-09-03 - W23-T03 Wave 23 Documentation and Status Alignment

Status: documentation aligned; Wave 23 remains implemented under review.

Actions:

- added `docs/wave_reports/wave_23_validation_summary.md`;
- added the W23-T03 handoff report;
- aligned the vulnerability matrix, testing strategy, roadmap, waves,
  source-of-truth map, risk register, and execution log so Wave 22 is accepted
  and Wave 23 is implemented under review, not accepted;
- recorded AML-5 exploit-success as concrete under review through
  `sploits/sentinel_aml/aml_network_room.py` and the bounded network-room
  dossier side view;
- recorded that exactly five reference exploit scripts exist and that
  `fixes/sentinel_aml/` remains README-only;
- kept W24-W28 reference fix waves locked until Wave 23 acceptance advances the
  sequence.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave23_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no code, checker logic, exploit behavior, gate behavior, Makefile behavior,
  fix artifact, migration, config, deployment, debug/admin shortcut, direct DB
  path, SQLi, shell/subprocess execution, credential/session exposure, owner
  private-note API abuse, owner EDD API abuse, export/dispute path reuse,
  graph/audit path reuse, broad network-room serialization, or
  checker-private/public attack-data boundary was changed.

## 2026-09-03 - W24-T04 Wave 24 Documentation and Status Alignment

Status: documentation aligned; Wave 24 remains implemented under review.

Actions:

- added `docs/wave_reports/wave_24_validation_summary.md`;
- added the W24-T04 handoff report;
- aligned the vulnerability matrix, testing strategy, roadmap, waves,
  source-of-truth map, risk register, and execution log so Wave 23 is accepted
  and Wave 24 is implemented under review, not accepted;
- recorded the AML-1 reference fix artifact
  `fixes/sentinel_aml/aml_dedup_preview.patch` and its W24-T01/T02/T03
  patch-apply, exploit-blocked, fixed-checker, and anti-coarse-fix evidence;
- kept Wave 25 through Wave 28 locked until Wave 24 orchestrator acceptance
  advances the reference-fix sequence.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave24_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no product code, checker logic, exploit behavior, gate behavior, Makefile
  behavior, fix artifact, migration, config, deployment, debug/admin shortcut,
  direct DB path, SQLi, shell/subprocess execution, credential/session
  exposure, owner private-note API change, owner EDD API change, AML-2 through
  AML-5 fix artifact, or checker-private/public attack-data boundary was
  changed.

## 2026-09-03 - W24-F02 Wave 24 Status Reconciliation After Gate Fix

Status: documentation reconciled; Wave 24 remains blocked pending exact
aggregate-gate re-review.

Actions:

- updated the roadmap, waves ledger, source-of-truth map, risk register, and
  Wave 24 validation summary so Wave 24 is not overclaimed as accepted after
  W24-F01;
- recorded that W24-F01 implemented the gate-liveness fix, but exact
  `timeout 300 make wave24-gate` exit-0 evidence is still required before Wave
  24 acceptance;
- kept Wave 25 through Wave 28 locked, with only the AML-1 reference fix
  artifact present.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave24_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no product code, checker logic, exploit behavior, fix patch semantics,
  migration, deployment config, AML-2 through AML-5 fix artifact, debug/admin
  shortcut, direct DB checker path, feature-disable fix, broad sensitive-field
  exposure, public attack-data schema, or checker-private/public attack-data
  boundary was changed.

## 2026-09-03 - W25-T04 Wave 25 Documentation and Status Alignment

Status: documentation aligned; Wave 25 is implemented under review.

Actions:

- added `docs/wave_reports/wave_25_validation_summary.md`;
- added the W25-T04 handoff report;
- aligned the vulnerability matrix, testing strategy, roadmap, waves,
  source-of-truth map, risk register, and execution log so Wave 25 is
  implemented under review, not accepted;
- recorded that AML-1 and AML-2 reference fix artifacts are concrete:
  `fixes/sentinel_aml/aml_dedup_preview.patch` and
  `fixes/sentinel_aml/aml_audit_timeline.patch`;
- kept AML-3 through AML-5 reference fixes pending and Wave 26 locked until
  Wave 25 orchestrator acceptance.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave25_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no product code, checker logic, exploit behavior, gate behavior, Makefile
  behavior, patch semantics, migration, deployment config, debug/admin
  shortcut, direct DB path, endpoint-removal fix, sensitive-field exposure,
  public attack-data schema, or checker-private/public attack-data boundary was
  changed.

## 2026-09-03 - W26-T04 Wave 26 Documentation and Status Alignment

Status: documentation aligned; Wave 26 is implemented under review.

Actions:

- added `docs/wave_reports/wave_26_validation_summary.md`;
- added the W26-T04 handoff report;
- aligned the vulnerability matrix, testing strategy, roadmap, waves,
  source-of-truth map, risk register, and execution log so Wave 25 is accepted
  and Wave 26 is implemented under review, not accepted;
- recorded the AML-3 reference fix artifact
  `fixes/sentinel_aml/aml_related_graph.patch` and its W26-T01/T02/T03
  patch-apply, exploit-blocked, fixed-checker, and anti-coarse-fix evidence;
- kept Wave 27 and Wave 28 locked until Wave 26 orchestrator acceptance
  advances the reference-fix sequence.

Verification:

- `python -B scripts/check_docs_tree.py`: exit 0; status `pass`
- `python -B scripts/check_wave26_gate.py`: exit 0; status `pass`
- `python -B scripts/check_competition_matrix_gate.py`: exit 0; status
  `pass`

Scope preserved:

- no product code, checker logic, exploit behavior, gate behavior, Makefile
  behavior, patch semantics, migration, deployment config, debug/admin
  shortcut, direct DB path, endpoint-removal fix, sensitive-field exposure,
  public attack-data schema, graph side-view broadening, owner EDD API change,
  AML-4/AML-5 fix artifact, or checker-private/public attack-data boundary was
  changed.

## 2026-09-03 - W26-F01 Wave 26 Aggregate Gate Liveness Stabilization

Status: liveness fix implemented; Wave 26 remains implemented under review.

Actions:

- added `scripts/run_go_release_tests.py` as a deterministic package-by-package
  release/offline Go test runner;
- changed only the Wave 26 aggregate gate Go test step to call the helper,
  preserving checker tests, Wave 26 tests, competition tests, exploit compiles,
  patch checks, Go vet, Wave 26 gate, matrix, docs, ForcAD, and archive hygiene;
- updated `scripts/check_wave26_gate.py` and `tests/test_wave26_gate.py` so the
  gate requires the helper and rejects the old opaque aggregate Go test line;
- updated the Wave 26 validation summary, testing strategy, roadmap, waves,
  source-of-truth map, and risk register without marking Wave 26 accepted.

Verification:

- `python -B -m unittest discover -s tests -p "test_wave26_gate.py"`: exit 0;
  22 tests passed
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"`:
  exit 0; 30 tests passed
- `python -B -m unittest discover -s tests -p "test_checker_*.py"`: exit 0;
  97 tests passed
- no-repo-cache `python -B -m py_compile` for all five Sentinel AML exploits
  and `scripts/run_go_release_tests.py`: exit 0
- `python -B scripts/check_wave26_gate.py`: exit 0; status `pass`
- `python -B scripts/run_go_release_tests.py --go go --package-timeout 120`:
  exit 0
- `python -B scripts/check_competition_matrix_gate.py`: exit 0; status `pass`
- `python -B scripts/check_docs_tree.py`: exit 0; status `pass`
- `python -B scripts/validate_forcad_config.py`: exit 0
- `python -B scripts/check_archive_hygiene.py`: exit 0; status `pass`
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_dedup_preview.patch`:
  exit 0
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_audit_timeline.patch`:
  exit 0
- `git apply --check --whitespace=error fixes/sentinel_aml/aml_related_graph.patch`:
  exit 0
- release/offline no-repo-cache `go vet ./...`: exit 0
- raw local `go vet ./...`: exit 1 because default Windows Go telemetry/cache
  paths were access denied; release/offline no-repo-cache vet passed
- intermediate archive hygiene: exit 1 after raw local py-compile created
  generated `__pycache__` directories; generated caches were removed and final
  archive hygiene passed
- local `timeout 300 make wave26-gate`: exit 1 before project code because
  Windows `timeout.exe` does not execute a command
- local `make wave26-gate`: exit 1 because no make-compatible executable is
  installed on PATH

Scope preserved:

- no product code, checker behavior, exploit scripts, patch semantics,
  migrations, deployment config, public attack-data schema, ForcAD place/PFR
  layout, AML-4/AML-5 fix artifact, debug/admin shortcut, direct DB path, shell
  helper in product/checker/exploit paths, graph DTO broadening, or
  checker-private/public attack-data boundary was changed.

## 2026-09-03 - W27-T04 Wave 27 Documentation and Status Alignment

Status: documentation aligned; Wave 27 is implemented under review.

Actions:

- added `docs/wave_reports/wave_27_validation_summary.md`;
- added the W27-T04 handoff report;
- aligned the vulnerability matrix, testing strategy, roadmap, waves,
  source-of-truth map, risk register, and execution log so Wave 26 is accepted
  and Wave 27 is implemented under review, not accepted;
- recorded the AML-4 reference fix artifact
  `fixes/sentinel_aml/aml_export_redaction.patch` and its W27-T01/T02/T03
  patch-apply, exploit-blocked, fixed-checker, and anti-coarse-fix evidence;
- recorded the matrix state as AML-1 through AML-4 fix cells concrete and
  AML-5 fix cells pending;
- kept Wave 28 locked until Wave 27 orchestrator acceptance advances the
  reference-fix sequence.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave27_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no product code, checker logic, exploit behavior, gate behavior, Makefile
  behavior, patch semantics, migration, deployment config, debug/admin
  shortcut, direct DB path, endpoint-removal fix, sensitive-field exposure,
  public attack-data schema, export DTO broadening, owner note/EDD API change,
  AML-5 fix artifact, or checker-private/public attack-data boundary was
  changed.

## 2026-09-03 - W27-F02 Wave 27 Status Reconciliation After Gate Fix

Status: documentation reconciled; Wave 27 remains implemented under review.

Actions:

- reviewed W27-F01 evidence and found no exit-0 GNU-style
  `timeout 300 make wave27-gate` result in this workspace;
- updated the Wave 27 validation summary, roadmap, waves ledger, testing
  strategy, source-of-truth map, and risk register to preserve the first-review
  liveness-blocker history without fabricating acceptance;
- created `docs/wave_reports/wave_27_W27-F02_handoff.md`;
- kept Wave 28 and the AML-5 reference fix locked until orchestrator
  acceptance records exact aggregate-gate success.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave27_gate.py`
- `python -B scripts/check_competition_matrix_gate.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no Go or Python product/checker/exploit/fix code, patch semantics,
  migration, deployment config, public attack-data schema, AML-5 fix artifact,
  visibility behavior, debug/admin shortcut, direct DB path, endpoint-removal
  fix, sensitive-field exposure, or checker-private/public attack-data boundary
  was changed.

## 2026-09-03 - W28-F03 Wave 28 Documentation and Status Ledger Recovery

Status: documentation aligned; Wave 28 is implemented under review.

Actions:

- added `docs/wave_reports/wave_28_validation_summary.md`;
- added the W28-F03 handoff report;
- aligned the roadmap, waves ledger, source-of-truth map, vulnerability matrix,
  testing strategy, risk register, and execution log so Wave 27 is complete and
  Wave 28 is implemented under review, not accepted;
- recorded W28-F01 evidence for `fixes/sentinel_aml/aml_network_room.patch` and
  W28-F02 evidence for `scripts/check_wave28_gate.py`,
  `tests/test_wave28_gate.py`, `wave28-gate`, and the competition matrix final
  fix cells;
- recorded that AML-1 through AML-5 exploit-success and fix cells are concrete
  in validation while final competition readiness remains pending;
- kept Wave 29 locked until Wave 28 orchestrator acceptance.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_archive_hygiene.py`
- local `timeout 300 make wave28-gate` could not run because Windows
  `TIMEOUT.EXE` rejected GNU syntax and `make` is unavailable on PATH; W28-F02
  records passing component evidence and leaves exact wrapper evidence to the
  orchestrator review host.

Scope preserved:

- no product code, checker logic, exploit behavior, gate behavior, Makefile
  behavior, patch content, migration, deployment config, debug/admin shortcut,
  direct DB path, endpoint-removal fix, sensitive-field exposure, public
  attack-data schema, network-room DTO broadening, owner note/EDD API change,
  or checker-private/public attack-data boundary was changed.

## 2026-09-03 - W29-T03 Documentation And Status Matrix Reconciliation

Status: documentation aligned; Wave 29 is implemented under review.

Actions:

- added `docs/wave_reports/wave_29_validation_summary.md`;
- added the W29-T03 handoff report;
- aligned the roadmap, waves ledger, source-of-truth map, vulnerability matrix,
  testing strategy, risk register, and Definition of Done so Wave 28 is
  complete, Wave 29 is implemented under review, and Wave 30 remains locked;
- recorded that AML-1 through AML-5 vulnerable-checker, exploit-success,
  fixed-checker, exploit-blocked, and anti-coarse-fix cells are concrete in
  validation;
- kept final competition readiness pending until Wave 29 orchestrator
  acceptance and Wave 30 packaging/release validation.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no code, checker logic, sploit behavior, patch semantics, migration,
  deployment config, public attack-data schema, flag-id format, debug/admin
  shortcut, direct DB path, sensitive-field exposure, projection/redaction
  boundary, or final release-readiness claim was changed.

## 2026-09-03 - W29-F02 Wave 29 Status Ledger Reconciliation After Exact Gate Success

Status: documentation reconciled; Wave 29 is ready for orchestrator re-review,
not accepted.

Actions:

- reconciled the roadmap, waves ledger, source-of-truth map, testing strategy,
  risk register, execution log, and Wave 29 validation summary after W29-F01
  recorded exact GNU-style `timeout 300 make wave29-gate` exit-0 evidence;
- preserved the first orchestrator review history that Wave 29 was `needs
  fixes` because the aggregate gate timed out;
- recorded that the liveness blocker is addressed in agent validation and Wave
  29 is ready for orchestrator re-review only;
- kept Wave 30 locked until Wave 29 orchestrator acceptance and kept final
  competition readiness pending Wave 30 packaging/release validation.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_archive_hygiene.py`
- `python -B scripts/check_wave29_gate.py`

Scope preserved:

- no product code, checker logic, sploit behavior, fix patch semantics,
  migration, deployment config, source-of-truth requirements, public attack
  data schema, flag-store mapping, debug/admin shortcut, direct DB path,
  side-view private-data exposure, Wave 30 start, or final competition-readiness
  claim was changed.

## 2026-09-03 - W30-T03 Final ForcAD, Checker, Exploit, Fix Matrix Evidence

Status: final validation evidence recorded; Wave 30 remains under orchestrator
review.

Actions:

- added `docs/wave_reports/wave_30_final_validation_summary.md`;
- added the W30-T03 handoff report;
- updated testing strategy to describe final Wave 30 validation evidence and
  command coverage;
- recorded final evidence for the Wave 29 aggregate matrix/regression gate,
  competition matrix gate, ForcAD config, archive hygiene, and release archive
  builder;
- preserved that final competition readiness is not self-claimed by the agent.

Verification:

- `timeout 300 make wave29-gate` - exit 0, 3m39.277s.
- `make competition-matrix-gate` - exit 0, 0m0.914s with a temporary WSL
  `python` shim to `python3`.
- `python -B scripts/validate_forcad_config.py` - exit 0.
- `python -B scripts/check_archive_hygiene.py` - exit 0.
- `make release-archive` - exit 0.

Scope preserved:

- no code, tests, checker behavior, sploit behavior, fix patch semantics,
  migration, config, docs contracts, deployment semantics, public attack-data
  schema, debug/admin shortcut, direct DB path, side-view private-data exposure,
  or final competition-readiness claim was changed.

## 2026-09-03 - W30-T04 Final Documentation, DoD, And Risk Closure

Status: final documentation and risk ledgers are ready for orchestrator review.

Actions:

- expanded `docs/definition_of_done.md` with explicit final readiness criteria
  for clean deploy, migrations, core workflows, all-place checker PUT/GET,
  CHECK/HAVOC, vulnerable-profile reproducibility, reference exploit success,
  reference fix blocking, fixed-checker preservation, no debug/direct-DB
  shortcuts, and flag lifetime;
- reconciled `docs/13_roadmap.md`, `docs/waves.md`, and
  `docs/source_of_truth_map.md` so Wave 30 is ready for orchestrator release
  review without claiming final acceptance;
- updated `docs/15_risk_register.md` so evidence-backed fix-wave and packaging
  risks are mitigated while final orchestrator acceptance remains an explicit
  open boundary risk;
- added `docs/wave_reports/wave_30_W30-T04_handoff.md`.

Verification:

- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_archive_hygiene.py`

Scope preserved:

- no implementation code, tests, checker behavior, sploit behavior, fix patch
  semantics, config, migrations, release archive, public attack-data schema,
  debug/admin shortcut, direct DB path, unresolved leak normalization, or final
  competition-readiness claim was changed.

## 2026-09-03 - W30-F02 Final Release Gate Target and Status Reconciliation

Status: `wave30-gate` added; Wave 30 is ready for orchestrator review only.

Actions:

- added `make wave30-gate` as the single final release-readiness target;
- added `scripts/check_wave30_gate.py` and `tests/test_wave30_gate.py` to
  require a concrete target that delegates to stabilized Wave 29 evidence and
  runs Wave 30 validation, ForcAD, archive hygiene, and release archive
  generation;
- updated the testing strategy, release-readiness manifest, final validation
  summary, roadmap, waves ledger, source-of-truth map, and risk register to
  name `timeout 300 make wave30-gate` as the final acceptance command;
- preserved that Wave 30 acceptance is orchestrator-only and unlocks no future
  feature waves.

Verification:

- `python -B -m unittest discover -s tests -p "test_wave30_gate.py"` - exit 0,
  6 tests in 2.833s after final documentation updates.
- `python -B scripts/check_wave30_gate.py` - exit 0.
- `python -B scripts/check_docs_tree.py` - exit 0.
- `timeout 300 make wave30-gate` - exit 0 in 4m3.712s on the WSL
  GNU-timeout/make path; release archive
  `/tmp/sentinel-aml-release/sentinel_aml_release.tar.gz`, 668 files, SHA-256
  `7ee8026ce68da3ca1f59507b19ec077151d06d1229bfafc7b1688cafa43b2fa5`.
- `python -B scripts/check_archive_hygiene.py` - exit 0 after final
  documentation updates.

Scope preserved:

- no product behavior, checker behavior, exploit semantics, fix patch
  semantics, public attack-data schema, release-readiness boundary weakening,
  direct DB path, debug/admin shortcut, side-view widening, or docs-only pass
  was introduced.

## 2026-09-03 - W31-T01 Final Release Candidate Handoff

Status: blocked pending Wave 30 orchestrator acceptance.

Actions:

- created `docs/wave_reports/final_release_candidate.md` as a documentation-only
  release-candidate handoff;
- recorded the latest W30-F02 candidate package metadata:
  `/tmp/sentinel-aml-release/sentinel_aml_release.tar.gz`, 668 files, SHA-256
  `7ee8026ce68da3ca1f59507b19ec077151d06d1229bfafc7b1688cafa43b2fa5`;
- preserved that active ledgers still show Wave 30 as ready for orchestrator
  review only, so no final release candidate or competition-readiness acceptance
  was issued.

Verification:

- no validation commands were rerun for W31-T01, per the handoff-only testing
  instruction to reference accepted Wave 30 evidence rather than replace it.

Scope preserved:

- no product code, checker code, sploit, fix patch, Makefile,
  source-of-truth requirement, CTF behavior, security behavior, or Wave 30
  evidence was changed.

## 2026-09-03 - W31-F01 Final Aggregate Gate Liveness Stabilization

Status: implemented under review; final release candidate remains blocked
pending orchestrator acceptance.

Actions:

- changed `scripts/run_vulnerable_profile_tests.py` to use the shared
  process-tree-aware `run_command` helper from `scripts/run_go_release_tests.py`;
- kept all five AML-1 through AML-5 focused vulnerable-profile scenarios,
  shared out-of-repository Go cache/appdata paths, sploit/fix/matrix/checker
  evidence, ForcAD validation, archive hygiene, and release archive generation
  in the final gate path;
- added focused tests for capped vulnerable-profile child timeouts and Wave 30
  static validation that rejects plain `subprocess.run` fallback behavior;
- kept `docs/wave_reports/final_release_candidate.md` blocked because Wave 30
  orchestrator acceptance is not recorded in active ledgers.

Verification:

- `python -B -m unittest discover -s tests -p "test_run_vulnerable_profile_tests.py"` -
  exit 0, 3 tests in 0.010s.
- `python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"` -
  exit 0, 3 tests in 0.516s.
- `python -B -m unittest discover -s tests -p "test_wave30_gate.py"` -
  exit 0, 7 tests in 3.417s.
- `python -B scripts/check_competition_matrix_gate.py` - exit 0.
- `python -B scripts/check_archive_hygiene.py` - exit 0.
- `python -B scripts/validate_forcad_config.py` - exit 0.
- `/usr/bin/timeout 300 make wave30-gate` - exit 0 in 3m49.270s on the WSL
  GNU-timeout/make path; release archive
  `/tmp/sentinel-aml-release/sentinel_aml_release.tar.gz`, 671 files, SHA-256
  `bb6b37097cf4739a9c5a8edbdfb650a95ce5763372bb5f3aaa5a3e4e29fa26a7`.

Scope preserved:

- no product code, checker behavior, CHECK/HAVOC evidence, reference sploit,
  reference fix patch, public attack data, direct DB shortcut, debug/admin
  route, shell helper, leaked credential path, or final readiness acceptance
  was changed.

## 2026-09-04 - W31-F02 Release Candidate Handoff and Durable Artifact Metadata

Status: release candidate package metadata ready for orchestrator review; final
competition readiness remains pending orchestrator acceptance.

Actions:

- updated `docs/wave_reports/final_release_candidate.md` from a conservative
  boundary note into the final release-candidate manifest;
- refreshed `docs/wave_reports/wave_31_release_candidate_handoff.md`;
- built a durable release archive outside `/tmp` and outside the repository at
  `C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz`;
- recorded the 671-file inventory and SHA-256
  `d850a2e0e4111a72f3c2e2ece4ee72814517305ff0931db7616bf45f4a87e7ed`;
- updated Definition of Done, roadmap, source-of-truth map, and risk register
  so durable release-candidate metadata is review evidence only while final
  competition readiness remains not self-accepted.

Verification:

- cited W31-F01 same-snapshot `/usr/bin/timeout 300 make wave30-gate` evidence:
  exit 0 in 3m49.270s;
- `python -B scripts/build_release_archive.py --output-dir C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release` -
  exit 0, elapsed 1.747s;
- `python -B scripts/check_archive_hygiene.py C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz` -
  exit 0, elapsed 0.175s;
- `python -B scripts/check_archive_hygiene.py` - exit 0, elapsed 0.178s;
- `Get-FileHash -Algorithm SHA256 C:\Users\2005g\.codex\visualizations\2026\09\03\01a0694d-7ad4-78b3-898f-a25d97094366\sentinel-aml-release\sentinel_aml_release.tar.gz` -
  exit 0, elapsed 0.064s, hash matched builder output.

Scope preserved:

- no product behavior, checker logic, sploit behavior, fix patch semantics,
  vulnerable profile, Makefile target, source-of-truth requirement, debug/admin
  shortcut, direct DB path, shell helper, public flag data, or final
  competition-readiness acceptance was changed.

## 2026-09-04 - W31-F01 Final Gate Liveness Revalidation And Boundary Correction

Status: liveness fix verified in agent validation; final release candidate
remains blocked pending orchestrator acceptance.

Actions:

- verified that `scripts/run_vulnerable_profile_tests.py` uses the shared
  process-tree-aware runner and the capped vulnerable-profile child timeout;
- confirmed `wave30-gate` still delegates to `wave29-gate`, reruns the
  competition matrix, validates Wave 30 wiring, validates ForcAD, checks
  archive hygiene, and builds the release archive;
- corrected `docs/wave_reports/final_release_candidate.md` so agent validation
  does not issue the final release candidate before orchestrator acceptance.

Verification:

- `/usr/bin/timeout 300 make wave30-gate` - exit 0 in 3m49.270s on the
  WSL GNU-timeout/make path; release archive
  `/tmp/sentinel-aml-release/sentinel_aml_release.tar.gz`, 671 files, SHA-256
  `bb6b37097cf4739a9c5a8edbdfb650a95ce5763372bb5f3aaa5a3e4e29fa26a7`.
- `python -B scripts/check_competition_matrix_gate.py` - exit 0, elapsed
  0.235s.
- `python -B scripts/check_archive_hygiene.py` - exit 0, elapsed 0.204s.
- `python -B scripts/validate_forcad_config.py` - exit 0, elapsed 0.116s.
- `python -B -m unittest discover -s tests -p "test_run_vulnerable_profile_tests.py"` -
  exit 0, 3 tests in 0.011s.
- `python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"` -
  exit 0, 3 tests in 0.517s.
- `python -B -m unittest discover -s tests -p "test_wave30_gate.py"` - exit 0,
  7 tests in 3.743s.

Scope preserved:

- no product behavior, checker behavior, CHECK/HAVOC evidence, reference
  sploit, reference fix patch, public attack data, direct DB shortcut,
  debug/admin route, shell helper, leaked credential path, public flag data, or
  final readiness acceptance was changed.

## 2026-09-08 - W32-T05 Stability Evidence and Ledger Reconciliation

Status: runtime/A-D stability candidate ready for orchestrator review; final
release packaging, player/admin productization, code sanitization, player-facing
leak cleanup, final manifests, checksums, and package promotion remain deferred
to Wave 33+.

Actions:

- reconciled `docs/13_roadmap.md`, `docs/waves.md`,
  `docs/source_of_truth_map.md`, `docs/definition_of_done.md`,
  `docs/15_risk_register.md`, and this execution log so Wave 32 is the active
  archive-free stability checkpoint before packaging;
- recorded Wave 32 evidence paths:
  `docs/wave_reports/wave_32_checker_validation.md`,
  `docs/wave_reports/wave_32_sploit_fix_matrix.md`,
  `docs/wave_reports/wave_32_runtime_smoke.md`, and
  `docs/wave_reports/wave_32_stability_summary.md`;
- preserved W30/W31 release archive and durable handoff records as historical
  package-context evidence only;
- preserved that Wave 32 issues no final candidate, accepts no final package,
  and marks no final competition readiness state done.

Verification:

- `timeout 300 make ad-stability-gate` - exit 0; `ad-stability-gate: pass
  elapsed=72.350s`; outer elapsed about 84.048s in the target environment.
- `python -B -m unittest discover -s tests -p "test_checker_*.py"` - exit 0,
  107 tests in 5.036s.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` -
  exit 0, 40 tests in 2.828s.
- `python -B -m unittest discover -s tests -p "test_runtime_smoke.py"` - exit 0,
  6 tests.
- `go test ./cmd/aml-api ./cmd/aml-worker ./internal/httpapi` - exit 0.
- `go test ./cmd/aml-worker` - exit 0.
- `go test ./internal/risk ./internal/alert ./internal/networkroom` - exit 0.
- `go test ./...` - exit 0.
- `python -B scripts/runtime_smoke.py` with
  `DATABASE_URL=postgres://sentinel:sentinel@localhost:55432/sentinel_aml_test?sslmode=disable`
  and `SENTINEL_AML_POSTGRES_PORT=55432` - exit 0;
  `runtime-smoke: pass elapsed=16.906s`.
- `python -B scripts/check_docs_tree.py` - exit 0 after W32-T05 ledger
  reconciliation.
- final-acceptance wording scan after W32-T05 found no active ledger statement
  claiming final candidate issuance, package acceptance, or final competition
  readiness completion.

Scope preserved:

- no product behavior, checker behavior, CHECK/HAVOC evidence, reference
  sploit behavior, reference fix patch semantics, vulnerable-profile symbol,
  public attack-data schema, debug/admin route, direct DB path, or public flag
  field was changed in W32-T05.

## 2026-09-08 - W33-T06 Stability Preservation and Regression Evidence

Status: Wave 33 packaging/productization regression candidate ready for
orchestrator review; final release packaging remains deferred.

Actions:

- added `wave33-gate` as an archive-free Wave 33 aggregate target backed by
  `scripts/check_wave33_gate.py`;
- added `tests/test_wave33_gate.py` to assert the gate is present, excludes
  final archive/manifest/checksum generation, includes player hygiene,
  candidate tree checks, checker tests, competition matrix, all five sploit
  syntax checks, all five fix patch checks, vulnerable-profile tests,
  release-profile Go tests, docs-tree validation, and ForcAD validation;
- recorded Wave 33 validation evidence in
  `docs/wave_reports/wave_33_validation_summary.md`;
- retargeted stale organizer-only Wave 24 through Wave 29 fix evidence
  validators and reference fix patch paths from pre-productization filenames to
  the Wave 33 neutral source names, preserving the same fix semantics;
- kept Wave 33 as candidate-tree/hygiene validation only; no final release
  archive, player release archive, final manifest, or checksum was generated.

Verification:

- `python -B scripts/check_wave33_gate.py --run` - exit 0;
  final rerun `wave33-gate: pass elapsed=127.453s`; earlier run before ledger
  updates also passed in 130.578s.
- `python -B scripts/check_ad_stability_gate.py --run` - exit 0;
  `ad-stability-gate: pass elapsed=130.531s`.
- `python -B scripts/check_wave29_gate.py` - exit 0 after legacy validator
  retargeting.
- `python -B -m unittest discover -s tests -p "test_wave33_gate.py"` - exit 0,
  8 tests.
- `python -B -m unittest discover -s tests -p "test_player_bundle*.py"` -
  exit 0, 21 tests.
- `python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"` -
  exit 0, 40 tests.
- `python -B scripts/check_competition_matrix_gate.py` - exit 0.
- `make wave33-gate` - local Windows host exit 1 before target execution:
  `make` is not installed.
- `timeout 300 make ad-stability-gate` - local Windows PowerShell exit 1 before
  target execution because Windows `timeout` syntax is not GNU `timeout`; direct
  Python gate evidence above is the local equivalent.

Scope preserved:

- no product behavior, checker behavior, CHECK/HAVOC evidence, reference sploit
  behavior, vulnerable/fixed profile semantics, public attack-data schema,
  debug/admin route, direct DB path, public flag field, final archive target, or
  final readiness status was changed in W33-T06.

## 2026-09-08 - W33-F01 Wave 33 Aggregate Gate Liveness Stabilization

Status: liveness fix verified; Wave 33 is ready for orchestrator re-review.

Actions:

- made `make wave33-gate` and `make ad-stability-gate` delegate directly to
  their process-tree-bounded Python aggregate runners;
- kept static gate tests as named phases inside those aggregate runners instead
  of duplicating them in Make before the bounded runner starts;
- added a 285-second aggregate deadline with per-phase remaining-time output;
- reused one out-of-repository Go cache/appdata pair across vulnerable-profile
  tests, release-profile Go tests, `go vet`, and `go build`;
- reduced nested Go package timeouts to 60 seconds for aggregate liveness while
  keeping standalone helper defaults available;
- added a temporary gate-local `python` shim for POSIX review hosts that expose
  `python3` but not `python`.

Verification:

- `/usr/bin/timeout 300 make wave33-gate` - exit 0 on the WSL GNU-timeout/make
  path; `wave33-gate: pass elapsed=129.902s`.
- `python -B scripts/check_wave33_gate.py --run --go go --python python` -
  exit 0; `wave33-gate: pass elapsed=119.500s`.
- `python -B scripts/check_ad_stability_gate.py --run --go go --python python` -
  exit 0; `ad-stability-gate: pass elapsed=109.812s`.
- `python -B -m unittest discover -s tests -p "test_wave33_gate.py"` -
  exit 0, 8 tests in 3.669s.
- `python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"` -
  exit 0, 4 tests in 0.517s.
- `python -B -m unittest discover -s tests -p "test_run_vulnerable_profile_tests.py"` -
  exit 0, 4 tests in 0.009s.
- `python -B -m unittest discover -s tests -p "test_ad_stability_gate.py"` -
  exit 0, 10 tests in 3.981s.

Scope preserved:

- no product behavior, checker behavior, CHECK/HAVOC coverage, two checker flag
  stores, owner-view checker GET path, reference sploit behavior, reference fix
  patch semantics, vulnerable-profile coverage, public attack-data schema,
  player-candidate hygiene policy, debug/admin route, direct DB shortcut, public
  flag field, final archive build, final manifest, or checksum generation was
  added, removed, or weakened.

## 2026-09-08 - W33-F02 Repository-Submission Hygiene Cleanup

Status: hygiene check implemented and verified.

Actions:

- added `scripts/check_repository_submission_hygiene.py` for submitted
  repository archives or extracted submission trees;
- added focused tests proving submitted archives fail on `__pycache__/`, `.pyc`,
  `.gocache*`, `.appdata*`, and generated `tmp/*candidate*` entries;
- added an explicit `--allow-wave33-local-candidates` mode that permits known
  ignored Wave 33 candidate directories and hygiene allowlist sidecars only for
  live local staging, not for archives;
- clarified `.gitignore` comments for local Wave 33 candidate output;
- removed generated local `tmp/` candidate trees and Python bytecode caches from
  the workspace after validation runs.

Verification:

- `python -B -m unittest discover -s tests -p "test_repository_submission_hygiene.py"` -
  exit 0, 6 tests in 0.022s.
- `python -B -m unittest discover -s tests -p "test_archive_hygiene.py"` -
  exit 0, 14 tests in 0.139s after cleanup.
- `python -B scripts/check_repository_submission_hygiene.py` - exit 0 on the
  cleaned workspace; scanned 853 members.
- `python -B scripts/check_repository_submission_hygiene.py --allow-wave33-local-candidates` -
  exit 0 with generated Wave 33 candidates present; scanned 945 members.

Scope preserved:

- no product behavior, checker behavior, reference sploit behavior, reference
  fix semantics, vulnerable-profile behavior, candidate builder selection,
  ForcAD config, debug/admin route, direct DB path, or organizer evidence was
  removed or weakened.

## 2026-09-08 - W33-F03 Player Source Runtime-Readiness Guard

Status: promotion guard implemented; current player candidate remains staged,
not final.

Actions:

- added `PACKAGING_STATUS.json` to generated player-service candidates with
  `final_package: false` and `source_runtime_ready: false`;
- updated player candidate README text to state that runtime delivery proof is
  required before promotion;
- added `--require-runtime-ready` to `scripts/check_player_bundle_hygiene.py`;
- required final source delivery to prove `vendor/`, `Dockerfile`,
  `deploy/compose.yaml`, `go.mod`, `go.sum`, and a successful runtime proof
  command;
- required final binary/image delivery to prove a successful runtime command and
  no Go source surface in the player artifact.

Verification:

- `/usr/bin/timeout 300 make wave33-gate` - exit 0 on the WSL GNU-timeout/make
  path; `wave33-gate: pass elapsed=99.817s`.
- `python -B -m unittest discover -s tests -p "test_player_bundle_build.py"` -
  exit 0, 11 tests in 0.956s.
- `python -B -m unittest discover -s tests -p "test_player_bundle_hygiene.py"` -
  exit 0, 15 tests in 0.202s.
- `python -B scripts/check_player_bundle_hygiene.py tmp\wave33-player-service-candidate --allowlist tmp\wave33-player-service-candidate.hygiene-allowlist.json` -
  exit 0; staged candidate hygiene passed across 82 members.
- `python -B scripts/check_player_bundle_hygiene.py tmp\wave33-player-service-candidate --allowlist tmp\wave33-player-service-candidate.hygiene-allowlist.json --require-runtime-ready` -
  expected exit 1; current staged candidate is not final and lacks runtime
  proof.

Scope preserved:

- no final player/admin archives, final manifests, checksums, service behavior,
  checker behavior, sploit/fix behavior, vulnerable-profile semantics, ForcAD
  config, debug/admin helper, direct DB shortcut, or organizer evidence changed.

## 2026-09-10 - W33-F04 Wave 33 Aggregate Gate Stabilization

Status: liveness fix verified; Wave 33 remains archive-free and ready for
orchestrator review.

Actions:

- hardened the shared process-tree runner in `scripts/run_go_release_tests.py`
  so cleanup runs even after the root child process exits;
- closed stdout/stderr streams after process-tree cleanup so descendants cannot
  keep pipes open after a parent has printed successful unittest output;
- waited on Windows root processes after closing the kill-on-close job handle so
  root `Popen` objects are reaped cleanly;
- added a regression where a parent exits while a child keeps stdout open,
  proving the bounded runner returns promptly;
- kept `wave33-gate` archive-free and preserved every A/D evidence phase.

Verification:

- `/usr/bin/timeout 300 make wave33-gate` - exit 0 on the WSL
  GNU-timeout/make path; host elapsed `157.304s`, runner elapsed `156.520s`.
- `python -B scripts/check_wave33_gate.py --run --go go --python python` -
  exit 0 on the Windows host; host elapsed `139.490s`, runner elapsed
  `139.281s`.
- `python -B -m unittest discover -s tests -p "test_wave33_gate.py"` -
  exit 0, 8 tests in 2.416s.
- `python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"` -
  exit 0, 5 tests in 0.825s.
- `python -B -m unittest discover -s tests -p "test_run_vulnerable_profile_tests.py"` -
  exit 0, 4 tests in 0.010s.
- `python -B scripts/check_competition_matrix_gate.py` - exit 0.
- `python -B scripts/check_docs_tree.py` - exit 0.
- `python -B scripts/validate_forcad_config.py` - exit 0.

Scope preserved:

- no product behavior, checker behavior, CHECK/HAVOC coverage, two checker flag
  stores, owner-view checker GET path, reference sploit behavior, reference fix
  patch semantics, vulnerable-profile coverage, public attack-data schema,
  player/admin candidate hygiene policy, debug/admin route, direct DB shortcut,
  public flag field, final archive build, final manifest, or checksum
  generation was added, removed, or weakened.

## 2026-09-10 - W33-F05 Repository-Submission Hygiene Gate Integration

Status: aggregate hygiene integration verified; Wave 33 remains archive-free
and ready for orchestrator review.

Actions:

- added strict `scripts/check_repository_submission_hygiene.py` as a bounded
  `wave33-gate` phase before player/admin candidate generation;
- added post-generation
  `scripts/check_repository_submission_hygiene.py --allow-wave33-local-candidates`
  so the gate proves only known ignored Wave 33 staging candidates are present
  during local validation;
- added a final cleanup phase that removes only
  `tmp/wave33-player-service-candidate`,
  `tmp/wave33-player-service-candidate.hygiene-allowlist.json`, and
  `tmp/wave33-admin-checker-candidate`;
- added static/unit coverage for strict-before-build ordering, local-staging
  ordering, and cleanup-only behavior;
- kept all checker, sploit, fix, vulnerable-profile, release-profile Go,
  docs-tree, and ForcAD phases in the aggregate gate.

Verification:

- `python -B -m unittest discover -s tests -p "test_repository_submission_hygiene.py"` -
  exit 0, 6 tests in 0.053s.
- `python -B -m unittest discover -s tests -p "test_wave33_gate.py"` - exit
  0, 9 tests in 2.655s.
- `python -B scripts/check_repository_submission_hygiene.py` - exit 0 on the
  cleaned repository workspace; scanned 864 members.
- `python -B scripts/check_repository_submission_hygiene.py --allow-wave33-local-candidates` -
  exit 0 after staging the Wave 33 player/admin candidates; scanned 1262
  members.
- `/usr/bin/timeout 300 make wave33-gate` through the WSL GNU-timeout/make
  path - exit 0; host elapsed `139.731s`, runner elapsed `139.245s` across 28
  bounded phases.

Scope preserved:

- no organizer checker, sploit, fix, vulnerable-profile, CHECK/HAVOC,
  owner-view checker GET, two flag-store evidence, ForcAD config, product
  behavior, debug/admin endpoint, direct DB shortcut, public flag field, final
  archive, final manifest, checksum, or player/admin final package was added,
  removed, or weakened.

## 2026-09-08 - W34-T01 Product-Facing Code Surface Hardening

Status: implemented under review; final player package remains blocked pending
runtime-delivery proof.

Actions:

- updated `scripts/build_player_bundle.py` so generated player source rewrites
  source-visible build-profile filenames and helper identifiers to
  product-neutral policy names;
- removed the previous generated hygiene allowlist exception for the Go CLI
  `flag` package by staging neutral argument parsing in the player candidate
  entrypoint only;
- added scanner coverage in `scripts/check_player_bundle_hygiene.py` for known
  internal build-profile path and identifier patterns in player source;
- added focused tests for generated policy names, empty allowlists, and
  synthetic internal build-profile source leaks;
- added `docs/wave_reports/wave_34_product_surface_hardening.md` and updated
  packaging/testing documentation.

Verification:

- `python -B scripts/build_player_bundle.py --output-dir tmp\w34-player-review-candidate --allowlist-out tmp\w34-player-review-candidate.hygiene-allowlist.json` -
  exit 0; generated 57 files.
- `python -B scripts/check_player_bundle_hygiene.py tmp\w34-player-review-candidate --allowlist tmp\w34-player-review-candidate.hygiene-allowlist.json` -
  exit 0; scanned 82 candidate members.
- W34 suspicious-token inventory over `tmp\w34-player-review-candidate` -
  exit 1 from `rg`, meaning no matches for the searched leak tokens.
- `python -B -m unittest discover -s tests -p "test_player_bundle_build.py"` -
  exit 0, 12 tests in 1.090s.
- `python -B -m unittest discover -s tests -p "test_player_bundle_hygiene.py"` -
  exit 0, 16 tests in 0.239s.
- `go test ./...` - exit 0 in the organizer repository.
- `go vet ./...` - exit 0 in the organizer repository.
- `go build ./cmd/aml-api ./cmd/aml-worker` - exit 0 in the organizer
  repository.
- `go test ./...` from `tmp\w34-player-review-candidate` - exit 0, confirming
  the staged source transform is internally consistent.
- `/usr/bin/timeout 300 make wave33-gate` through the WSL GNU-timeout/make path -
  exit 0; host wrapper elapsed 91.654s, runner elapsed 91.050s.
- `/usr/bin/timeout 300 make ad-stability-gate` through the WSL
  GNU-timeout/make path - exit 0; host wrapper elapsed 86.083s, runner elapsed
  85.654s.
- Final aggregate-generated candidate hygiene scan - exit 0; scanned 82
  members with an empty generated allowlist.
- `python -B scripts/check_repository_submission_hygiene.py` - exit 0 after
  generated-candidate cleanup; scanned 855 members.

Scope preserved:

- no organizer product behavior, checker behavior, sploit/fix behavior,
  vulnerable-profile semantics, public attack-data semantics, ForcAD config,
  debug/admin endpoint, direct DB shortcut, final player/admin archive,
  manifest, checksum, or organizer evidence was added, removed, or weakened.

## 2026-09-08 - W34-T02 Player Package Runtime Proof

Status: source-delivery candidate runtime proof passed; no release archive was
created.

Actions:

- expanded `scripts/build_player_bundle.py` to stage source-delivery runtime
  inputs: `vendor/`, `Dockerfile`, `deploy/compose.yaml`, participant docs, and
  a player-safe `cmd/aml-migrate` command;
- added `scripts/check_player_package_runtime.py` to rebuild the candidate, run
  hygiene, run offline Go test/build, validate candidate Compose, run live
  PostgreSQL/migration/worker/API smoke, stamp `PACKAGING_STATUS.json`, and
  rerun hygiene with `--require-runtime-ready`;
- updated `scripts/runtime_smoke.py` so the same smoke logic can target a
  package-specific Compose file and migration command;
- kept player hygiene strict for project-owned content while skipping vendored
  third-party content text; vendored paths are still scanned for obvious
  challenge-map leaks;
- updated participant run/troubleshooting docs for the source package commands.

Verification:

- `python -B -m unittest discover -s tests -p "test_player_bundle_build.py"` -
  exit 0, 12 tests in 4.860s.
- `python -B -m unittest discover -s tests -p "test_player_bundle_hygiene.py"` -
  exit 0, 18 tests in 0.244s.
- `python -B -m unittest discover -s tests -p "test_player_package_runtime.py"` -
  exit 0, 3 tests in 0.014s.
- `python -B -m unittest discover -s tests -p "test_runtime_smoke.py"` -
  exit 0, 7 tests in 0.005s.
- `python -B scripts/build_player_bundle.py --output-dir tmp\w34-player-source-candidate --allowlist-out tmp\w34-player-source-candidate.hygiene-allowlist.json` -
  exit 0; generated 311 files.
- `python -B scripts/check_player_bundle_hygiene.py tmp\w34-player-source-candidate --allowlist tmp\w34-player-source-candidate.hygiene-allowlist.json` -
  exit 0; scanned 385 candidate members.
- `python -B scripts/check_player_bundle_hygiene.py tmp\w34-player-source-candidate --allowlist tmp\w34-player-source-candidate.hygiene-allowlist.json --require-runtime-ready` -
  exit 0 after runtime proof stamping; runtime delivery proof present.
- `python -B scripts/check_player_package_runtime.py --output-dir tmp\w34-player-source-candidate --allowlist-out tmp\w34-player-source-candidate.hygiene-allowlist.json --go go --docker docker --database-url "postgres://sentinel:sentinel@localhost:55433/sentinel_aml?sslmode=disable" --base-url "http://127.0.0.1:18080"` -
  exit 0; host wrapper elapsed 38.360s, script elapsed 38.156s.
- `/usr/bin/timeout 300 make wave33-gate` through the WSL GNU-timeout/make
  path - exit 0; host wrapper elapsed 130.900s, runner elapsed 130.421s.
- `/usr/bin/timeout 300 make ad-stability-gate` through the WSL
  GNU-timeout/make path - exit 0; host wrapper elapsed 94.144s, runner elapsed
  93.697s.
- Focused `rg --pcre2` leak-token inventory over project-owned player candidate
  paths - exit 1, meaning no matches.
- `python -B -m unittest discover -s tests -p "test_docs_tree.py"` - exit 0,
  10 tests in 0.286s.
- `python -B scripts\check_repository_submission_hygiene.py` - exit 0 after
  generated-candidate cleanup; scanned 858 members.
- The first full-smoke attempt on default package port `54330` failed because
  the host refused that port; the accepted run used `55433`.

Scope preserved:

- no checker behavior, sploit/fix behavior, vulnerable-profile semantics,
  public attack-data semantics, ForcAD config, debug/admin endpoint, direct DB
  shortcut, final archive, manifest, checksum, or image push was added.

## 2026-09-08 - W34-T04 Final Split-Package Gate

Status: final split-package gate verified; ready for orchestrator review.

Actions:

- added `make final-split-package-gate` backed by
  `scripts/check_split_package_gate.py`;
- kept player-service, admin/checker, and organizer-internal evidence as
  separate artifact statuses;
- made the gate rebuild and scan the runtime-ready player source candidate,
  rebuild and inventory-check the admin/checker candidate, then clean generated
  candidates before archive hygiene;
- delegated the player runtime proof to the Windows host when WSL invokes
  Windows `go.exe`/`docker.exe`, keeping Docker, Go, and API health probes on
  the same loopback surface;
- preserved the archive-free boundary: no final archives, release archives,
  manifests, checksums, or image pushes are created.

Verification:

- `/usr/bin/timeout 300 make final-split-package-gate` - exit 0 on the WSL
  GNU-timeout/make path; host elapsed `147.199s`, runner elapsed `146.706s`.
- Nested `player-package-runtime-proof` - exit 0; rebuilt a 311-file player
  source candidate, scanned 385 candidate members, ran candidate
  `go test ./...`, ran candidate `go build ./cmd/aml-api ./cmd/aml-worker
  ./cmd/aml-migrate`, validated package Compose, applied 9 migrations,
  restarted the worker twice, completed API health/workflow smoke, and reran
  hygiene with `--require-runtime-ready`.
- Nested `admin-inventory-gate` - exit 0; exact 7-file admin/checker allowlist
  passed and copied ForcAD config validated.
- Nested `organizer-ad-stability-gate` - exit 0;
  `ad-stability-gate: pass elapsed=90.291s`, preserving checker tests,
  competition matrix, five sploit syntax checks, five fix patch checks,
  vulnerable-profile tests, release-profile Go tests, Go vet/build, docs tree,
  and ForcAD validation.
- Nested `archive-hygiene`, `repository-submission-hygiene`, final `docs-tree`,
  and root ForcAD config phases all exited 0.
- `python -B -m unittest discover -s tests -p "test_split_package_gate.py"` -
  exit 0, 9 tests in 1.647s.
- `python -B -m unittest discover -s tests -p "test_player_package_runtime.py"` -
  exit 0, 5 tests in 0.025s.
- `python -B -m unittest discover -s tests -p "test_runtime_smoke.py"` -
  exit 0, 9 tests in 0.006s.
- Standalone `/usr/bin/timeout 300 make ad-stability-gate` - exit 0 on the WSL
  GNU-timeout/make path; host elapsed `91.147s`, runner elapsed `90.659s`.

Scope preserved:

- no product behavior, checker behavior, reference sploit behavior, reference
  fix semantics, vulnerable-profile behavior, public attack-data semantics,
  flag store, debug/admin endpoint, direct DB shortcut, public flag field,
  final archive, final manifest, checksum, or image push was added, removed, or
  weakened.

## 2026-09-10 - W34-T06 Status Freeze and Concept Preservation

Status: documentation/status freeze implemented; ready for orchestrator review.

Actions:

- replaced the stale top-level README status with a current sanitized overview
  that points maintainers to the canonical Wave 34 status freeze without
  exposing player-facing challenge internals;
- added `docs/wave_reports/wave_34_status_freeze.md` as the canonical Wave 34
  status authority;
- updated roadmap, source-of-truth map, and Definition of Done so Wave 34 is
  runtime A/D alignment plus split candidate proof, not final distribution
  acceptance;
- marked candidate-local `PACKAGING_STATUS.json` and "final split-package gate"
  language as historical/candidate evidence that does not override the status
  freeze;
- preserved the original service concept: natural business data stores,
  owner-view checker GET, side-view business logic weaknesses, internal
  reference attacks/fixes, and strong CHECK/HAVOC evidence.

Verification:

- `python -B scripts/check_docs_tree.py` - exit 0.
- `python -B -m unittest discover -s tests -p "test_docs_tree.py"` - exit 0,
  10 tests in 0.269s.
- `python -B scripts/check_repository_submission_hygiene.py` - exit 0.

Scope preserved:

- documentation-only change; no product code, checker code, sploit logic, fix
  patches, vulnerable-profile semantics, package builders, ForcAD config,
  debug/admin routes, direct DB paths, or final artifacts were changed.
