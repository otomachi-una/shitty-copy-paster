# Wave 05 Validation Summary

## Scope

Wave 05 adds secure EDD persistence, owner EDD HTTP APIs, live PostgreSQL integration coverage, visibility regression checks, and the current-branch Wave 05 validation gate.

Implemented Wave 05 surfaces:

- `edd_records` migration in `migrations/000004_create_edd_records.sql`.
- Owner-scoped EDD repository in `internal/edd`.
- Owner-authenticated EDD routes:
  - `POST /api/customers/{customer_id}/edd`
  - `GET /api/customers/{customer_id}/edd`
  - `PATCH /api/customers/{customer_id}/edd`
- Current branch gate: `scripts/check_wave05_gate.py`.

## Tests and Gates

Required local/offline gates:

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`
- `python -B scripts/check_docs_tree.py`
- `python -B scripts/check_wave05_gate.py`
- `python -B scripts/validate_forcad_config.py`
- `python -B -m unittest discover -s tests -p "test_*.py"`

W05-T04 local verification completed successfully for the Python/docs/ForcAD gates, 47 Python unittests, and offline Go test/vet in vendor mode with `GOCACHE` pointed at a writable temp directory. The first direct Go test attempt hit the known Windows default cache ACL issue before compilation; it did not attempt network access or report code/dependency failures.

Live PostgreSQL gate:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresWave05EDDAPIIntegration -count=1 -v
```

The live gate applies all migrations to a clean schema and exercises normal auth, customer, and EDD owner API flows through the real repository/service/HTTP stack.

W05-T04 live verification passed against the local Docker PostgreSQL service on `localhost:54329`.

## CTF Invariants

- No checker PUT/GET behavior exists.
- No public attack data exists.
- No planned vulnerabilities exist.
- No exploit or reference-fix scripts exist.
- ForcAD config remains unchanged.
- `CaseNote.body` and `EDDRecord.confidential_comment` remain private business fields only.

## Security and Visibility Invariants

- EDD confidential comments are visible only in owner EDD DTOs.
- Cross-owner EDD access fails closed with `404`.
- EDD confidential comments do not appear in non-EDD response bodies, logs, public views, checker routes, graph/export/network/audit side views, or worker surfaces.
- HTTP responses use explicit DTOs rather than direct DB model serialization.

## Status

Wave 04 is complete. Wave 05 is marked `needs fixes` until W05-T01, W05-T02, W05-T03, and W05-T04 pass orchestrator review.
