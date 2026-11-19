# Wave 06 Validation Summary

## Summary

Wave 06 adds validation-only hardening for projection boundaries, private-field leak regression, and cross-owner fail-closed authorization coverage. It does not add new product routes, checker behavior, public attack data, planned vulnerabilities, exploit scripts, reference fixes, or side-view implementations.

## Scope Validated

- Projection allowlists exist under `internal/projection` for current owner views and future safe placeholder projections.
- `CaseNote.body` is allowed only in owner case-note DTO/projection contexts.
- `EDDRecord.confidential_comment` is allowed only in owner EDD DTO/projection contexts.
- HTTP leak regression tests plant high-entropy private note and EDD sentinels and allow them only in owner `GET /api/cases/{case_id}/notes` and owner `GET /api/customers/{customer_id}/edd`.
- Cross-Owner Authorization Matrix tests cover customer, account, transaction, alert, case, case-note, and EDD owner boundaries.
- Out-of-scope dedup, audit, graph, export, network, checker, attack-data, debug, and admin routes remain absent.
- Sploit and reference-fix scripts remain absent.
- Docs tree and ForcAD configuration remain valid.

## Gate Coverage

`scripts/check_wave06_gate.py` verifies:

- retained Wave 05 migration/table set;
- retained owner route surface;
- no out-of-scope route or handler markers;
- projection allowlist package and tests;
- HTTP leak regression suite markers;
- cross-owner authorization matrix markers;
- DTO private-field placement for note bodies and EDD confidential comments;
- sensitive-log guardrails;
- no exploit or fix scripts;
- Wave 06 handoffs and validation summary;
- source-of-truth status alignment;
- docs-tree and ForcAD validators.

## Test Status

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: initial run failed because the Windows default Go build cache under `AppData\Local\go-build` returned access denied; rerun with `GOCACHE=%TEMP%\sentinel-aml-go-cache` passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: initial run failed for the same default-cache permission issue; rerun with `GOCACHE=%TEMP%\sentinel-aml-go-cache` passed.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/check_wave06_gate.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.
- `python -B -m unittest discover -s tests -p "test_*.py"`: passed, 54 tests.

## Live PostgreSQL

Wave 06 does not require a live PostgreSQL gate. Existing live auth, Wave 03, Wave 04, and Wave 05 gates remain opt-in and serial when `SENTINEL_AML_INTEGRATION_DATABASE_URL` is set.

## CTF Invariants

- No checker PUT/GET behavior.
- No public attack data.
- No planned vulnerabilities.
- No exploit or reference-fix scripts.
- ForcAD config unchanged.
- `CaseNote.body` and `EDDRecord.confidential_comment` remain private business fields only.

## Security Invariants

- Projection tests reject accidental sensitive-field exposure.
- Cross-owner tests fail closed and do not reveal private sentinel values.
- Explicit DTO/projection allowlists remain authoritative.
- Unsupported future route probes return stable errors without private data.

## Current Status

Wave 05 is complete. Wave 06 is `needs fixes` until W06-T01, W06-T02, W06-T03, and W06-T04 pass orchestrator review.
