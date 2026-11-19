# Wave 04 Validation Summary

## Scope Validated

Wave 04 covers deterministic risk scoring, alert generation, owner alert workflows, owner case workflows, and private owner-only case notes.

Validated implementation surfaces:

- `internal/risk` deterministic scoring and idempotent alert generation.
- `internal/alert` owner-scoped alert create/get/list/claim/triage repository behavior.
- `internal/casework` owner-scoped case and private-note repository behavior.
- `internal/httpapi` authenticated owner routes for alerts, cases, and private notes.
- `cmd/aml-api` wiring for domain, investigation, and risk services.
- `migrations/000003_create_alerts_cases_notes.sql`.
- `scripts/check_wave04_gate.py`.

## Gate Coverage

The Wave 04 gate checks:

- expected Wave 04 migrations and table set;
- required previous-wave routes plus Wave 04 investigation routes;
- auth wrapping for all product and investigation routes;
- absent checker, public attack-data, EDD, graph, export, network-room, debug, admin, and planned vulnerability routes;
- explicit response DTOs without owner/auth/session/checker-private internal fields;
- `CaseNote.body` is confined to the private-note create request and owner note response;
- non-owner note-body regression tests are present;
- no exploit scripts or planned vulnerability scripts exist;
- live PostgreSQL Wave 04 risk and investigation API gate hooks exist;
- Wave 04 handoffs and documentation are present;
- docs tree, ForcAD config, Wave 01 scope, and retained Wave 03 invariants remain clean for the expanded branch.

## Test Results

- `GOTOOLCHAIN=local go test ./...` - passed.
- `GOTOOLCHAIN=local go vet ./...` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/check_wave04_gate.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.
- `python -B -m unittest discover -s tests -p "test_*.py"` - passed, 40 tests.
- `python -B scripts/check_wave03_gate.py` - expected historical-gate failure on the current Wave 04 branch because the Wave 03 gate intentionally rejects alert/case/note migrations and routes.

Full command details are recorded in `docs/wave_reports/wave_04_W04-T04_handoff.md`.

## Live PostgreSQL Status

Live PostgreSQL Wave 04 integration was available locally through Docker Compose. The supported serial live gates passed:

- `TestWave04LivePostgresRiskAlertGeneration`
- `TestWave04LivePostgresInvestigationRepositories`
- `TestLivePostgresWave04InvestigationAPIIntegration`

An initial parallel run hit the documented shared-schema reset race. The live gates should be run serially against one database URL.

## CTF Invariants

- Future checker place 1 owner path is prepared through normal APIs.
- Checker PUT/GET remains unimplemented.
- No public attack data exists.
- No planned vulnerabilities, exploits, or reference fixes exist.
- `CaseNote.body` remains normal private business data, not an artificial flag field.

## Security / Visibility Invariants

- Private note body is returned only through owner-authorized case-note endpoints.
- Alert queue and case shell projections do not include note bodies.
- Cross-owner access fails closed as `404`.
- No debug/admin/checker-only route exists.
- Logs do not include note bodies or credential material.

## Current Review State

Wave 04 is ready for orchestrator review after W04-T04 gate verification.
