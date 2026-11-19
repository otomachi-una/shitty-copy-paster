# Wave 08 Validation Summary

## Scope

Wave 08 adds the secure audit baseline:

- `000006_create_audit_events.sql` for normalized redacted audit events;
- `internal/audit` repository primitives for append/list and sensitive-field redaction;
- owner workflow instrumentation for case creation, case status changes, private note creation, and EDD create/update;
- authenticated secure owner timeline endpoint:
  - `GET /api/cases/{case_id}/timeline`;
- explicit `owner_case_audit` / `CaseAuditView` DTO fields:
  - `id`;
  - `object_type`;
  - `object_id`;
  - `event_type`;
  - `public_message`;
  - `changes`;
  - `created_at`;
  - `visibility_scope`;
- Anti-AML-2 regression tests proving `CaseNote.body`, `EDDRecord.confidential_comment`, raw `diff_json`, value hashes, credentials, session material, checker-private markers, and artificial flag fields do not appear in timeline responses.

## Validation Gate

Current branch validation authority:

```sh
python -B scripts/check_wave08_gate.py
make wave08-gate
```

The Wave 08 gate checks:

- expected migrations are ordered through `000006_create_audit_events.sql`;
- `audit_events` fields, constraints, and indexes match the secure audit contract;
- `internal/audit` has redaction helpers and owner-scoped case timeline query shape;
- existing auth/product/investigation/EDD/dedup routes remain present;
- secure owner case timeline dispatch exists under `/api/cases/`;
- graph/export/network/entities/checker/public attack-data/debug/admin routes remain absent;
- audit DTOs and projection contracts contain only redacted allowlisted fields;
- audit presenters collapse sensitive labels to `sensitive_field` and omit raw hashes/diffs;
- `CaseNote.body` and `EDDRecord.confidential_comment` stay limited to owner note/EDD contexts;
- Anti-AML-2 HTTP, projection, and source guard tests exist;
- exploit and reference-fix scripts remain absent;
- Wave 08 handoffs, this validation summary, docs tree, and ForcAD config validation pass.

## Test Evidence

Final W08-T04 validation is recorded in `docs/wave_reports/wave_08_W08-T04_handoff.md` and includes:

- `make wave08-gate`;
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`;
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`;
- `python -B -m unittest discover -s tests -p "test_*.py"`;
- `python -B scripts/check_docs_tree.py`;
- `python -B scripts/check_wave08_gate.py`;
- `python -B scripts/validate_forcad_config.py`.

If `make` is unavailable on a local host, run the target commands directly:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave08_gate.py
python -B scripts/validate_forcad_config.py
```

On the W08-T04 Windows host, `make wave08-gate` could not be executed because `make` was not installed on `PATH`. Every underlying target command passed when run directly. The first Go test attempt also hit the known default Go build-cache permission issue; rerunning with `GOCACHE` pointed at a writable workspace cache passed, and that generated cache was removed after validation.

## CTF Invariants

- No checker PUT/GET behavior exists.
- No public attack data exists.
- No planned vulnerability exists.
- No exploit or reference-fix scripts exist.
- No graph/export/network route exists.
- AML-2 remains future-only until Wave 15.
- `CaseNote.body` and `EDDRecord.confidential_comment` remain private owner-only business fields.

## Security Invariants

- Audit timeline access is owner-scoped.
- Timeline responses do not expose raw `diff_json`, value hashes, actor/owner IDs, credentials, sessions, checker-private markers, or artificial flag fields.
- Sensitive field names are collapsed to `sensitive_field`.
- Private note bodies and EDD confidential comments are absent from audit persistence raw values and audit HTTP responses.
- Obvious out-of-scope route expansions remain blocked by the Wave 08 gate.

## Status

Wave 07 is complete. Wave 08 is `needs fixes` pending orchestrator review of W08-T01, W08-T02, W08-T03, and W08-T04.
