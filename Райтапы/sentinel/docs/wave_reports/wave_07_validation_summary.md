# Wave 07 Validation Summary

## Scope

Wave 07 adds the secure dedup baseline:

- `cases.dedup_hint` metadata via `migrations/000005_add_case_dedup_hint.sql`;
- owner-verified duplicate candidate discovery in `internal/casework`;
- authenticated secure dedup endpoints:
  - `GET /api/cases/{case_id}/duplicates`;
  - `GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview`;
- public-only `CaseDuplicatePreviewView` DTO/projection fields:
  - `case_id`;
  - `public_summary`;
  - `risk_tags`;
  - `overlap_score`;
  - `match_explanation`;
- Anti-AML-1 regression tests proving private note and EDD confidential-comment sentinels do not appear in dedup responses.

## Validation Gate

Current branch validation authority:

```sh
python -B scripts/check_wave07_gate.py
make wave07-gate
```

The Wave 07 gate checks:

- expected migrations are ordered through `000005_add_case_dedup_hint.sql`;
- no out-of-scope dedup, audit, graph, export, network, worker, checker-private, public attack-data, or flag-store tables exist;
- existing auth/product/investigation/EDD routes remain present;
- secure dedup dispatch exists under `/api/cases/`;
- graph/export/network/entities/checker/public attack-data/debug/admin routes remain absent;
- dedup DTOs and projection contracts contain only public overlap fields;
- dedup presenters omit `CaseNote.body`, `EDDRecord.confidential_comment`, `private_notes`, audit/diff markers, auth/session markers, owner IDs, raw DB rows, and checker-private markers;
- Anti-AML-1, HTTP leak-regression, and source guard tests exist;
- exploit and reference-fix scripts remain absent;
- Wave 07 handoffs, this validation summary, docs tree, and ForcAD config validation pass.

## Test Evidence

Final W07-T04 validation ran:

- `make wave07-gate` was attempted, but this Windows host does not have `make`, `mingw32-make`, or `gmake` on `PATH`;
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`;
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`;
- `python -B -m unittest discover -s tests -p "test_*.py"`;
- `python -B scripts/check_docs_tree.py`;
- `python -B scripts/check_wave07_gate.py`;
- `python -B scripts/validate_forcad_config.py`;
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run "Dedup|AML1|Visibility|CaseDuplicatePreview" -count=1`;
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/projection ./tests -run "Projection|Dedup|Wave07" -count=1`.

The `make wave07-gate` target exists in `Makefile`; every underlying target command passed when run directly. Go commands used vendor mode and a local writable `GOCACHE` where needed.

## CTF Invariants

- No checker PUT/GET behavior exists.
- No public attack data exists.
- No planned vulnerability exists.
- No exploit or reference-fix scripts exist.
- AML-1 remains locked until Wave 14.
- `CaseNote.body` and `EDDRecord.confidential_comment` remain private owner-only business fields.

## Security Invariants

- Dedup candidate visibility does not grant private investigation visibility.
- Merge-preview exposes public overlap metadata only.
- Cross-owner source case access fails closed.
- Private note bodies and EDD confidential comments are absent from dedup list and merge-preview responses.
- Obvious out-of-scope route expansions remain blocked by the Wave 07 gate.

## Status

Wave 06 is complete. Wave 07 is `needs fixes` pending orchestrator review of W07-T01, W07-T02, W07-T03, and W07-T04.
