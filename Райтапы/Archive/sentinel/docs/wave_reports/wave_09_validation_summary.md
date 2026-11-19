# Wave 09 Validation Summary

## Summary

Wave 09 adds the secure related-graph baseline for Sentinel AML. The current branch includes `migrations/000007_create_entity_graph.sql`, `internal/graph` repository primitives, authenticated graph metadata endpoints, explicit graph DTO/projection allowlists, Anti-AML-3 regression tests, and a branch-level validation gate at `scripts/check_wave09_gate.py`.

Wave 08 is complete. Wave 09 is `needs fixes` until W09-T01, W09-T02, W09-T03, and W09-T04 pass orchestrator review.

## Implemented Scope

- Graph persistence foundation: `entity_graph_nodes` and `entity_graph_edges`.
- Secure owner-authenticated graph route family:
  - `GET /api/graph/entities/{entity_hint}`
  - `GET /api/graph/entities/{entity_hint}/related-cases`
  - `GET /api/graph/entities/{entity_hint}/edd-summaries`
- Safe response DTOs:
  - `GraphEntityView`
  - `GraphRelatedCaseView`
  - `EDDGraphSummaryView`
- Projection contracts for `graph_entity`, `graph_related_case`, and `edd_graph_summary`.
- Named Anti-AML-3 tests proving graph views do not expose private stores.

## Gate Coverage

`scripts/check_wave09_gate.py` checks migration ordering, expected graph tables, graph repository safe shape, graph route registration, graph DTO fields, graph projection contracts, Anti-AML-3 test markers, response visibility boundaries, sensitive log markers, absence of exploit/fix scripts, required Wave 09 handoff reports, source-of-truth status markers, Makefile target coverage, docs tree validation, and ForcAD config validation.

Run:

```sh
python -B scripts/check_wave09_gate.py
make wave09-gate
```

## CTF Invariants

- No checker PUT/GET behavior exists.
- No public attack data exists.
- No exploit or reference-fix scripts exist.
- No planned vulnerability behavior exists.
- AML-1 remains future-only until Wave 14.
- AML-2 remains future-only until Wave 15.
- AML-3 remains future-only until Wave 16.
- `CaseNote.body` and `EDDRecord.confidential_comment` remain private business fields, not active checker stores.

## Security Invariants

- Graph access requires authentication and an owned normalized `entity_hint`.
- Graph visibility is safe metadata visibility, not private investigation visibility.
- Graph responses do not expose private note bodies, EDD confidential comments, EDD narrative fields, raw audit diffs, credentials, session material, owner IDs, analyst/author/assignee IDs, transaction trace IDs, counterparty fingerprints, checker-private markers, artificial flag fields, or raw DB rows.
- Cross-owner and unknown graph hints fail closed.
- Projection allowlists remain authoritative for graph response shapes.

## Validation Results

- `make wave09-gate`: not runnable on this Windows host because `make` is not installed on `PATH`; the target exists and every underlying command was run directly.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...`: initial run hit the known Windows default Go build-cache access-denied condition, then passed with `GOCACHE` set to a writable workspace cache.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...`: passed with the writable workspace `GOCACHE`.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/projection ./tests -run "AML3|Graph|Visibility|Projection" -count=1`: passed.
- `python -B -m unittest discover -s tests -p "test_wave09_gate.py"`: passed, 9 tests.
- `python -B -m unittest discover -s tests -p "test_*.py"`: passed, 79 tests.
- `python -B scripts/check_docs_tree.py`: passed.
- `python -B scripts/check_wave09_gate.py`: passed.
- `python -B scripts/validate_forcad_config.py`: passed.

## Known Gaps

- Live PostgreSQL execution was not required for Wave 09 because the new gate is static/unit/projection focused and graph live integration remains covered by repository/API tests.
- AML-3 vulnerable behavior, exploit scripts, reference fixes, checker flows, export, and network-room behavior remain deferred.

## Ready For Orchestrator Review

Yes.
