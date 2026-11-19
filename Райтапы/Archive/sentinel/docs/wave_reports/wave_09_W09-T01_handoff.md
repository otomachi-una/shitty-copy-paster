# Wave 09 W09-T01 Handoff - Graph Persistence and Repository Primitives

## 1. Summary

W09-T01 adds the secure related-entity graph persistence foundation and repository primitives. The implementation creates architecture-aligned materialized graph node/edge tables, while the repository currently derives safe graph summaries at query time from existing `entity_hint`, case shell metadata, and EDD review status.

Ready for orchestrator review: yes.

## 2. Implementation Details

- Added ordered migration `000007_create_entity_graph.sql`.
- Added `entity_graph_nodes` and `entity_graph_edges` with nonblank hints, allowed node/relation values, uniqueness, indexes, and edge-strength bounds.
- Added `internal/graph.Repository` with:
  - `HasEntityAccess` for explicit owner-owned `entity_hint` authorization;
  - `GetEntitySummary` for safe related-entity counts, public risk tags, highest risk, relation type, and timestamps;
  - `ListRelatedCases` for safe public case/customer metadata;
  - `ListEDDSummaries` for EDD review status and customer risk metadata without confidential comments or raw EDD narrative fields.
- Kept graph access separate from private case-note and EDD authorization.
- Kept graph output as explicit domain/repository structs, not raw DB rows.
- Did not add graph HTTP routes, graph workers, checker paths, public attack data, or AML-3 behavior.

Materialized-vs-query-time decision: W09-T01 creates `entity_graph_nodes` and `entity_graph_edges` to preserve the architecture's table names and future persistence shape, but repository reads use query-time discovery until a later wave defines deterministic graph materialization/update semantics.

## 3. Files Changed

- `migrations/000007_create_entity_graph.sql`
- `internal/graph/repository.go`
- `internal/graph/repository_test.go`
- `tests/migration_sql_test.go`
- `docs/04_database_model.md`
- `docs/06_visibility_and_projections.md`
- `docs/audit_export_graph_invariants.md`
- `docs/10_workers_and_async_flows.md`
- `docs/12_testing_strategy.md`
- `docs/15_risk_register.md`
- `docs/wave_reports/wave_09_W09-T01_handoff.md`

## 4. Tests Added

- Migration ordering coverage through `000007_create_entity_graph.sql`.
- Graph table shape tests for nodes, edges, constraints, and indexes.
- Owner graph-access happy path and non-owner denial tests.
- Safe entity summary tests.
- Safe related case summary tests.
- Safe EDD graph summary tests.
- Query-source guard tests rejecting private note bodies, EDD confidential comments, raw EDD narrative fields, audit diffs, credentials, session material, checker-private markers, and artificial flag fields.
- Invalid entity-hint and context-cancellation tests.

## 5. Tests Run

- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/graph ./tests` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...` - passed.
- `GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...` - passed.
- `python -B scripts/check_docs_tree.py` - passed.
- `python -B scripts/validate_forcad_config.py` - passed.

Go commands used a workspace-local writable `GOCACHE` to avoid the known Windows default build-cache access-denied issue.

## 6. Documentation Updated

- Database model documents `entity_graph_nodes`, `entity_graph_edges`, constraints, indexes, and the materialized-schema/query-time-summary decision.
- Visibility/projection docs describe safe graph authorization and forbidden graph fields.
- Audit/export/graph invariant docs distinguish secure graph persistence from AML-3.
- Worker docs state that no graph worker, queue, refresh job, or traversal job exists in W09-T01.
- Testing strategy documents focused graph and migration coverage.
- Risk register adds graph metadata overreach mitigation.

## 7. CTF Invariants Checked

- No checker PUT/GET path was added.
- No public attack data was added.
- No vulnerability behavior was added.
- No exploit or reference-fix script was added.
- No direct DB checker dependency was added.
- Future flag stores remain private owner fields only.

## 8. Security Invariants Checked

- Graph access is granted only when the requesting analyst owns at least one customer for the normalized `entity_hint`.
- Graph query tests reject private `CaseNote.body`, `EDDRecord.confidential_comment`, raw EDD `source_of_funds`, raw EDD `risk_rationale`, raw audit `diff_json`, credentials, token/session fields, owner IDs, checker-private markers, and artificial flag fields.
- Graph outputs are explicit safe structs and contain only public/metadata fields.
- Graph rights do not expand private case-note or EDD rights.

## 9. Self-Review

This task stayed within persistence, repository, tests, and documentation. It did not modify HTTP handlers, checker code, sploit placeholders, ForcAD config, audit timeline behavior, dedup vulnerable behavior, export/network-room behavior, or production routes.

Known gap: the materialized graph tables are not populated by a worker in W09-T01. That is intentional; future graph API or worker waves must define deterministic population semantics before using the materialized tables as an active read source.

## 10. Risks / Open Questions

- Future graph HTTP work must add projection allowlists and leak regression tests before exposing repository data.
- Future graph materialization must remain deterministic and must not copy private note, EDD, audit, auth/session, checker-private, or flag-bearing fields into graph tables.
- Earlier wave gates remain historical and may reject the intentional Wave 09 graph migration until a Wave 09 gate updates current-branch authority.

## 11. Ready for Orchestrator Review

yes
