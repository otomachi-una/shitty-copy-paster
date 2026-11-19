# Wave 16 W16-T01 Handoff

## 1. Summary

Implemented the controlled AML-3 vulnerable related-graph profile behind the
`aml3_vulnerable` Go build tag. The default build keeps graph EDD summaries
metadata-only. The tagged profile narrows the planned leak to
`GET /api/graph/entities/{entity_hint}/edd-summaries`, where an authenticated
user who owns at least one customer in the normalized `entity_hint` cluster can
see related EDD `confidential_comment` values.

## 2. Implementation Details

- Added the `aml3_vulnerable` profile split in `internal/httpapi`.
- Updated the graph EDD-summary handler to call a profile-specific response
  builder.
- Kept default `EDDGraphSummariesResponse` unchanged in the secure profile.
- Added a tagged vulnerable response shape that preserves public summary fields
  and adds only `confidential_comment`.
- Added a tagged `internal/graph` repository helper that selects
  `er.confidential_comment` only under `aml3_vulnerable`, while preserving the
  existing authenticated entity-hint access check.
- Did not change checker PUT/GET, public attack data, exploit files, fixes, or
  runtime routes.

## 3. Files Changed

- `internal/httpapi/server.go`
- `internal/httpapi/graph_profile_secure.go`
- `internal/httpapi/graph_profile_aml3_vulnerable.go`
- `internal/graph/repository_aml3_vulnerable.go`
- `internal/httpapi/graph_profile_secure_test.go`
- `internal/httpapi/aml3_vulnerable_graph_test.go`
- `docs/wave_reports/wave_16_W16-T01_handoff.md`

## 4. Tests Added

- Default-build secure profile test proving AML-3 is disabled and graph
  `/edd-summaries` does not expose `confidential_comment`.
- Tagged AML-3 test proving the intended `confidential_comment` exposure through
  graph EDD summaries.
- Tagged boundedness checks proving case-note bodies, EDD narrative fields,
  audit internals, credentials/session material, transaction traces, raw DB row
  markers, export responses, and network-room dossiers are not broadened.
- Tagged cross-owner direct note/EDD checks proving owner APIs remain
  fail-closed.

## 5. Tests Run

Commands were run on Windows PowerShell with `GOTOOLCHAIN=local`,
`GOFLAGS=-mod=vendor`, `GOTELEMETRY=off`, and workspace-local `GOCACHE` and
`APPDATA`.

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml3_vulnerable ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
```

Results:

- `go test ./...`: pass.
- `go test -tags aml3_vulnerable ./...`: pass.
- `go vet ./...`: pass.

## 6. Documentation Updated

Added this W16-T01 handoff report. Broader roadmap, vulnerability-matrix, and
gate documentation remain for later Wave 16 documentation/gate tasks.

## 7. CTF Invariants Checked

- Public attack data remains unchanged and credential-free.
- Future AML-3 exploit can use place 2 public `entity_hint` as a locator.
- Checker owner GET paths for `CaseNote.body` and
  `EDDRecord.confidential_comment` remain independent of graph side views.
- No AML-3 exploit or reference fix file was added.
- AML-4 and AML-5 were not activated.

## 8. Security Invariants Checked

- Default build graph remains metadata-only.
- AML-3 exists only under the `aml3_vulnerable` build tag.
- The tagged leak is limited to graph EDD-summary `confidential_comment`.
- Cross-owner direct note and EDD APIs still fail closed.
- No hidden debug/admin route, runtime profile toggle, direct DB checker path,
  raw database serialization, credentials, sessions, audit hashes, transaction
  trace IDs, export leak, or network-room leak was introduced.

## 9. Self-Review

The vulnerable behavior was introduced in
`internal/httpapi/graph_profile_aml3_vulnerable.go` and
`internal/graph/repository_aml3_vulnerable.go`. Profile selection is compile
time via `//go:build aml3_vulnerable`; the default profile file is compiled
when that tag is absent. Existing secure graph DTOs remain unchanged.

## 10. Risks / Open Questions

- W16 gate and full documentation alignment are not part of this task scope and
  remain for later Wave 16 tasks.
- This implementation intentionally exposes related EDD comments for every EDD
  record in an accessible entity-hint cluster under the vulnerable profile.

## 11. Ready for Orchestrator Review

yes
