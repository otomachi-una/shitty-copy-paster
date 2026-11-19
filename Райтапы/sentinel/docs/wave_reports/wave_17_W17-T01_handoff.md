# Wave 17 W17-T01 Handoff

## 1. Summary

Implemented the controlled AML-4 vulnerable export profile behind the
`aml4_vulnerable` Go build tag. The default build remains recursively redacted.
The tagged profile leaks only linked duplicate-case private analyst note bodies
through authenticated dispute export bundle generation.

## 2. Implementation Details

- Added compile-time export profile hooks in `internal/exporting` and
  `internal/httpapi`.
- Kept the default export profile inert under `!aml4_vulnerable`.
- Added the tagged AML-4 export profile so linked duplicate case private notes
  are copied into export profile data only when the request is a dispute export
  and linked cases are in scope.
- Reused the existing casework dedup/private-note eligibility helper so the leak
  is reachable only through normal authenticated duplicate/dispute product flow.
- Extended export bundle context with `dispute_id` so vulnerable output is not
  produced for ordinary non-dispute case exports.
- Kept default export DTO/source guard compatibility by leaving the vulnerable
  field name in tagged profile data, not default typed DTO fields.
- Did not change checker PUT/GET paths, public attack data, sploit files, fix
  files, runtime routes, or AML-1/AML-2/AML-3 behavior.

## 3. Files Changed

- `internal/exporting/redaction.go`
- `internal/exporting/export_profile_secure.go`
- `internal/exporting/export_profile_aml4_vulnerable.go`
- `internal/exporting/export_profile_aml4_vulnerable_test.go`
- `internal/httpapi/server.go`
- `internal/httpapi/export_profile_secure.go`
- `internal/httpapi/export_profile_aml4_vulnerable.go`
- `internal/httpapi/export_profile_secure_test.go`
- `internal/httpapi/aml4_vulnerable_export_test.go`
- `docs/wave_reports/wave_17_W17-T01_handoff.md`

## 4. Tests Added

- Default-build secure export regression proving dispute exports do not expose
  linked private notes, EDD confidential comments, credentials, sessions, audit
  diffs, or raw internal markers.
- Tagged AML-4 HTTP test proving
  `POST /api/disputes/{dispute_id}/export` leaks the intended linked duplicate
  private note body under `aml4_vulnerable`.
- Tagged AML-4 boundedness checks proving root private notes, linked EDD
  confidential comments, credentials, sessions, AML-5/network-room-style fields,
  and cross-owner direct owner APIs remain protected.
- Tagged export bundle unit test proving profile data is emitted only for
  dispute exports with linked cases and contains only linked private notes.

## 5. Tests Run

Commands were run from Windows PowerShell with `GOTOOLCHAIN=local`,
`GOFLAGS=-mod=vendor`, `GOTELEMETRY=off`, and temp `GOCACHE`/`APPDATA`
directories outside the repository.

```sh
go test ./internal/exporting ./internal/httpapi
go test -tags aml4_vulnerable ./internal/exporting ./internal/httpapi
go test ./...
go test -tags aml4_vulnerable ./...
go vet ./...
```

Results:

- `go test ./internal/exporting ./internal/httpapi`: pass.
- `go test -tags aml4_vulnerable ./internal/exporting ./internal/httpapi`:
  pass.
- `go test ./...`: pass.
- `go test -tags aml4_vulnerable ./...`: pass.
- `go vet ./...`: pass.

## 6. Documentation Updated

Added this Wave 17 W17-T01 implementation handoff. Broader vulnerability matrix,
projection matrix, testing strategy, roadmap, and risk-register updates remain
for the later Wave 17 documentation/gate tasks.

## 7. CTF Invariants Checked

- Checker GET for place 1 still reads owner `/api/cases/{case_id}/notes`.
- Checker GET for place 2 still reads owner
  `/api/customers/{customer_id}/edd`.
- Public attack data remains unchanged and credential-free.
- AML-4 is available only in the tagged vulnerable build.
- AML-5, reference sploits, and reference fixes were not added.
- AML-1, AML-2, and AML-3 profile behavior was not changed.

## 8. Security Invariants Checked

- Default build export responses remain recursively redacted.
- The AML-4 leak is local to linked duplicate-case note data in dispute export
  bundles.
- EDD confidential comments are not exposed by AML-4 tests.
- Audit diffs, credentials, sessions, raw rows, direct owner API bypasses, and
  network-room data remain excluded.
- No hidden debug/admin route, runtime vulnerability toggle, or direct DB
  checker path was introduced.

## 9. Self-Review

The vulnerable behavior was introduced in
`internal/exporting/export_profile_aml4_vulnerable.go` and
`internal/httpapi/export_profile_aml4_vulnerable.go`. Profile selection is
compile time via `//go:build aml4_vulnerable`; the secure profile files compile
when that tag is absent. The HTTP hook populates linked-case notes only after
the normal export flow has resolved duplicate candidates, and the exporting hook
emits only private notes from linked cases when a dispute export context is
present.

## 10. Risks / Open Questions

- The broader Wave 17 gate and source-of-truth documentation updates are still
  pending in later Wave 17 tasks.
- The vulnerable profile intentionally places linked note bodies in a generic
  profile-data map to keep default source guard tests from accepting raw
  sensitive DTO fields in secure source paths.

## 11. Ready for Orchestrator Review

yes
