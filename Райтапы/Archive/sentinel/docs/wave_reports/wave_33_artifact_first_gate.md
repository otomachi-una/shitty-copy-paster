# W33-AF5 Aggregate Artifact-First Gate

## Summary

W33-AF5 adds `make artifact-first-gate` as the bounded aggregate gate for
artifact-first review. The gate starts with generated-output cleanup, then
builds the transfer artifacts and tests the exact archive bytes before writing
one machine-readable validation summary.

AF-F01 reconciles the delivered artifact boundary used by both
`artifact-gate` and `artifact-first-gate`: the canonical player contract is a
single `player-service-with-ui.v1` artifact containing backend runtime binaries
and participant UI runtime files. The gate must not pass with the UI marked
not applicable.

AF-F02 makes `frontend/dist` the documented prebuilt UI input for transfer
packaging. The aggregate gate runs the frontend source scanner and dist scanner
before building the artifacts, then scans the final player tarball bytes.

AF-F03/AF-F04 make runtime readiness evidence artifact-local. The validation
summary stamps the player artifact SHA-256, admin artifact SHA-256, runtime
smoke status, checker CHECK/HAVOC status, five-sploit status, five-fix workflow
status, and matrix status. Player-facing `PACKAGING_STATUS.json` records
operational package contents and runtime requirements; exact-artifact runtime
proof remains in the external validation summary when live validation is not run
locally.

AF-F05 separates the internal repository-submission zip from player/admin
transfer artifact hygiene. `make repository-submission-archive` creates a clean
internal review zip without generated outputs, frontend build/install output,
caches, bytecode, test reports, local QA folders, or nested transfer archives.
When transfer checksums exist, the zip references player/admin transfer
artifacts by checksum only.

This report does not claim final release acceptance.

## Gate Command

```sh
/usr/bin/timeout 300 make artifact-first-gate
```

The internal runner uses a 285 second aggregate deadline so the external
`timeout 300` wrapper has room to terminate cleanly.

## Phase Order

1. `clean-generated` with frontend UI build preservation for packaging
2. `verify-frontend-ui-source-scan`
3. `verify-frontend-ui-dist-scan`
4. `build-transfer-artifacts`
5. `verify-artifact-inventory`
6. `verify-player-artifact-hygiene`
7. `verify-admin-artifact-hygiene`
8. `verify-repository-submission-hygiene`, only when `REPOSITORY_SUBMISSION`
   is supplied
9. `verify-player-ui-artifact`
10. `verify-player-runtime-profile-evidence`
11. `verify-admin-checker-sploit-fix-matrix-evidence`

`build-transfer-artifacts` is the only `build_artifacts.py` build pass; it
creates both the player-service and admin/organizer archives. The subsequent
`verify-artifact-inventory` phase is the only `--verify-only` pass and checks
the generated transfer inventory and checksum bytes before hygiene and runtime
evidence checks.

The validation summary is written to
`out/artifact-first-validation-summary.json`.

## External Gates

The summary records live runtime obligations as `external-required` when they
are not run by this bounded byte-validation pass:

- runtime smoke from the player artifact;
- checker CHECK/HAVOC from the admin artifact against that runtime;
- five sploits from the admin artifact against that runtime;
- five fixes through the accepted fix workflow;
- checker/sploit/fix matrix evidence against a deployed player runtime.

Each obligation is tied in the summary to the exact current-run artifact
SHA-256 values. Historical wave reports remain context only and are not treated
as runtime readiness proof for newly generated transfer bytes.

Static artifact evidence still preserves the checker, five sploits, five fixes,
runtime matrix references, and CHECK/HAVOC evidence through the admin/organizer
artifact.

## Repository Submission Boundary

The repository-submission artifact is
`out/repository-submission/sentinel-aml-repository-submission.zip`. It is an
internal review snapshot and is scanned with
`scripts/check_repository_submission_hygiene.py`. It is intentionally separate
from the player/admin transfer artifacts under `out/artifacts/`, which remain
validated by artifact-byte hygiene scanners against the exact tarball bytes.

## Player Component Contract

The player archive, `out/manifests/player_manifest.json`, and
`PACKAGING_STATUS.json` must agree on delivered components:

- `backend-runtime`, required and included under `bin/`;
- `participant-ui`, required and included under `ui/`;
- `ui/index.html` and `ui/runtime-config.js` are mandatory runtime files.

The player manifest lists the exact delivered UI members and their per-file
SHA-256 digests. Source maps, frontend source, tests, Playwright reports,
package metadata, `node_modules`, caches, and `.tsbuildinfo` remain forbidden in
the transfer artifact.

## Ready for Review

Ready for artifact-first gate review only.
