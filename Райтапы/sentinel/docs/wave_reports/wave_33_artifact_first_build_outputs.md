# W33-AF1 Artifact-First Build Outputs

## Summary

W33-AF1 introduces deterministic transfer artifacts for the player-service and
admin/organizer audiences. The build flow writes exact archives, manifests,
and SHA-256 checksums under `out/` and validates those outputs directly rather
than relying on repo-local `tmp/` candidate leftovers.

This report does not claim final competition readiness or final release
acceptance.

## Outputs

- `out/artifacts/sentinel-aml-player-service.tar.gz`
- `out/artifacts/sentinel-aml-admin-organizer.tar.gz`
- `out/manifests/player_manifest.json`
- `out/manifests/admin_manifest.json`
- `out/checksums/SHA256SUMS`

## Implementation Notes

- `scripts/build_artifacts.py` cleans `out/artifacts/`, `out/manifests/`, and
  `out/checksums/` before every build.
- The player artifact is built from the sanitized player-service candidate
  generated in an external temporary staging directory.
- The admin/organizer artifact is built from the internal repository inventory
  and preserves checker, sploit, fix, test, docs, gate, and CHECK/HAVOC
  evidence while excluding generated output, caches, archives, frontend dist,
  local frontend dependencies, and ignored scratch paths.
- Manifests record archive-rooted file inventories, per-file sizes, per-file
  SHA-256 digests, artifact size, and artifact SHA-256 digest.
- `out/checksums/SHA256SUMS` records checksums for both archives and both
  manifests.

## Tests

`scripts/check_artifacts.py --run` covers:

- clean generated output directories;
- manifest inventory matching archive inventory;
- checksum entries matching output bytes;
- rerun cleanup of stale generated files;
- verify-only failure when a required artifact is missing;
- admin/organizer inventory retention of checker, sploit, fix, test, and wave
  evidence.

## CTF Invariants

- Competition runtime behavior is not changed.
- Both checker places remain in the organizer/admin artifact.
- All five reference sploits remain in the organizer/admin artifact.
- All five reference fixes remain in the organizer/admin artifact.
- CHECK/HAVOC tests and gate evidence remain in the organizer/admin artifact.
- The player artifact remains derived from the sanitized player-service builder
  and does not include checker, sploit, fix, tests, or wave-report evidence.

## Ready for Review

Ready for artifact-output review only.
