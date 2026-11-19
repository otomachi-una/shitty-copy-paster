# Sentinel AML Source/Admin Artifact Contract

## Canonical Outputs

The canonical participant artifact is:

```text
out/artifacts/sentinel-aml-player-source.tar.gz
```

The organizer-only artifact is:

```text
out/artifacts/sentinel-aml-admin-organizer.tar.gz
```

An optional binary runtime convenience artifact may also be generated:

```text
out/artifacts/sentinel-aml-player-binary.tar.gz
```

`sentinel-aml-player-source.tar.gz` is the primary player distribution. It contains sanitized backend service source plus a prebuilt static frontend bundle. Teams can inspect, patch, test, and rebuild the Go service during classic Attack-Defense play; frontend source and npm build inputs stay organizer-side.

`sentinel-aml-admin-organizer.tar.gz` is organizer-only. It owns checker, sploit, reference-fix, test, gate, and evidence material. It must never be marked player-facing.

`sentinel-aml-player-binary.tar.gz` is non-primary. Binary-only is not sufficient for classic A/D distribution because teams need source code to produce their own patched builds.

Historical `sentinel-aml-player-service.tar.gz` outputs, when present, are legacy compatibility aliases for older runtime gates. They are non-primary and are not the player distribution contract.

Full repository zip is never a player artifact. Repository handoff archives are review/submission artifacts only and must not be substituted for the player source package.

## Required Separation

The player source package must exclude organizer-only material, internal validation outputs, generated transfer archives, repository caches, and historical wave evidence.

The admin/organizer package may preserve organizer evidence and validation material needed to operate and review the challenge.

Artifact-first validation is mandatory: manifests, checksum records, static frontend hashes, and byte-level validation must bind readiness claims to the exact archives under `out/artifacts/`.
