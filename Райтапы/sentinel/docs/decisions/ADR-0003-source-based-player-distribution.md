# ADR-0003: Source-Based Player Distribution

## Status

Accepted for Wave 34 packaging contract work.

## Context

Sentinel AML is distributed for Attack-Defense play. Participant teams must be able to inspect, patch, test, and rebuild the service they run. A binary player package is useful for smoke tests and runtime proof, but binary-only is not sufficient for classic A/D distribution.

Existing full repository archives are not safe player artifacts because they can contain organizer-only checker, sploit, reference-fix, test, validation, and evidence material.

## Decision

The canonical player artifact is `out/artifacts/sentinel-aml-player-source.tar.gz`.

The canonical organizer artifact is `out/artifacts/sentinel-aml-admin-organizer.tar.gz`.

The optional binary artifact is `out/artifacts/sentinel-aml-player-binary.tar.gz`, and it is explicitly non-primary.

Historical `out/artifacts/sentinel-aml-player-service.tar.gz` output may exist only as a legacy compatibility alias for older runtime gates. It is non-primary.

Full repository zip is never a player artifact.

Artifact-first validation must validate the exact archive bytes, matching manifests, checksums, and the source/admin role contract before distribution readiness can be claimed.

## Consequences

Player distribution is source-based and patchable by teams.

Organizer-only materials remain separated in the admin/organizer artifact.

Binary runtime validation can remain useful, but it cannot replace source-based player distribution.

Repository-submission archives remain review artifacts, not player-facing artifacts.
