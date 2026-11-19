# W34-P01 Distribution Model And Artifact Contract

## Summary

W34-P01 defines source-based player distribution as the canonical Sentinel AML A/D artifact contract.

## Canonical Artifacts

- `out/artifacts/sentinel-aml-player-source.tar.gz` is the primary participant artifact.
- `out/artifacts/sentinel-aml-admin-organizer.tar.gz` is organizer-only.
- `out/artifacts/sentinel-aml-player-binary.tar.gz` may be generated as non-primary runtime convenience.

Full repository zip is never a player artifact. Binary-only is not sufficient for classic A/D delivery.

## Validation

`scripts/build_artifacts.py --verify-only` now validates the source/admin contract, source archive inventory, manifest role flags, and checksum bytes for generated outputs.

The source player archive excludes checker, sploit, fix, docs, tests, validation, generated archives, and repository cache paths.

## Invariants

No product logic, checker logic, sploits, reference fixes, DB migrations, or vulnerability behavior were changed by this packaging-contract work.
