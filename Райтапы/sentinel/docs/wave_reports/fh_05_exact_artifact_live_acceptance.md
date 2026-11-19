# FH-05 Exact Artifact Live Acceptance

FH-05 adds `scripts/check_exact_artifact_live_acceptance.py` and the
`make exact-artifact-live-acceptance` target for opt-in runtime validation of
the exact player/admin transfer archive bytes.

The runner extracts:

- `out/artifacts/sentinel-aml-player-service.tar.gz`
- `out/artifacts/sentinel-aml-admin-organizer.tar.gz`

It then deploys the extracted player package with its packaged Compose
template, runs CHECK/HAVOC with the checker extracted from the admin artifact,
executes PUT/GET for both checker flag stores, runs all five extracted
reference sploits, and validates all five extracted reference fixes in isolated
admin-artifact source copies.

For live fixed-service validation, runtime hunks are applied from the exact
admin artifact patches with `*_test.go` hunks excluded. This keeps historical
test-evidence drift from blocking deployment while still proving the production
fix behavior against a live service.

The machine-readable summary is written to:

```text
out/exact-artifact-live-acceptance-summary.json
```

The summary records the exact player/admin SHA-256 values and marks
`historical_candidate_tree_substitute: false`, so historical candidate-tree
evidence cannot satisfy this acceptance path.
