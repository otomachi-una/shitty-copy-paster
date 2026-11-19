# W34-P06 Player Source/Admin Artifact Gate

## Summary

`make player-source-admin-artifact-gate` is the artifact-first final A/D acceptance command for the source-based Sentinel AML distribution model. It builds the player source artifact and admin organizer artifact, verifies their exact SHA-256 values against manifests, validates hygiene, and then runs live runtime plus checker/sploit/fix evidence only from extracted artifact trees.

## Exact Outputs

- Player source: `out/artifacts/sentinel-aml-player-source.tar.gz`
- Admin organizer: `out/artifacts/sentinel-aml-admin-organizer.tar.gz`
- Summary: `out/validation/player_source_admin_artifact_gate_summary.json`

## Command

```sh
make player-source-admin-artifact-gate
```

Equivalent direct command:

```sh
python -B scripts/check_player_source_admin_artifact_gate.py --summary-output out/validation/player_source_admin_artifact_gate_summary.json
```

## Gate Phases

1. Clean gate-owned output and validation work directories.
2. Build `sentinel-aml-player-source.tar.gz`.
3. Build `sentinel-aml-admin-organizer.tar.gz`.
4. Bind both artifacts to SHA-256 values from external manifests.
5. Validate player source manifest and anti-spoiler hygiene.
6. Validate admin contents and organizer-only hygiene.
7. Unpack both transfer archives into a clean validation directory.
8. Build and run the extracted player source with Docker Compose.
9. Run public API/UI smoke checks.
10. Run admin checker CHECK/HAVOC, both PUT/GET flag stores, and noise lifecycle when available.
11. Run all five reference sploits from the extracted admin artifact against the extracted player runtime.
12. Apply all five reference fixes to a clean extracted player-source copy using deterministic player-source patch path remapping.
13. Rebuild the fixed player runtime and confirm sploits are blocked while checker CHECK/GET remains green.

## External Runtime Handling

If Docker or the Compose plugin is unavailable, the gate records `external-required` and exits non-zero. That result is not a pass and cannot be used as final acceptance.

## Security Notes

The summary records artifact SHA-256 values, phase statuses, public endpoint checks, and per-row matrix outcomes. It stores hashes of generated test values rather than raw flags and redacts checker secrets, private state, sessions, and tokens from command/error tails.

## Invariants

- No repository source tree is used as a substitute after artifacts are built.
- Player validation runs from the exact player source tarball.
- Checker, sploits, and fixes run from the exact admin organizer tarball.
- All five sploits and all five fixes remain in scope.
- Admin materials remain organizer-only.
