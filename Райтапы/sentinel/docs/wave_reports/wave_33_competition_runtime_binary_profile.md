# W33-AF4 Competition Runtime Profile Reconciliation

## Summary

W33-AF4 reconciles the competition runtime/profile gate with the current
binary/OCI-oriented player delivery strategy. The guard no longer assumes that
player validation is primarily a source Dockerfile tag-propagation check.

## Mode Implemented

Default mode is binary player delivery:

```sh
python -B scripts/check_competition_runtime_profile.py --mode binary --player-manifest out/manifests/player_manifest.json --player-artifact out/artifacts/sentinel-aml-player-service.tar.gz
```

The gate still validates the internal competition runtime tag set and internal
`competition-runtime-build` target so the secure/default baseline cannot be
accepted as the competition runtime. Player delivery validation then checks the
player manifest and archive inventory.

Explicit source mode remains available only when selected with `--mode source`.
It rejects stale secure-default Dockerfile builds and dual default/detail policy
source pairs.

## Runtime Evidence Required

Binary mode requires:

- `runtime_profile.delivery_mode` set to `binary-image` or `oci-image`;
- built runtime members for `aml-api`, `aml-worker`, and `aml-migrate`;
- no Go source surface in player archive bytes;
- manifest build-profile evidence with `labels_exposed_in_player_artifact:
  false`;
- at least one passing runtime smoke or acceptance evidence record.

Source mode requires:

- explicit `runtime_profile.delivery_mode: source`;
- runtime evidence;
- source runtime files such as `go.mod`, `go.sum`, `Dockerfile`, and
  `deploy/compose.yaml`;
- no dual-policy default/detail source pairs;
- a Dockerfile/build path that uses the competition profile rather than the
  secure/default baseline.

## Tests Added

- stale secure-default source Dockerfile is rejected;
- binary player artifact with runtime evidence passes;
- source artifact containing dual default/detail policy files fails;
- missing runtime evidence fails.

## CTF Invariants

- No vulnerability set changed.
- The internal competition profile still requires the five neutral policy tags.
- Source delivery is not required for players.
- Secure/default build cannot be accepted as competition runtime.
- Runtime proof or acceptance evidence remains required.

## Ready for Review

Ready for review as binary-mode runtime/profile gate reconciliation.
