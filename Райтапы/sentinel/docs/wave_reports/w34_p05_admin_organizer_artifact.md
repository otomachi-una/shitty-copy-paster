# W34-P05 Admin Organizer Artifact

## Summary

`sentinel-aml-admin-organizer.tar.gz` is the organizer-only distribution package for Sentinel AML. It is separate from the player source artifact and contains checker, reference exploit, reference fix, validation, test, documentation, and evidence materials needed by competition operators.

## Artifact Contract

- Player artifact: `out/artifacts/sentinel-aml-player-source.tar.gz`
- Admin artifact: `out/artifacts/sentinel-aml-admin-organizer.tar.gz`
- Admin external manifest: `out/artifacts/ADMIN_MANIFEST.json`
- Admin external checksums: `out/artifacts/ADMIN_SHA256SUMS`

The admin archive is never player-facing and must not be copied into participant source packages.

## Build And Validation

Build:

```sh
python -B scripts/build_admin_organizer_artifact.py --output out/artifacts/sentinel-aml-admin-organizer.tar.gz
```

Validate exact archive bytes:

```sh
python -B scripts/check_admin_artifact_contents.py out/artifacts/sentinel-aml-admin-organizer.tar.gz
python -B scripts/check_admin_artifact_hygiene.py out/artifacts/sentinel-aml-admin-organizer.tar.gz
```

Make target:

```sh
make admin-organizer-artifact-gate
```

## Contents

The archive contains:

- `checkers/sentinel_aml/`
- `sploits/sentinel_aml/`
- `fixes/sentinel_aml/`
- `scripts/`
- `tests/`
- `docs/`
- `validation/README.md`
- `README_ADMIN.md`
- `ADMIN_MANIFEST.json`
- `SHA256SUMS`
- `Makefile`
- `config.yml`

The archive excludes generated local transfer artifacts, caches, nested player/admin archives, local validation extraction trees, and archived foreign materials.

## Operator Flow

1. Deploy or extract the exact player source artifact.
2. Run player runtime checks with `scripts/check_player_source_runtime.py`.
3. Run checker CHECK/HAVOC/PUT/GET from `checkers/sentinel_aml/`.
4. Run all five reference exploit scripts from `sploits/sentinel_aml/`.
5. Apply each reference patch from `fixes/sentinel_aml/` to a copied player tree and rerun checker plus exploit-blocking validation.
6. Record the exact SHA-256 values from `ADMIN_MANIFEST.json` and the player source manifest.

## Invariants

- Organizer checker, sploits, fixes, and evidence remain authoritative.
- Organizer-only materials are not copied into player source.
- The admin package is labeled organizer-only in both `README_ADMIN.md` and `ADMIN_MANIFEST.json`.
- Validation is tied to exact artifact bytes through the external manifest.
