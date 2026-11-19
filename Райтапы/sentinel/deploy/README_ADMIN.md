# Sentinel AML Admin Organizer Package

This package is organizer-only. It contains checker, reference exploit, reference fix, validation, and evidence materials that must not be distributed to participant teams.

## Checker

Set the service address and checker secret in the execution environment used by the gameserver. The checker entrypoint is:

```sh
python -B checkers/sentinel_aml/checker.py check <host>
python -B checkers/sentinel_aml/checker.py havoc <host>
python -B checkers/sentinel_aml/checker.py put <host> <flag_id> <flag> <vuln>
python -B checkers/sentinel_aml/checker.py get <host> <flag_id> <flag> <vuln>
```

ForcAD registration metadata is in `config.yml`.

## Reference Exploits

Run the five reference exploit scripts from `sploits/sentinel_aml/` against a live player-source deployment when validating the competition matrix:

```sh
python -B sploits/sentinel_aml/aml_dedup_preview.py
python -B sploits/sentinel_aml/aml_audit_timeline.py
python -B sploits/sentinel_aml/aml_related_graph.py
python -B sploits/sentinel_aml/aml_export_redaction.py
python -B sploits/sentinel_aml/aml_network_room.py
```

## Reference Fixes

The five reference patches live under `fixes/sentinel_aml/`. Apply each patch to an extracted player source tree, then rerun checker CHECK plus the relevant exploit-blocked validation.

## Exact Artifact Acceptance

Use this package together with the exact player source artifact:

```sh
python -B scripts/check_player_source_runtime.py out/artifacts/sentinel-aml-player-source.tar.gz
python -B scripts/check_exact_artifact_live_acceptance.py --player-artifact out/artifacts/sentinel-aml-player-source.tar.gz --admin-artifact out/artifacts/sentinel-aml-admin-organizer.tar.gz
python -B scripts/check_competition_matrix_gate.py
```

Do not copy this package into player source distributions.
