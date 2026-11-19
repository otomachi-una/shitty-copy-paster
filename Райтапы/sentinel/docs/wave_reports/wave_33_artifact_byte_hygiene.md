# W33-AF2 Artifact-Byte Hygiene Gates

## Summary

W33-AF2 adds strict hygiene checks for the exact player and admin transfer
artifacts. The scanner reads archive members and content bytes from explicit
artifact paths, strips the stable transfer root, and applies audience-specific
rules.

## Scanner Rules

Player artifacts fail on:

- checker, sploit, fix, test, internal script, and docs paths;
- source maps and source-map references;
- CTF and vulnerability-map vocabulary in player-facing paths or content;
- internal build-profile source vocabulary and dual-policy source names;
- unsafe archive member paths;
- local/generated/cache artifacts including `node_modules/`, `__pycache__/`,
  `.tsbuildinfo`, `tmp/`, `temp/`, `out/`, `.gocache*`, `.appdata*`, `.pyc`,
  and nested archive files.

Admin artifacts fail when:

- required organizer evidence is missing, including checker, sploit, fix, test,
  wave evidence, and ForcAD material;
- local/generated/cache artifacts are present.

The existing narrow admin/checker candidate hygiene remains intact and still
rejects reference sploit/fix/vulnerability-map material from that operator-only
candidate.

## Tests Added

- Synthetic clean player artifact passes.
- Synthetic player artifact with checker/sploit/fix members fails.
- Synthetic player artifact with a source map fails.
- Synthetic player artifact with forbidden CTF/vulnerability vocabulary fails.
- Synthetic admin artifact missing checker/fix/sploit evidence fails.
- Synthetic player and admin artifacts containing `node_modules/`,
  `__pycache__/`, `.tsbuildinfo`, `tmp/`, or `.gocache*` fail.
- Combined runner scans explicit archive paths.

## Current Artifact Scan

Command:

```sh
python -B scripts/check_artifact_hygiene.py --player-artifact out/artifacts/sentinel-aml-player-service.tar.gz --admin-artifact out/artifacts/sentinel-aml-admin-organizer.tar.gz
```

Result:

- player artifact: pass;
- admin/organizer artifact: fail.

Violations:

- `frontend/tsconfig.app.tsbuildinfo`;
- `frontend/tsconfig.node.tsbuildinfo`.

These are generated frontend TypeScript build-info files inside the current
admin transfer artifact. They remain hard failures and are not allowlisted.

## CTF Invariants

- Player artifact hygiene does not allow checker, sploit, fix, docs, wave
  report, or vulnerability-map disclosure.
- Admin/organizer hygiene requires checker, five sploits, five fixes, tests,
  and wave evidence to remain present.
- No checker behavior, sploit behavior, fix behavior, product runtime behavior,
  or CHECK/HAVOC semantics changed.

## Ready for Review

Ready for scanner review. Current artifact bytes are not clean because the
admin/organizer archive contains generated `.tsbuildinfo` files.
