# W30-T02 Handoff - Release Archive Builder And Hygiene Gate

## 1. Summary

Added a deterministic release archive builder and extended archive hygiene so
it validates generated archives, not only the working tree. Built and validated
a release archive outside the repository.

## 2. Implementation Details

- Added `scripts/build_release_archive.py` to produce
  `sentinel_aml_release.tar.gz` outside the repository.
- Normalized tar metadata for deterministic output: sorted file order, fixed
  ownership fields, fixed mtime, stable file modes, and gzip mtime set to zero.
- Excluded local cache, bytecode, editor, temporary archive, temporary review,
  and `docs/archive/` foreign material paths from the archive.
- Extended `scripts/check_archive_hygiene.py` to inspect `.tar`, `.tar.gz`,
  `.tgz`, and `.zip` archive contents directly.
- Added `make release-archive`.
- Updated deployment docs with release packaging and generated-archive
  validation instructions.

## 3. Files Changed

- `Makefile`
- `scripts/check_archive_hygiene.py`
- `scripts/build_release_archive.py`
- `tests/test_archive_hygiene.py`
- `docs/11_deployment.md`
- `docs/wave_reports/wave_30_W30-T02_handoff.md`

## 4. Tests Added

- Clean release archive with required inventory passes.
- Missing required checker artifact fails.
- Forbidden archive members fail.
- Archive path traversal fails.
- Builder determinism and foreign-artifact exclusion are covered.
- Builder rejects output directories inside the repository.

## 5. Tests Run

- `python -B -m unittest discover -s tests -p "test_archive_hygiene.py"` - exit 0.
- `python -B scripts/check_archive_hygiene.py` - exit 0.
- `python -B scripts/build_release_archive.py --output-dir C:\Users\2005g\AppData\Local\Temp\sentinel-aml-release-w30-t02` - exit 0.
- `python -B scripts/check_archive_hygiene.py C:\Users\2005g\AppData\Local\Temp\sentinel-aml-release-w30-t02\sentinel_aml_release.tar.gz` - exit 0.
- `make release-archive` - exit 0 through the WSL make path; generated archive hygiene validation also exited 0.
- `python -B scripts/check_docs_tree.py` - exit 0.
- `make wave29-gate` - exit 0.

Generated archive:

- Path:
  `C:\Users\2005g\AppData\Local\Temp\sentinel-aml-release-w30-t02\sentinel_aml_release.tar.gz`
- File count: 660.

## 6. Documentation Updated

`docs/11_deployment.md` now documents `make release-archive`, the direct
builder command, generated-archive hygiene validation, required A/D artifacts,
and excluded artifact classes.

## 7. CTF Invariants Checked

- The archive inventory requires checker files, all five sploits, all five
  fix patches, ForcAD config, Docker Compose config, Go source, migrations,
  tests, vendor dependencies, and review docs.
- Packaging does not alter checker PUT/GET, CHECK/HAVOC, public attack data,
  sploit behavior, fix patches, migrations, or vulnerability profiles.

## 8. Security Invariants Checked

- Archive hygiene rejects local caches, bytecode, IDE files, coverage output,
  nested temporary archives, unsafe archive paths, and archived foreign
  material.
- No secrets, local credentials, debug/admin shortcuts, direct DB shortcuts, or
  private reviewer artifacts were added.

## 9. Self-Review

The packaging flow writes outside the repository so the working tree hygiene
gate stays clean. The generated archive is validated separately by the same
hygiene script in archive-inspection mode. This task changed packaging,
validation, tests, and deployment docs only.

## 10. Risks / Open Questions

- Final release-candidate promotion remains a later Wave 30 review step.

## 11. Ready for Orchestrator Review

yes
