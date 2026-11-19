# W33-AF3 Repository Submission Hygiene

## Summary

W33-AF3 strengthens repository-submission hygiene so the submitted zip/tar is
checked as archive bytes. This gate is separate from player artifact hygiene:
the internal repository submission may retain organizer evidence, but it must
not include generated local output or caches.

FH-04 adds an explicit allowlist-built handoff archive command:

```sh
python -B scripts/build_repository_submission.py --output out/repository-submission/sentinel-aml-repository-submission.zip .
python -B scripts/check_repository_submission_hygiene.py out/repository-submission/sentinel-aml-repository-submission.zip
```

The builder includes only reviewed top-level project files and source/evidence
directories, then validates the exact zip bytes it produced. Local generated
workspace files can exist during packaging work, but they are not copied into
the repository-submission archive and are not treated as transfer-artifact
readiness evidence.

## Scanner Rules

`scripts/check_repository_submission_hygiene.py` accepts an extracted tree, zip,
or tar archive. For archives, it strips one common wrapper directory before
scanning member paths.

The scanner rejects:

- `frontend/node_modules/`;
- `frontend/dist/`;
- `tmp/`, `temp/`, and `out/`;
- `__pycache__/`, `.pyc`, `.pyo`;
- `.tsbuildinfo`;
- `.gocache*`, `.appdata*`, `.gotelemetry*`;
- browser/profile output such as `.playwright/`, `edge-profile/`,
  `chrome-profile/`, `chromium-profile/`, and `browser-profile/`;
- screenshots, traces, Playwright reports, blob reports, and test-results;
- `validation/` local review output;
- nested generated transfer archives unless `--allow-nested-archives` is used
  for a documented non-submission scan.

The scanner does not reject organizer-only source-of-truth materials such as
checker code, sploits, fixes, tests, wave reports, gates, or internal docs.

## Cleanup Behavior

`make clean-generated` runs:

```sh
python -B scripts/check_repository_submission_hygiene.py --clean-generated .
```

The cleanup helper removes only known generated output locations under the
workspace: `tmp/`, `temp/`, `out/`, frontend install/build/test outputs,
frontend `.tsbuildinfo`, and local Go/appdata/Python cache roots. It does not
remove product, checker, sploit, fix, docs, tests, or gate source files.

## Tests Added

Synthetic archive coverage proves failures for:

- Python bytecode and `__pycache__/`;
- Go/appdata caches;
- generated `tmp/*candidate*` paths;
- `frontend/node_modules/` and `frontend/dist/`;
- `.tsbuildinfo`, browser profiles, Playwright reports, and test-results;
- nested transfer archives;
- local cleanup removing generated outputs while preserving source evidence.

## Current Workspace Scan

The strict real-current-workspace command is:

```sh
python -B scripts/check_repository_submission_hygiene.py .
```

It is expected to fail before cleanup when local generated outputs are present.
A submitted archive must be created after cleanup and then scanned by archive
path.

## Ready for Review

Ready for scanner review. Submitted archive promotion is blocked until the
archive itself passes this gate.
