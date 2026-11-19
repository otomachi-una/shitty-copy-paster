# Wave 33 Bundle Split

## Summary

W33-T04 adds candidate-tree generation for the player-service and
admin/checker package boundaries. The scripts stage inspectable directories
under ignored `tmp/` paths by default and do not build final archives, checksums,
release manifests, or promoted packages.

No service behavior, checker behavior, sploits, fixes, migrations, Docker
runtime, or organizer evidence was changed.

## Candidate Scripts

`scripts/build_player_bundle.py` builds `tmp/player-service-candidate` by
default. It uses an allowlist copier for player service source and runtime
inputs:

- generated player `README.md`;
- `go.mod` and `go.sum`;
- non-test Go source under `cmd/` and `internal/`;
- database migrations under `migrations/`;
- generated `config/player.env.example`;
- generated `deploy/compose.yaml`.

The player builder excludes organizer-only `checkers/`, `sploits/`, `fixes/`,
`tests/`, `scripts/`, `docs/`, Python caches, Go tests, local build outputs, and
archives. It also sanitizes the staged copy of legacy profile build-tag aliases
and internal marker field names that are useful in organizer source but should
not appear in player-facing source.

`scripts/build_admin_bundle.py` builds `tmp/admin-checker-candidate` by default.
It includes only:

- generated admin `README.md`;
- `config.yml`;
- `sentinel_aml/checker.py`;
- `sentinel_aml/checker_lib.py`;
- `sentinel_aml/requirements.txt`.

Both scripts reject the organizer repository root as an output path. Repo-local
outputs are allowed only under ignored `tmp/` or `temp/` directories.

## Make Targets

- `make player-candidate` stages the player-service candidate tree and hygiene
  allowlist sidecar.
- `make admin-candidate` stages the admin/checker candidate tree.
- `make bundle-candidates` stages both candidate trees.
- `make player-hygiene-gate` runs player bundle tests, generates or scans a
  player candidate, and runs `scripts/check_player_bundle_hygiene.py`.

These targets do not call `release-archive`, `scripts/build_release_archive.py`,
or final package/archive generation.

## Generated Inventory

Player candidate generated at `tmp/player-service-candidate`:

- 56 files total;
- `README.md`;
- `cmd/aml-api/main.go`;
- `cmd/aml-worker/main.go`;
- `config/player.env.example`;
- `deploy/compose.yaml`;
- `go.mod`;
- `go.sum`;
- 39 non-test Go files under `internal/`;
- 9 SQL migrations under `migrations/`.

Admin/checker candidate generated at `tmp/admin-checker-candidate`:

- `README.md`;
- `config.yml`;
- `sentinel_aml/checker.py`;
- `sentinel_aml/checker_lib.py`;
- `sentinel_aml/requirements.txt`.

The generated player hygiene sidecar is
`tmp/player-service-candidate.hygiene-allowlist.json`. It allows the Go standard
library command-line `flag` token only in `cmd/aml-api/main.go`.

## Inspection Workflow

Recommended review flow:

1. Generate candidates with `make bundle-candidates` or by running both builder
   scripts directly.
2. Inspect `tmp/player-service-candidate` and `tmp/admin-checker-candidate`.
3. Run `make player-hygiene-gate`, or run the scanner directly with the
   generated allowlist sidecar.
4. Run `make ad-stability-gate` in an environment with `make` available before
   promoting any later package wave.
5. Build final archives only in a later packaging task after candidate
   inventories and hygiene evidence are accepted.

## Failed and Allowed Examples

Expected failures:

- adding `checkers/sentinel_aml/checker.py` to the player candidate fails on the
  forbidden `checkers/` path and checker-private tokens;
- adding `sploits/`, `fixes/`, `tests/`, `scripts/`, or `docs/` to the player
  candidate fails as organizer-only material;
- adding filenames or content with `aml1`, `AML-1`, `vulnerable`,
  `attack_info`, `public_attack_data`, `LEAK_TARGET`, `MUST_NOT_LEAK`, or
  `checker_secret` fails closed.

Allowed examples:

- neutral service source under `cmd/` and `internal/`;
- migrations required by the service runtime;
- neutral customer/account/transaction/case/EDD/audit/graph/export/network-room
  business terminology;
- the Go standard library `flag` package in the API entrypoint, allowed by a
  narrow generated sidecar entry.

## Tests Run

- `python -B -m py_compile scripts\build_player_bundle.py scripts\build_admin_bundle.py scripts\check_player_bundle_hygiene.py` -
  exit 0.
- `python -B -m unittest discover -s tests -p "test_player_bundle_build.py"` -
  exit 0, 9 tests.
- `python -B -m unittest discover -s tests -p "test_player_bundle_hygiene.py"` -
  exit 0, 12 tests.
- `python -B -m unittest discover -s tests -p "test_player_bundle*.py"` -
  exit 0, 21 tests.
- `python -B scripts\build_player_bundle.py --output-dir tmp\player-service-candidate --allowlist-out tmp\player-service-candidate.hygiene-allowlist.json` -
  exit 0, 56 files.
- `python -B scripts\build_admin_bundle.py --output-dir tmp\admin-checker-candidate` -
  exit 0, 5 files.
- `python -B scripts\check_player_bundle_hygiene.py tmp\player-service-candidate --allowlist tmp\player-service-candidate.hygiene-allowlist.json` -
  exit 0; scanned 81 candidate members.
- `python -B scripts\check_docs_tree.py` - exit 0.
- `make bundle-candidates` could not run in this Windows shell because `make`
  is not installed. The Makefile targets were covered by unit tests and the
  underlying commands were run directly.

## CTF and Security Invariants

- Organizer-full evidence remains in the repository, including checker,
  sploits, fixes, tests, wave reports, vulnerable profile evidence, and
  stability gates.
- Player candidate generation excludes checker internals, sploits, fixes, tests,
  internal gate scripts, wave docs, and vulnerability-map labels.
- Admin/checker generation includes checker/operator inputs only and does not
  include reference sploits or fixes.
- No final release archive, player archive, checksum, or final manifest is
  generated by these scripts or targets.

## Risks

- The player source candidate is staged, not a final supported release package.
  Later packaging work must still compile/test the staged tree or choose
  binary/image distribution.
- The source sanitizer is intentionally narrow. Future source-distribution work
  should keep the hygiene scan as the authority and add reviewed transforms only
  when needed.
- Literal Make target execution remains unverified in this Windows environment
  until `make` is available.

## Ready for Review

Yes, for candidate tree generation and hygiene-gate integration.
