# Wave 33 Packaging Boundary

## Summary

W33-T01 defines the player/admin packaging boundary without building final
packages. The repository remains organizer-full and internal; player-facing
artifacts must be produced later from explicit allowlists and leak scans.

No product code, checker code, sploits, fixes, migrations, Docker runtime, or
Makefile behavior changed in this task.

## Files Updated

- `docs/player_admin_packaging_split_plan.md`
- `docs/wave_reports/wave_33_packaging_boundary.md`
- `docs/source_of_truth_map.md`
- `docs/13_roadmap.md`

## Boundary Decisions

| Artifact class | Audience | Decision |
| --- | --- | --- |
| Organizer-full internal package | organizers | May contain the full repository, including checker, sploits, fixes, tests, vulnerable profiles, scripts, docs, wave reports, and all stability evidence. It must not be shipped to players. |
| Player-service package | players/teams | Must be allowlist-built. Binary/image delivery is preferred. Source delivery is blocked until a sanitizing staging process removes vulnerability-map filenames, build tags, symbols, checker internals, tests, sploits, fixes, and wave evidence. |
| Admin/checker package | competition operators | May contain checker runner files, dependencies, minimal operator notes, ForcAD/Hackerdom registration material, and platform-required public locator schema. It must not contain sploits, fixes, vulnerable-profile source, wave reports, or checker-private examples. |
| Optional evidence package | organizers/reviewers | May contain validation reports, command evidence, package inventories, static leak scans, manifests, and checksums for internal review only. It is not player-facing. |

## Player Source Allowlist

Future player source packages may include only a sanitized staging tree:

- service runtime entrypoints under `cmd/aml-api/` and `cmd/aml-worker/`;
- required `internal/` service implementation after vulnerable-profile names,
  build tags, and obvious vulnerability symbols are removed or neutralized;
- `migrations/*.sql`;
- `go.mod`, `go.sum`, and `vendor/` when source builds are required;
- sanitized runtime config/deployment templates and a minimal player README.

Required exclusions include `checkers/`, `sploits/`, `exploits/`, `fixes/`,
`tests/`, organizer `scripts/`, wave reports, agent packets, decisions,
vulnerability matrix, checker design, flag-store internals, risk/roadmap/log
docs, `*_test.go`, Python tests, gate scripts, runtime smoke scripts, archive
builders, `aml[1-5]_vulnerable` names/build tags/symbols, exploit paths, fix
patches, checker-private state, credentials, raw flags, and organizer path
manifests.

## Player Binary/Image Allowlist

Future player binary/image packages may include compiled `aml-api` and
`aml-worker` binaries or an OCI image, migrations, sanitized runtime config,
sanitized deployment material, and minimal player operations notes.

They must exclude source, tests, scripts, checker package, sploits, fixes, wave
docs, evidence reports, vulnerability matrices, build tags, source filenames,
symbol names, checker credentials, checker-private state, sample flags,
reference exploit/fix names, and organizer-path manifests/checksums.

## Admin/Checker Boundary

The admin/checker package may include `checker.py`, `checker_lib.py`,
`requirements.txt`, minimal operator deployment notes, and platform registration
material. Public attack data must stay limited to gameplay locator fields.

The admin/checker package must exclude sploits, fixes, vulnerable-profile
source, vulnerability maps, wave reports, product test suites, checker-private
state examples, checker secrets, session tokens, raw/sample flags, private
owner credentials, direct DB helpers, and debug/admin helper notes.

## Tests Run

- `python -B scripts/check_docs_tree.py` - exit 0.

No code tests were required or run for W33-T01.

## CTF and Security Invariants

- Organizer-full retains two checker flag stores, five reference sploits, five
  reference fixes, CHECK/HAVOC, vulnerable-profile evidence, fixed-checker
  evidence, and exploit-blocking fix evidence.
- Player-facing artifacts must not disclose checker internals, checker
  credentials, flags, private checker state, reference exploit paths, fix
  patches, vulnerability maps, wave docs, or attack-info schemas beyond public
  gameplay locator needs.
- Future package builders must be allowlist-first and must produce
  package-specific inventories and static leak scans before promotion.

## Risks and Open Decisions

- Player source distribution remains blocked until a validated sanitizing
  staging process exists.
- The future packaging wave must decide whether player delivery is image-only,
  source-based, or mixed.
- Neutral naming for any source-distributed vulnerable behavior remains a later
  design decision.
- Secret injection for the admin/checker package remains a later operator
  packaging decision.

## Ready for Review

Yes, for packaging boundary and allowlist design only.
