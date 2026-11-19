# Sentinel AML Player/Admin Packaging Split Plan

This plan defines the package boundary for future Wave 34+ package-construction
work. It does not build packages and does not change product code, checker code,
sploits, fixes, migrations, Docker runtime, or Makefile behavior.

The organizer repository remains the complete internal source of truth for
service validation. Player-facing artifacts must be derived from it through an
explicit allowlist and must not disclose the vulnerability map, checker
internals, reference sploits, reference fixes, or wave evidence.

## Artifact Classes

| Artifact class | Audience | Purpose | Status in W33-T01 |
| --- | --- | --- | --- |
| Organizer-full internal package | organizers only | Full repository, validation evidence, checker, sploits, fixes, vulnerable profiles, docs, reports, gates, and future release machinery | Boundary defined; may retain all evidence |
| Player-service package | players/teams | Deployable Sentinel AML service and only the gameplay/runtime material required to run it | Boundary defined; not built |
| Admin/checker package | ForcAD/Hackerdom operators and checker runners | Checker and service registration material needed by the competition platform | Boundary defined; not built |
| Optional evidence package | organizers/reviewers only | Stability, packaging, and audit evidence for acceptance review | Boundary defined; not player-facing |

## Organizer-Full Internal Package

Organizer-full is the only class allowed to contain the complete repository
shape.

Allowed contents:

- `cmd/`, `internal/`, `migrations/`, `vendor/`, `go.mod`, `go.sum`;
- `checkers/`, `sploits/`, `exploits/`, `fixes/`, `tests/`, `scripts/`;
- `docs/`, including `docs/wave_reports/`, `docs/agent_packets/`,
  `docs/decisions/`, and archived review material;
- `Makefile`, `config.yml`, `docker-compose.yml`, README files, and future
  release scripts;
- all vulnerable-profile files, build tags, test fixtures, checker scenario
  inventories, sploit/fix matrices, and anti-coarse-fix evidence.

Forbidden handling:

- do not provide organizer-full directly to players;
- do not treat organizer-full as a player-service source package;
- do not remove checker, sploit, fix, vulnerable-profile, CHECK/HAVOC, or
  exploit-blocking evidence from organizer-full to make player packaging easier.

## Player-Service Package

The player-service package contains only what a team needs to run the challenge
service. It must not teach the intended vulnerability map.

### Player Source Distribution Allowlist

Player source distribution is releasable only after a future sanitizing staging
step produces a source tree with neutral names and no validation evidence. The
allowlist for that staged tree is:

- `cmd/aml-api/` and `cmd/aml-worker/` runtime entrypoints;
- `internal/` service implementation required by the selected competition
  service behavior after vulnerability-profile names, build tags, and obvious
  vulnerability symbols have been removed or neutralized;
- `migrations/*.sql`;
- `go.mod`, `go.sum`, and `vendor/` when offline source builds are required;
- prebuilt static frontend runtime files under `web/dist/`, with no source maps,
  npm metadata, TypeScript source, frontend tests, or build-time configuration;
- player runtime configuration templates with no checker credentials, flags,
  private checker state, exploit paths, or organizer-only comments;
- player deployment files produced for the service package, such as a sanitized
  `Dockerfile`, sanitized compose file, and minimal player README.

Required source exclusions:

- `frontend/src/`, `frontend/public/`, `frontend/package*.json`,
  `frontend/vite.config.*`, `frontend/tsconfig*.json`, frontend tests,
  frontend coverage, `frontend/node_modules/`, and source maps;
- `checkers/`, `sploits/`, `exploits/`, `fixes/`, `tests/`, and organizer
  `scripts/`;
- `docs/wave_reports/`, `docs/agent_packets/`, `docs/decisions/`, and archived
  review material;
- vulnerability matrix, checker design, flag-store internals, testing strategy,
  risk register, execution log, source-of-truth map, roadmap, and split-plan
  docs unless rewritten into a minimal player README;
- `*_test.go`, Python test files, fixtures, validation logs, gate scripts,
  archive builders, runtime smoke scripts, and local cache artifacts;
- files or symbols exposing planned vulnerability identifiers, including
  `aml1_vulnerable`, `aml2_vulnerable`, `aml3_vulnerable`, `aml4_vulnerable`,
  `aml5_vulnerable`, `*_aml*_vulnerable.go`,
  `*_aml*_vulnerable_test.go`, and matching build tags;
- reference fix patch names and contents, exploit script names and contents,
  checker scenario inventory, public/private checker-state schema notes, and
  anti-coarse-fix controls;
- generated manifests or checksums that reference organizer-only paths.

Until the sanitizing staging step exists and is validated, player source
distribution is blocked. Binary/image distribution is the preferred player
delivery mode.

Wave 33 source candidates were staging outputs only. Wave 34 proved a source
delivery candidate path for review evidence. The final player transfer model is
backend source plus built static frontend: the player archive must not expose
CTF labels, source-level policy names, checker internals, sploits, fixes,
tests, wave docs, or frontend source/build inputs.

If source delivery is explicitly selected later, the runtime-profile guard must
prove the flattened source contains only the chosen competition behavior, no
dual default/detail policy source pairs, runtime evidence, and a build command
that cannot silently compile the secure/default baseline.

### Player Binary/Image Distribution Allowlist

Player binary/image distribution may contain:

- compiled `aml-api` and `aml-worker` binaries or an OCI image containing those
  binaries;
- migrations required at service startup;
- runtime configuration templates containing only player-visible service
  settings;
- sanitized compose/Kubernetes/systemd material needed to run PostgreSQL and the
  service;
- a minimal player README with service startup commands, ports, health endpoints,
  and gameplay-neutral operational notes.

Required binary/image exclusions:

- Go/Python source, tests, validation scripts, checker package, sploits, fixes,
  wave docs, evidence reports, vulnerability matrices, build tags, source
  filenames, and symbol names;
- checker credentials, checker private state, sample flags, attack-info schemas
  beyond platform-required public locator fields, reference exploit paths, fix
  patches, and organizer logs;
- package manifests or checksums that disclose organizer-only file paths or
  excluded artifact names.

## Admin/Checker Package

The admin/checker package is for competition operators and checker runners, not
players.

Allowed contents:

- `checkers/sentinel_aml/checker.py`;
- `checkers/sentinel_aml/checker_lib.py`;
- `checkers/sentinel_aml/requirements.txt`;
- minimal checker README and deployment notes for operators;
- ForcAD/Hackerdom service registration material, including the public service
  name, place count, and checker invocation contract;
- public attack-data format required by the platform, limited to locator data
  needed for gameplay.

Required exclusions:

- reference sploits and fixes;
- vulnerable-profile source files, build tags, and vulnerability names;
- product test suites, wave reports, validation matrices, and risk ledgers;
- checker-private state examples, checker secrets, session tokens, passwords,
  raw flags, sample flags, and private owner credentials;
- direct database helpers, debug/admin helper notes, or any path that teaches
  checker GET internals beyond normal public platform operation.

## Optional Evidence Package

The optional evidence package is internal review material. It may be shared with
organizers or orchestrator reviewers, but never with players.

Allowed contents:

- selected validation reports from `docs/wave_reports/`;
- gate outputs and command records for `ad-stability-gate`, runtime smoke,
  docs-tree validation, checker validation, sploit/fix matrix validation, and
  future packaging hygiene;
- package inventories, manifests, and checksums for internal review;
- static scan results proving player/admin package exclusions.

Required exclusions:

- live flags, checker secrets, session tokens, private checker state, production
  credentials, and unredacted environment files;
- any evidence bundle intended for players.

Evidence package contents may describe vulnerabilities, sploits, and fixes only
when the package is marked organizer/reviewer internal.

## Boundary Rules

- The organizer repository must retain two checker flag stores, five reference
  sploits, five reference fixes, CHECK/HAVOC coverage, vulnerable-profile
  evidence, fixed-checker evidence, and exploit-blocking fix evidence.
- Player-facing artifacts must not contain checker internals, checker
  credentials, raw flags, checker-private state, reference sploits, reference
  fixes, vulnerability matrices, wave reports, or obvious vulnerable-profile
  filenames/build tags/symbols.
- Admin/checker artifacts must contain only checker execution material and
  platform-required public locator schemas; they must not include reference
  exploit/fix material or vulnerability maps.
- Binary/image player delivery is preferred because it can hide source-level
  vulnerability map names. Source delivery remains blocked until a validated
  sanitizing staging process exists.
- Source candidate staging must rewrite organizer-internal variant vocabulary
  into product-neutral runtime policy names. Generated player source must not
  expose the legacy vulnerability labels or internal build-profile helper/file
  names that mapped directly to review evidence.
- Future package builders must be allowlist-first. Exclusions are guardrails,
  not the primary selection mechanism.
- Every future package must have a package-specific inventory and static leak
  scan before promotion.
- Review submission archives are distinct from local generated candidate
  directories. Submitted repository snapshots must exclude `tmp/*candidate*`,
  candidate allowlist sidecars, `__pycache__/`, `.pyc`, `.gocache*`, and
  `.appdata*` artifacts unless an evidence package intentionally documents the
  generated output outside the repository-submission class.

## Open Decisions for Later Waves

- Whether player delivery will be binary/image only or include sanitized source.
- Whether the runtime-proven W34 source candidate should be shipped as source
  or wrapped into a later archive/image release format.
- The final player deployment format: tarball, OCI image, compose project,
  Kubernetes manifests, or a combination.
- The exact operator secret injection mechanism for the admin/checker package.
- Whether optional evidence packages are produced per review wave or only at
  final release review.
