# Sentinel AML — Testing Strategy

Current validation covers skeleton integrity, auth persistence,
customer/account/transaction APIs, owner investigation workflows, owner-scoped
EDD APIs, projection allowlist contracts, secure side views, planned vulnerable
profiles, five accepted reference exploits, five reference-fix evidence rows,
final ForcAD/matrix validation, and release archive hygiene while preserving
checker PUT/GET behavior for both active checker places.

## Current Test Surfaces

- Go package tests with `go test ./...`.
- Go static checks with `go vet ./...`.
- ForcAD config validation with `scripts/validate_forcad_config.py`.
- Documentation tree validation with `scripts/check_docs_tree.py`.
- Wave 01/02 scope validation with `scripts/check_wave01_scope.py`.
- Wave 02 integration gate validation with `scripts/check_wave02_gate.py`.
- Wave 03 integration gate validation with `scripts/check_wave03_gate.py`.
- Wave 04 integration gate validation with `scripts/check_wave04_gate.py`.
- Wave 05 integration gate validation with `scripts/check_wave05_gate.py`.
- Wave 06 visibility/projection gate validation with `scripts/check_wave06_gate.py`.
- Wave 07 secure dedup gate validation with `scripts/check_wave07_gate.py`.
- Wave 08 secure audit gate validation with `scripts/check_wave08_gate.py`.
- Wave 09 secure graph gate validation with `scripts/check_wave09_gate.py`.
- Wave 10 secure export/network-room gate validation with `scripts/check_wave10_gate.py`.
- Wave 11 checker no-bypass gate validation with `scripts/check_wave11_gate.py`.
- Wave 12 multi-place checker gate validation with `scripts/check_wave12_gate.py`.
- Wave 13 CHECK/HAVOC framework validation with `scripts/check_wave13_gate.py`.
- Wave 17 AML-4 export-redaction profile validation with `scripts/check_wave17_gate.py`.
- Wave 18 AML-5 network-room profile validation with `scripts/check_wave18_gate.py`.
- Wave 19 AML-1 reference exploit validation with `scripts/check_wave19_gate.py`.
- Wave 20 AML-2 reference exploit validation with `scripts/check_wave20_gate.py`.
- Wave 21 AML-3 reference exploit validation with `scripts/check_wave21_gate.py`.
- Wave 22 AML-4 reference exploit validation with `scripts/check_wave22_gate.py`.
- Wave 23 AML-5 reference exploit validation with `scripts/check_wave23_gate.py`.
- Wave 24 AML-1 reference fix validation with `scripts/check_wave24_gate.py`.
- Wave 25 AML-2 reference fix validation with `scripts/check_wave25_gate.py`.
- Wave 26 AML-3 reference fix validation with `scripts/check_wave26_gate.py`.
- Wave 27 AML-4 reference fix validation with `scripts/check_wave27_gate.py`.
- Archive hygiene validation with `scripts/check_archive_hygiene.py`.
- Projection allowlist contract tests under `internal/projection/` and repository-level projection visibility tests under `tests/`.
- Secure graph HTTP visibility tests under `internal/httpapi/`.
- Deterministic network-room lifecycle tests under `internal/networkroom/`,
  `cmd/aml-worker/`, runtime smoke, and the opt-in live PostgreSQL Wave 34
  network-room lifecycle hook.
- Live black-box competition matrix validation with
  `scripts/check_live_competition_matrix.py`, covering checker PUT, real
  reference sploit execution, checker GET, reference-fix isolated copies,
  exploit blocking, and CHECK/HAVOC against the Go API, PostgreSQL, and worker.
- Focused clean-deploy CHECK/HAVOC validation with
  `scripts/check_live_checker_clean_deploy.py`, covering the full default
  checker subcheck set against a fresh PostgreSQL/API/worker runtime.
- Go toolchain drift validation with `make toolchain-gate`.
- Offline vendored dependency validation through `GOFLAGS=-mod=vendor` and `scripts/check_wave03_gate.py`.
- Migration SQL validation under `tests/`.
- Wave 02 HTTP surface gate tests under `tests/`.
- Auth repository unit tests under `internal/auth/`.
- Auth service unit tests under `internal/auth/`.
- Auth HTTP route tests under `internal/httpapi/`.
- Opt-in live PostgreSQL migration/auth integration test under `internal/httpapi/`.
- Migration loader tests under `internal/db/`.
- Customer repository tests under `internal/customer/`.
- Account repository tests under `internal/account/`.
- Transaction repository tests under `internal/transaction/`.
- Alert repository tests under `internal/alert/`.
- Case and case-note repository tests under `internal/casework/`.
- EDD repository tests under `internal/edd/`.
- EDD owner API tests under `internal/httpapi/`.
- Deterministic risk scoring and alert generation tests under `internal/risk/`.
- Wave 03 owner API handler tests under `internal/httpapi/`.
- Opt-in live PostgreSQL Wave 03 domain repository integration test under `tests/`.
- Opt-in live PostgreSQL Wave 04 investigation repository integration test under `tests/`.
- Opt-in live PostgreSQL Wave 04 risk/alert generation integration test under `tests/`.
- Opt-in live PostgreSQL Wave 04 owner investigation API integration test under `internal/httpapi/`.
- Opt-in live PostgreSQL Wave 03 owner API integration test under `internal/httpapi/`.
- Opt-in live PostgreSQL Wave 34 network-room lifecycle integration test under
  `internal/httpapi/`.
- Opt-in live black-box competition matrix under `tests/`, enabled with
  `SENTINEL_AML_RUN_LIVE_MATRIX=1`.
- Opt-in live clean-deploy checker proof under `tests/`, enabled with
  `SENTINEL_AML_RUN_LIVE_CHECKER=1`.
- Frontend UI typecheck, unit/component tests, source security scan,
  production build, dist security scan, and Playwright browser smoke tests
  under `frontend/`.

## Frontend UI Validation

The current UI clean gate runs from `frontend/`:

```sh
npm ci
npx playwright install chromium
npm run typecheck
npm test
npm run security:scan
npm run build
npm run security:scan:dist
npx playwright test
```

Vitest covers API boundary, allowlisted adapters, session routing, rendered
product copy, UI primitives, and page-level states. Playwright starts a local
Vite server on `127.0.0.1:5174` and covers the supported alert-to-case browser
flow, two-analyst session isolation, unauthorized/forbidden/not-found/session
expiry states, loading/empty/error states, keyboard focus, core form usability,
and desktop/mobile horizontal overflow checks.

The frontend security scanner has separate source and production-output modes.
The dist scan checks generated JS/CSS/HTML and rejects production source map
artifacts. Frontend tests do not authorize backend source changes.

Participant-facing UI distribution is not the frontend source package. The
canonical player transfer artifact is one player-service artifact containing
both backend runtime binaries and the web interface as production runtime files
under `ui/`, copied from `frontend/dist` after a clean frontend build.
`frontend/dist` is the documented UI input path for artifact packaging; it must
come from `npm --prefix frontend run build` after dependency installation, and
the artifact gates run the frontend source and dist scanners before packaging
those bytes.
The generated candidate does not include `frontend/tests`, `frontend/e2e`,
frontend scanner scripts, Playwright configuration, source maps, or development
README material. `ui/runtime-config.js` remains a replaceable runtime file and
must not contain credentials.

Run the focused participant UI artifact checks:

```sh
npm --prefix frontend run security:scan:source
npm --prefix frontend run build
npm --prefix frontend run security:scan:dist
python -B scripts/build_player_bundle.py --output-dir tmp/ui-dist-player-candidate --allowlist-out tmp/ui-dist-player-candidate.hygiene-allowlist.json
python -B scripts/check_player_bundle_hygiene.py tmp/ui-dist-player-candidate --allowlist tmp/ui-dist-player-candidate.hygiene-allowlist.json
```

## Wave 02 Coverage

Current tests verify:

- migration files exist and are ordered;
- initial SQL defines required users and sessions fields;
- migration SQL stores `token_hash`, not raw tokens;
- migration SQL does not introduce artificial flag fields or out-of-scope AML domain tables;
- repository duplicate username handling maps PostgreSQL unique violations;
- session creation accepts token hashes only;
- canceled contexts stop repository and migration operations before DB work;
- role and status validation matches the Wave 02 contract.
- registration creates an `analyst` user and returns a one-time raw session token;
- duplicate registration is rejected;
- login succeeds with the correct password and rejects the wrong password;
- `/api/auth/me` rejects unauthenticated calls;
- `/api/auth/me` returns the current user for a valid bearer session;
- auth responses exclude password hashes, stored token hashes, internal row dumps, and checker-private markers;
- debug/admin route probes return 404.
- Wave 02 gate validation confirms migrations are present and ordered;
- Wave 02 gate validation confirms only `users` and `sessions` tables are introduced;
- Wave 02 gate validation confirms only health and auth routes are registered;
- Wave 02 gate validation confirms ForcAD config and canonical docs still pass;
- Wave 02 gate validation confirms no exploit scripts exist in the Wave 02 tree.
- live PostgreSQL integration applies migrations to a clean database, then exercises register, login, and authenticated/unauthenticated current-user flows through the real repository/service/HTTP stack;
- toolchain gate validation confirms `go.mod` remains pinned to `go 1.22.0` and test/vet run with `GOTOOLCHAIN=local`.
- vendor validation confirms `github.com/jackc/pgx/v5`, `golang.org/x/crypto`, and transitive Go modules are available under `vendor/`.

## Wave 03 Coverage

Current Wave 03 tests verify:

- migrations exist in order as `000001_create_users_sessions.sql` followed by `000002_create_customers_accounts_transactions.sql`;
- the Wave 03 migration defines `customers`, `accounts`, and `transactions` with required fields, owner/customer/account relationships, constraints, and indexes;
- Wave 03 migrations do not introduce alerts, cases, notes, EDD records, graph/export/network tables, reserved checker-private fields, or dedup placement;
- customer repository create/get/list paths preserve owner scope;
- account repository create/get/list paths preserve owner scope through the customer relationship;
- transaction repository create/get/list paths preserve owner scope through the account and customer relationships;
- duplicate customer registration numbers, duplicate account `iban_like` values, and duplicate transaction `trace_id` values map to explicit domain errors;
- required-field validation rejects incomplete records;
- canceled contexts stop repository operations before database work;
- optional live PostgreSQL integration applies all migrations to a clean database and exercises real auth, customer, account, and transaction repositories together.

## Wave 03 API Coverage

Current Wave 03 API tests verify:

- all product endpoints reject unauthenticated requests;
- authenticated analysts can create and read their own customers;
- duplicate owner-scoped customer, account, and transaction natural keys return stable `409` JSON responses;
- accounts can be created and listed only under an owned customer;
- direct account reads fail closed for other owners;
- transactions can be created only under an owned account;
- transaction create rejects client-supplied `risk_score` and reads back the server-owned default `0`;
- malformed, zero, negative, and excessive-scale transaction amounts fail with stable `invalid_request` JSON errors before database insert;
- direct transaction reads and customer transaction lists fail closed for other owners;
- malformed path IDs fail with stable `invalid_path` JSON errors;
- response DTOs omit owner IDs, auth hashes, stored token hashes, raw DB rows, and checker-private markers;
- profile, risk, alert, case, EDD, graph, export, network-room, public side-view, and checker-only endpoints remain absent;
- the opt-in live PostgreSQL owner API gate exercises register, customer create/read, account create/read/list, transaction create/read/list, and cross-owner denial through the real repository/service/HTTP stack.

## Wave 03 Gate

`scripts/check_wave03_gate.py` validates the current branch state:

- exact Wave 03 migration ordering and table set;
- required customer/account/transaction relationships and indexes;
- exact Wave 03 route registration and auth wrapping;
- absent alert, case, EDD, graph, export, network-room, public side-view, checker-only, debug, and admin routes;
- explicit DTOs without owner/auth/session/checker-private internal fields;
- repository owner-scope markers and context-aware boundaries;
- no exploit scripts;
- live PostgreSQL owner API gate presence;
- docs tree, ForcAD config, Wave 01 scope, and retained Wave 02 security/auth invariants.
- source-controlled vendored Go dependency presence and Makefile vendor-mode policy.
- transaction input contract hardening is covered by package tests: `risk_score` remains read-only and amount validation is shared through the transaction boundary.

Run:

```sh
python -B scripts/check_wave03_gate.py
make wave03-gate
```

## Offline Dependency Policy

Go dependencies are vendored in source control. Canonical clean/offline commands are:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_wave03_gate.py
python -B scripts/check_wave06_gate.py
python -B scripts/check_wave08_gate.py
```

For stronger local proof, run those Go commands with `GOPROXY=off` and a fresh `GOMODCACHE`. The Wave 03 gate checks `vendor/modules.txt`, required vendored module directories, absence of a `toolchain` directive, and Makefile vendor-mode policy.

## Wave 02 Gate Commands

Run:

```sh
go test ./...
go vet ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python3 -B scripts/check_docs_tree.py
python3 -B scripts/check_wave01_scope.py
python3 -B -m unittest discover -s tests -p "test_*.py"
python -B scripts/check_wave02_gate.py
make toolchain-gate
```

On the current Windows host, `python3` resolves to the Windows launcher stub and only prints `Python`. Use `python` as the local fallback when recording validation results. The same host may also require `GOCACHE` to point at a writable temporary directory for local Go commands because the default Windows Go build cache can return access denied errors.

## Archive Hygiene Gate

Review and competition bundles must exclude local environment artifacts. The
archive hygiene gate fails if the repository snapshot includes Go caches,
application-data scratch directories, telemetry caches, IDE configuration,
Python bytecode caches, local coverage output, temporary archives, or OS
metadata files. Cache directory checks cover wildcard variants such as
`.gocache-p1/` and `.appdata-p1/`, not only the base `.gocache/` and
`.appdata/` names.

Run:

```sh
python -B -m unittest discover -s tests -p "test_archive_hygiene.py"
python -B scripts/check_archive_hygiene.py
```

The unit tests cover clean snapshots, root-level cache/IDE directories, nested
`__pycache__/` directories, wildcard `.gocache*`/`.appdata*` directories,
local coverage files, temporary archive files, the actual repository tree, and
ignored `.git/` internals. The script must remain packaging-only: it must not
modify source files, checker behavior, vulnerability profiles, sploit
placeholders, fix placeholders, or ForcAD `config.yml`.

## Repository Submission Archive Hygiene

Submitted repository zips are checked separately from player/admin transfer
artifacts. The repository submission is allowed to contain organizer-only
materials such as checker code, sploits, fixes, tests, wave reports, gates, and
internal documentation. It must not contain local generated output or cache
state.

The byte-level submission scanner accepts a zip or tar archive path and strips
one common wrapper directory, such as `Sentinel_AML/`, before applying rules:

```sh
python -B scripts/check_repository_submission_hygiene.py submitted-repo.zip
```

It rejects `frontend/node_modules/`, `frontend/dist/`, `tmp/`, `temp/`,
`out/`, `__pycache__/`, `.pyc`, `.tsbuildinfo`, Go/appdata/telemetry caches,
browser profiles, screenshots, traces, Playwright/Vitest test output, and
nested generated transfer archives unless an explicit non-submission scan uses
`--allow-nested-archives`.

For a live local workspace, use the cleanup helper before building a submission
archive:

```sh
make clean-generated
python -B scripts/check_repository_submission_hygiene.py path/to/submitted-repo.zip
```

`make clean-generated` removes only known generated output locations under the
workspace, including `tmp/`, `temp/`, `out/`, frontend build/install/test
outputs, TypeScript build info, and local Go/appdata/Python cache roots. It
does not remove checker, sploit, fix, docs, tests, or product source evidence.

AF-F05 adds a deterministic repository-submission archive builder for the
internal review snapshot:

```sh
make repository-submission-archive
python -B scripts/check_repository_submission_hygiene.py out/repository-submission/sentinel-aml-repository-submission.zip
```

The produced zip excludes `out/`, generated transfer archives, frontend
`dist/`, `node_modules/`, TypeScript build info, bytecode, caches, test reports,
browser profiles, screenshots/traces, and local QA folders. Transfer artifacts
remain separate under `out/artifacts/`; when `out/checksums/SHA256SUMS` exists,
the repository-submission zip contains only
`REPOSITORY_SUBMISSION_ARTIFACTS.json` checksum references to those transfer
artifacts, not the tarballs themselves. Player/admin artifact hygiene must
still be run separately against the exact transfer artifact bytes.

## Live Black-Box Competition Matrix

Wave 34 adds a live acceptance gate for the complete A/D chain. The fast
preflight is:

```sh
python -B scripts/check_live_competition_matrix.py
python -B -m unittest discover -s tests -p "test_live_competition_matrix.py"
```

The full live matrix is opt-in because it starts Docker PostgreSQL services,
the Go API, and the Go worker, then creates isolated fixed-profile repository
copies for the five reference patches:

```sh
python -B scripts/check_live_competition_matrix.py --run --python python --go go --docker docker --json-output tmp/live-competition-matrix.json
```

Prerequisites:

- Docker Compose can start `postgres` from `docker-compose.yml`;
- local Go can run with vendored dependencies;
- local Python can invoke checker and sploit scripts;
- host ports can be allocated dynamically for API and PostgreSQL.

For AML-1 through AML-5 the live gate performs:

- checker `put` through normal service APIs;
- real reference sploit execution with public attack data only;
- checker `get`;
- checker `check` and `havoc`;
- reference fix patch application in an isolated copy;
- fixed-profile service start;
- sploit blocked while checker `get`, `check`, and `havoc` stay green.

The gate must not use direct DB reads for checker or exploit success, debug or
admin routes, fake HTTP services, or hand-written replacement exploit snippets.
AML-5 requires the real worker lifecycle to materialize network rooms. The
script emits machine-readable JSON containing per-AML vulnerable/fixed rows and
also prints the same evidence for human review.

## Wave 34 Clean-Deploy CHECK/HAVOC Proof

W34-T05 adds a focused clean-deploy checker proof:

```powershell
python -B scripts\check_live_checker_clean_deploy.py --run --python python --go go --docker docker --json-output tmp\live-checker-clean-deploy.json
```

Static mode validates that the default CHECK/HAVOC registry contains `health`,
`check_basic`, `check_case_notes`, `check_edd`, `check_dedup`, `check_audit`,
`check_graph`, `check_export`, `check_network_room`, and `check_retention`.
Live mode starts a clean PostgreSQL/API/worker runtime with the canonical
competition tags, runs checker `check`, runs checker `havoc`, and records
Hackerdom-compatible exit classifications. W34-T05 local target evidence:
exit `0`, elapsed `18.094s`, `check` exit `101` (`OK`), and `havoc` exit
`101` (`OK`).

The network-room subcheck is intentionally worker-aware but bounded. It creates
deterministic same-entity case inputs through normal APIs, polls
`GET /api/network/rooms` for the materialized participant-visible room, then
reads `GET /api/network/rooms/{room_id}/dossier`. Missing rooms, malformed
summaries, malformed dossiers, or broad private-field leaks fail MUMBLE; route
or service unavailability remains DOWN/MUMBLE according to the normal checker
error mapping. The proof does not read PostgreSQL directly, seed magic rooms,
or call debug/admin paths.

After Wave 03, `scripts/check_wave02_gate.py` remains a historical Wave 02 closure gate and still expects only the Wave 02 auth migration. Run it when validating a Wave 02 branch. Wave 03 schema validation is covered by Go migration tests and the Wave 03 live integration gate.

After Wave 04, `scripts/check_wave03_gate.py` remains a historical Wave 03 closure gate and still expects alerts/cases/notes to be absent. Run it when validating a Wave 03 branch. Wave 04 schema and persistence validation is covered by Go migration tests plus `internal/alert` and `internal/casework` repository tests until a dedicated Wave 04 gate is added.

After Wave 05, `scripts/check_wave04_gate.py` remains a historical Wave 04 closure gate and still expects EDD records/routes to be absent. Run it when validating a Wave 04 branch. Use `scripts/check_wave05_gate.py` for the current branch.

## Wave 04 Persistence Coverage

Current Wave 04 tests verify:

- migrations exist in order as `000001_create_users_sessions.sql`, `000002_create_customers_accounts_transactions.sql`, and `000003_create_alerts_cases_notes.sql`;
- the Wave 04 migration defines `alerts`, `cases`, and `case_notes` with required fields, owner-aware relationships, constraints, and indexes;
- Wave 04 migrations do not introduce EDD records, graph/export/network tables, reserved checker-private fields, public attack data, or dedup placement;
- alert repository create/get/list paths preserve owner scope through transactions, accounts, and customers;
- alert claim and triage paths preserve owner scope and reject invalid transitions;
- case repository create-from-alert, get/list, and status update paths preserve owner scope;
- case status updates reject invalid transitions;
- case note create/list paths preserve owner scope through cases;
- private note bodies are covered only by owner-authorized repository methods;
- repository methods honor canceled contexts before database work;
- duplicate alert and case creation errors map to explicit domain errors without leaking SQL internals.

## Wave 04 Risk/Alert Coverage

Current Wave 04 risk tests verify:

- same scoring input returns the same score, typology, and rule output;
- amount bucket boundaries are deterministic at `1000.00`, `10000.00`, and `50000.00`;
- country and counterparty fingerprint inputs affect the score predictably;
- low-risk transactions update server-owned `risk_score` without creating alerts;
- suspicious transactions create owner-scoped alerts with deterministic `rule_code`, `risk_score`, and `typology_hint`;
- repeated scoring of the same suspicious transaction is idempotent and does not create duplicate alert records;
- cross-owner scoring fails closed before alert creation;
- transaction create through the configured HTTP server can invoke the synchronous risk service and produce deterministic owner-scoped alerts;
- migrations still do not add future worker queue tables, EDD, graph, export, network-room, public attack data, checker storage, or planned vulnerability fields.

## Wave 04 Investigation API Coverage

Current Wave 04 API tests verify:

- all alert, case, and note endpoints reject unauthenticated requests;
- alert queue returns only alerts linked to the authenticated owner's customers;
- alert get, claim, and triage preserve owner scope;
- invalid alert transitions return stable `invalid_transition` JSON conflicts;
- cases can be created from owned alerts and read only by the owner;
- case status updates preserve owner scope and reject invalid transitions;
- private notes can be created and listed only through owner-authorized case paths;
- cross-owner alert, case, and note requests fail closed without leaking private note bodies;
- malformed alert/case IDs and invalid request bodies return stable JSON errors;
- checker, public attack-data, audit, EDD, graph, export, and network-room routes remain absent;
- the opt-in live PostgreSQL owner investigation API gate exercises customer, account, suspicious transaction, alert queue, claim, triage, case creation, private note creation/listing, status update, and cross-owner denial through the real repository/service/HTTP stack.

## Wave 04 Gate

`scripts/check_wave04_gate.py` validates the current branch state:

- exact Wave 04 migration ordering and table set;
- required alert, case, case-note, deterministic risk, and owner-scope repository markers;
- previous auth/customer/account/transaction routes plus Wave 04 investigation routes;
- auth wrapping for all product and investigation routes;
- absent checker, public attack-data, EDD, graph, export, network-room, debug, admin, and planned vulnerability routes;
- explicit DTOs without owner/auth/session/checker-private internal fields;
- `CaseNote.body` appears only in the private note create request and owner note response, not alert queue or case shell projections;
- non-owner and absent side-view note-body regression tests exist;
- live Wave 04 risk and investigation API gate hooks exist;
- Wave 04 handoffs and validation summary exist;
- docs tree, ForcAD config, Wave 01 scope, and retained Wave 03 invariants are clean for the expanded branch.

Run:

```sh
python -B scripts/check_wave04_gate.py
make wave04-gate
```

## Wave 05 EDD Persistence Coverage

Current Wave 05 tests verify:

- migrations exist in order through `000004_create_edd_records.sql`;
- the Wave 05 migration defines `edd_records` with `customer_id`, `analyst_user_id`, `source_of_funds`, `risk_rationale`, `confidential_comment`, `review_status`, timestamps, one-current-record uniqueness, status constraints, and required indexes;
- Wave 05 migrations do not introduce graph/export/network tables, worker queues, reserved checker-private fields, public attack data, or dedup placement;
- EDD repository create paths preserve owner scope through `customers.owner_user_id`;
- EDD repository get/update paths fail closed for cross-owner access;
- duplicate current EDD records map to explicit domain errors without leaking SQL details;
- invalid review statuses, cross-analyst writes, and missing confidential comments are rejected before database work;
- canceled contexts stop repository operations before database work;
- `confidential_comment` is persisted only in owner-scoped repository behavior and exposed only through the owner EDD HTTP DTO in Wave 05.

## Wave 05 EDD API Coverage

Current Wave 05 API tests verify:

- `POST /api/customers/{customer_id}/edd`, `GET /api/customers/{customer_id}/edd`, and `PATCH /api/customers/{customer_id}/edd` require authentication;
- owner create/get/patch paths return explicit EDD owner DTOs with `confidential_comment`;
- duplicate current EDD records return `409 {"error":"duplicate_edd_record"}`;
- cross-owner get and patch fail closed with `404 {"error":"not_found"}` without returning confidential comments;
- invalid review statuses, missing required fields, malformed JSON, unknown JSON fields, and malformed path IDs return stable JSON errors;
- graph/export/network/entity/checker/public attack-data routes remain absent;
- EDD confidential comments do not appear in customer, account, transaction, alert, case, or case-note non-EDD responses.
- opt-in live PostgreSQL EDD API coverage applies all migrations to a clean schema and exercises owner create/get/patch, duplicate conflict, cross-owner fail-closed behavior, unauthenticated rejection, strict JSON boundaries, and non-EDD/side-view response leak checks through the real repository/service/HTTP stack.

## Wave 05 Gate Coverage

`scripts/check_wave05_gate.py` validates the current branch state:

- migrations exist in order through `000004_create_edd_records.sql`;
- Wave 05 tables are limited to auth, customer/account/transaction, alert/case/note, and `edd_records`;
- EDD schema constraints and indexes match the source contract;
- product, investigation, and EDD owner routes remain protected by auth;
- EDD DTOs are explicit and `confidential_comment` appears only in EDD create/update/owner response DTOs;
- `CaseNote.body` remains limited to case-note owner views;
- logs avoid credential, note-body, and EDD confidential-comment fields;
- exploit scripts, checker routes, public attack data, graph/export/network/entity/audit side views, debug routes, and admin routes remain absent;
- Wave 05 handoffs and validation summary exist;
- docs-tree and ForcAD config validators pass.

Run the Wave 05 historical branch gate:

```sh
python -B scripts/check_wave05_gate.py
```

## Wave 06 Projection Coverage

Current Wave 06 projection tests verify:

- `internal/projection` exposes named contracts for owner customer, account, transaction, alert, case, case-note, and EDD views;
- `internal/projection` exposes future safe placeholder contracts for public case shell, duplicate preview, audit summary, export summary, graph summary, and network summary surfaces without adding routes;
- each projection contract's JSON tags exactly match its allowlist;
- `body` appears only in the owner case-note projection contract;
- `confidential_comment` appears only in the owner EDD projection contract;
- password hashes, token hashes, session secrets, checker-private markers, artificial flag fields, raw DB row markers, and `owner_user_id` are absent from every projection contract;
- future safe projection contracts also exclude owner-only note/EDD fields, user assignment fields, transaction trace IDs, and counterparty fingerprints;
- HTTP handlers do not pass known domain model variables directly to `writeJSON`;
- JSON encoding remains centralized behind `writeJSON` while handlers continue to use explicit DTO/presenter outputs.

Current Wave 06 HTTP visibility tests verify:

- a high-entropy private note body is visible only through `GET /api/cases/{case_id}/notes` for the owning user;
- a high-entropy EDD confidential comment is visible only through `GET /api/customers/{customer_id}/edd` for the owning user;
- unauthenticated and cross-owner note/EDD routes do not disclose either sentinel;
- `/api/auth/me`, customer, account, transaction, alert queue/detail, and case shell responses do not disclose either sentinel;
- unsupported customer profile/risk paths, secure Wave 07 dedup side views, Wave 08 owner timeline responses, and absent graph/export/network/entities/checker/attack-data probes do not disclose either sentinel;
- method-not-allowed and invalid-path JSON errors do not disclose either sentinel;
- leak assertions include the endpoint name in the failure message.

Current Wave 06 cross-owner authorization tests verify:

- `internal/authz` lists the current owner-scoped resource contracts for customer, account, transaction, alert, case, case-note, and EDD resources;
- cross-owner customer get fails closed with `404 not_found`;
- cross-owner account get/list/create under a foreign customer fails closed with `404 not_found`;
- cross-owner transaction get/list/create under a foreign account fails closed with `404 not_found`;
- cross-owner alert detail, claim, and triage fail closed with `404 not_found`;
- alert queue remains owner-filtered and does not include another analyst's alert;
- cross-owner case get/status fail closed with `404 not_found`;
- cross-owner case-note get/post fail closed with `404 not_found`;
- cross-owner EDD get/post/patch fail closed with `404 not_found`;
- fail-closed responses omit private note and EDD sentinel strings;
- unauthenticated protected routes return `401 unauthenticated`;
- malformed owner resource IDs return `400 invalid_path`.

Run the focused authorization matrix:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/authz ./internal/httpapi -run "OwnerScope|Authorization|CrossOwner" -count=1
```

Run the focused HTTP visibility suite:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run Visibility -count=1
```

Wave 06 did not register public, duplicate-preview, audit, export, graph, network-room, checker, debug, or admin routes. Wave 07 registers only secure dedup list/merge-preview routes. Wave 08 registers only the secure owner case timeline audit route and keeps customer/entity activity plus graph/export/network/checker/debug/admin routes absent. Future waves that activate additional surfaces must reuse or extend the allowlist contracts with tests before route exposure.

## Wave 06 Gate Coverage

`scripts/check_wave06_gate.py` validates the current branch state:

- migration ordering remains limited to auth, customer/account/transaction, alert/case/note, and EDD records;
- previous owner auth/product/investigation/EDD routes remain present and protected;
- out-of-scope public, dedup, audit, graph, export, network, checker, attack-data, debug, and admin routes remain absent for the Wave 06 historical branch;
- `internal/projection` defines explicit owner and future-safe allowlists;
- `CaseNote.body` appears only in owner note DTO/projection contexts;
- `EDDRecord.confidential_comment` appears only in owner EDD DTO/projection contexts;
- HTTP Leak Regression tests exist and plant private sentinels that are allowed only in owner note and EDD GET endpoints;
- Cross-Owner Authorization Matrix tests exist and verify fail-closed `404 not_found` behavior without private sentinel leakage;
- logs avoid credential, note-body, and EDD confidential-comment markers;
- sploit and reference-fix scripts remain absent;
- Wave 06 handoffs, validation summary, docs tree, and ForcAD config validators pass.

Run the Wave 06 current branch gate:

```sh
python -B scripts/check_wave06_gate.py
make wave06-gate
```

After Wave 06, `scripts/check_wave05_gate.py` remains a historical Wave 05 closure gate and may reject intentional Wave 06 source-of-truth status changes. After Wave 07, `scripts/check_wave06_gate.py` remains a historical Wave 06 closure gate and may reject intentional Wave 07 dedup migration/routes. After Wave 08 audit work begins, `scripts/check_wave07_gate.py` is historical and may reject the intentional audit migration or timeline route.

## Wave 07 Dedup Metadata Coverage

Current Wave 07 tests verify:

- migrations exist in order through `000005_add_case_dedup_hint.sql`;
- the Wave 07 migration adds `cases.dedup_hint` with a nonblank-when-set constraint and dedup indexes;
- prior retention-sensitive tables such as `case_notes` and `edd_records` remain intact;
- migrations still do not add dedup tables, audit tables, graph/export/network tables, worker queues, checker-private fields, public attack data, or artificial flag fields;
- case creation can persist a normalized non-secret dedup hint without exposing it through HTTP DTOs;
- duplicate candidate discovery verifies the source case owner before lookup;
- same-hint candidates are returned while the source case itself and unrelated hints are excluded by query shape;
- empty or missing dedup hints return an empty candidate list without a broad scan;
- candidate results and queries do not include `CaseNote.body`, `EDDRecord.confidential_comment`, audit diffs, credentials, or session material;
- canceled contexts stop duplicate candidate discovery before database work;
- authenticated owners can list secure duplicate candidates for an owned source case;
- authenticated owners can retrieve a secure merge preview for a valid same-hint candidate;
- non-candidate previews, unknown source cases, malformed IDs, and cross-owner source cases fail closed with stable JSON errors;
- dedup list and merge-preview responses omit private note bodies, EDD confidential comments, private-note markers, audit/diff markers, auth/session fields, and checker-private markers;
- the HTTP leak sentinel suite probes the new dedup endpoints and verifies private note/EDD sentinels remain absent;
- anti-AML-1 tests plant victim private note and EDD confidential-comment sentinels on a duplicate candidate and prove secure dedup list/merge-preview responses remain public-only;
- response-shape tests lock `CaseDuplicatePreviewView` to `case_id`, `public_summary`, `risk_tags`, `overlap_score`, and `match_explanation`;
- projection/source guardrails fail if current dedup side-view contracts or presenters reference `body`, `confidential_comment`, `private_notes`, audit/diff markers, auth/session markers, owner IDs, or checker-private fields.

Run:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/casework ./tests
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run "Dedup|AML1|Visibility|CaseDuplicatePreview" -count=1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/projection ./tests -run "Projection|Dedup" -count=1
```

## Wave 07 Gate Coverage

`scripts/check_wave07_gate.py` validates the Wave 07 branch state:

- migration ordering through `000005_add_case_dedup_hint.sql`;
- secure `cases.dedup_hint` metadata exists without new dedup, audit, graph, export, network, worker, checker-private, public attack-data, or flag-store tables;
- auth/product/investigation/EDD route surface is retained and secure dedup dispatch is present under `/api/cases/`;
- graph/export/network/entities/checker/public attack-data/debug/admin routes remain absent;
- `CaseDuplicatePreviewView` and current side-view projection contracts expose only `case_id`, `public_summary`, `risk_tags`, `overlap_score`, and `match_explanation`;
- dedup presenters do not reference `CaseNote.body`, `EDDRecord.confidential_comment`, `private_notes`, audit/diff markers, auth/session markers, owner IDs, raw DB rows, or checker-private fields;
- Anti-AML-1 HTTP tests, W06 leak-regression probes for dedup endpoints, and source guard tests exist;
- exploit and reference-fix scripts remain absent;
- Wave 07 handoffs, `wave_07_validation_summary.md`, docs tree, and ForcAD config validators pass.

Run the Wave 07 historical branch gate:

```sh
python -B scripts/check_wave07_gate.py
make wave07-gate
```

After Wave 08, `scripts/check_wave07_gate.py` remains a historical Wave 07 closure gate and may reject the intentional Wave 08 audit migration/timeline route.

## Wave 08 Audit Persistence and Timeline Coverage

Current Wave 08 tests verify:

- migrations exist in order through `000006_create_audit_events.sql`;
- the Wave 08 migration defines `audit_events` with `actor_user_id`, `object_type`, `object_id`, `event_type`, `public_message`, `diff_json`, `created_at`, and `visibility_scope`;
- audit event object type, event type, visibility scope, positive object ID, and JSON-array diff constraints exist;
- audit indexes exist for actor, object, event type, visibility/created-at, and created-at access patterns;
- migrations still do not add graph/export/network tables, worker queues, dedup tables, checker-private fields, public attack data, or artificial flag fields;
- audit repository create paths validate object/event/visibility values and require a public message;
- audit repository list paths scope case timelines through an owned case before returning events;
- `CaseNote.body` and `EDDRecord.confidential_comment` changes are converted to `[redacted]` plus deterministic `sha256:` hashes before persistence;
- raw private note and EDD confidential sentinels are absent from persisted `diff_json` arguments;
- canceled contexts stop audit repository operations before database work.
- owner workflows record redacted audit events for case creation, case status changes, private note creation, and EDD create/update;
- `GET /api/cases/{case_id}/timeline` returns owner-scoped audit DTOs for owned cases;
- cross-owner and unauthenticated timeline access fails closed without private sentinels;
- timeline responses omit raw `diff_json`, `actor_user_id`, raw `body`, raw `confidential_comment`, value hashes, credential/session fields, checker-private markers, and artificial flag fields;
- projection contracts include an owner-only `owner_case_audit` allowlist and a redacted audit-change allowlist;
- customer activity, raw audit, checker, public attack-data, debug, and admin routes remain absent; entity activity is limited to the authenticated related-entity side view with redacted sensitive values.
- Anti-AML-2 regression tests preserve existing secure owner note and owner EDD paths while proving owner timeline and secure related-entity activity surfaces do not expose those private values;
- source-level audit presenter guards reject raw `body`, `confidential_comment`, `password_hash`, `token_hash`, `session`, `checker_private`, `flag_value`, raw `diff_json`, and value-hash exposure;
- `docs/09_vulnerability_matrix.md` keeps AML-2 locked until Wave 15.

Run:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/projection ./tests -run "Audit|Timeline|AML2|Visibility|Projection" -count=1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/audit ./internal/projection -run "Audit|Timeline|Visibility|Projection" -count=1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/audit ./tests
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave08_gate.py
python -B scripts/validate_forcad_config.py
make wave08-gate
```

## Wave 08 Gate Coverage

`scripts/check_wave08_gate.py` validates the Wave 08 branch state:

- migration ordering through `000006_create_audit_events.sql`;
- audit table fields, constraints, and indexes;
- `internal/audit` repository redaction helpers and owner-scoped case timeline query shape;
- previous auth/product/investigation/EDD/dedup route surface plus secure `GET /api/cases/{case_id}/timeline`;
- graph/export/network/checker/public attack-data/debug/admin routes remain absent; `/api/entities/{entity_hint}/activity` is separately covered as the Wave 34 secure related-entity activity side view.
- `CaseAuditView`, `CaseAuditChangeResponse`, and `owner_case_audit` expose only allowlisted redacted fields;
- `CaseNote.body` and `EDDRecord.confidential_comment` remain private business fields and are not emitted through timeline DTOs;
- Anti-AML-2 HTTP, projection, and source guard tests exist;
- exploit and reference-fix scripts remain absent;
- Wave 08 handoffs, `wave_08_validation_summary.md`, docs tree, and ForcAD config validators pass.

Run the Wave 08 current branch gate:

```sh
python -B scripts/check_wave08_gate.py
make wave08-gate
```

## Wave 09 Graph Persistence Coverage

Current Wave 09 graph tests verify:

- migrations exist in order through `000007_create_entity_graph.sql`;
- the Wave 09 migration defines `entity_graph_nodes` and `entity_graph_edges` with nonblank hints, allowed node/relation types, uniqueness, strength bounds, and graph lookup indexes;
- graph tables do not contain `CaseNote.body`, `EDDRecord.confidential_comment`, EDD `source_of_funds`, EDD `risk_rationale`, raw audit `diff_json`, credentials, token/session material, checker-private markers, public attack data, or artificial flag fields;
- `internal/graph` can verify access when an analyst owns at least one customer for the requested normalized `entity_hint`;
- non-owners without a matching owned hint have no graph access;
- entity summaries include safe counts, relation type, highest risk score, public risk tags, and timestamps;
- related case summaries include only case shell and customer metadata;
- EDD graph summaries include review status and risk level only, not confidential comments or raw EDD narrative fields;
- graph repository query text avoids joins to `case_notes` and avoids selecting private EDD or audit fields;
- invalid hints and canceled contexts fail before database work.

Run:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/graph ./tests
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
```

W09-T01 does not add a graph HTTP endpoint or worker. W09-T02 exposes only the secure graph HTTP metadata endpoints after adding projection allowlists and HTTP leak tests.

## Wave 09 Graph HTTP Coverage

Current W09-T02 tests verify:

- `GET /api/graph/entities/{entity_hint}`, `GET /api/graph/entities/{entity_hint}/related-cases`, and `GET /api/graph/entities/{entity_hint}/edd-summaries` require authentication;
- graph access is allowed only when the authenticated analyst owns at least one customer matching the normalized entity hint;
- unknown or unauthorized graph hints fail closed with `404 not_found`;
- graph responses use explicit `GraphEntityView`, `GraphRelatedCaseView`, and `EDDGraphSummaryView` DTOs;
- graph DTOs include only entity hint, relation type, safe counts, public case/customer metadata, risk tags, review status, and timestamps;
- graph responses omit private note bodies, EDD confidential comments, EDD narrative fields, raw audit diffs, credentials, session material, owner IDs, analyst/author/assignee IDs, transaction trace IDs, counterparty fingerprints, checker-private markers, artificial flag fields, and raw DB rows;
- the consolidated HTTP visibility suite probes the new graph routes and confirms high-entropy note/EDD sentinels remain visible only in owner note and owner EDD endpoints;
- `/api/graph`, `/api/entities`, export, network, checker, public attack-data, debug, and admin surfaces remain absent.
- `TestAntiAML3RelatedGraphDoesNotExposePrivateStores` creates a victim and second analyst sharing an entity hint, confirms owner note/EDD paths still return private fields to the owner, and verifies graph endpoints for both users do not leak victim sentinels;
- `TestAntiAML3GraphProjectionContractsDenyPrivateFields` locks graph projection contracts against private note, EDD, audit, auth/session, checker, trace, owner, and raw-row fields;
- `TestAntiAML3GraphRepositorySummariesStayMetadataOnly` source-checks graph repository structs and query methods for private-field leakage.

Run:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/projection ./tests -run "AML3|Graph|Visibility|Projection" -count=1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
```

AML-3 remains future-only until Wave 16. Wave 09 tests prove the current secure graph baseline does not expose private stores through repository structs, HTTP DTOs, projection contracts, source presenters, or endpoint responses.

## Wave 10 Export Persistence And Redaction Coverage

Current W10-T01 tests verify:

- migrations exist in order through `000008_create_exports_disputes.sql`;
- `disputes`, `exports`, and `export_items` define owner fields, case/export relationships, status constraints, JSON payload constraints, retention-compatible timestamps, and lookup indexes;
- export persistence does not add network-room, checker, public attack-data, exploit, reference-fix, or artificial flag storage tables;
- `internal/exporting` repository methods create disputes, exports, and export items through owner-scoped `cases` or `exports` queries;
- non-owner root-case export creation fails closed with `ErrExportNotFound`;
- invalid export contexts, purposes, statuses, JSON payloads, item types, object types, relations, and canceled contexts fail before unsafe work;
- export redaction recursively walks root and linked cases but emits only public case shells, safe audit summaries, safe EDD summaries, and item metadata;
- root and linked private note bodies, EDD confidential comments, raw EDD narrative fields, raw audit diffs, and value hashes are omitted from JSON output;
- projection contracts include `export_bundle`, `export_case_shell`, `export_audit_summary`, `export_edd_summary`, and `export_item_metadata` and reject AML-4 private fields.

Run:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/exporting ./internal/projection ./tests
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
```

## Wave 10 Secure Export HTTP Coverage

Current W10-T02 HTTP tests verify:

- `POST /api/cases/{case_id}/exports`, `GET /api/exports/{export_id}`, `POST /api/disputes`, and `POST /api/disputes/{dispute_id}/export` require authentication;
- root case export creation and export retrieval are owner-scoped;
- cross-owner export retrieval fails closed with `404 not_found` and does not disclose private sentinels;
- dispute creation and dispute export resolve through the owning analyst's case/dispute;
- unknown JSON fields, invalid purposes, invalid scopes, malformed export/dispute IDs, and wrong methods return stable JSON errors;
- root and linked private note bodies, EDD confidential comments, EDD narrative fields, raw audit diffs, value hashes, auth/session fields, checker-private markers, and artificial flag fields are absent from export responses;
- network-room, checker, public attack-data, debug, admin, raw export, and broad export routes remain absent.

Run:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/exporting ./internal/projection -run "Export|Projection" -count=1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B -m unittest discover -s tests -p "test_*.py"
```

W10-T01 did not run the historical Wave 09 gate as a current-branch gate because `000008_create_exports_disputes.sql` is an intentional Wave 10 expansion that the Wave 09 gate is designed to reject. W10-T02 adds the secure HTTP export surface. W10-T05 adds the current Wave 10 branch gate.

## Wave 10 Network-Room Persistence And Dossier Coverage

Current W10-T03 tests verify:

- migrations exist in order through `000009_create_network_rooms.sql`;
- `network_rooms`, `network_room_cases`, and `network_room_participants` define deterministic room metadata, case-reference links, participant metadata, constraints, uniqueness, and lookup indexes;
- network-room migration storage omits private note bodies, EDD confidential comments, raw EDD narrative fields, raw audit diffs, value hashes, raw case blobs, checker-private markers, public attack data, artificial flag fields, and debug/admin state;
- `internal/networkroom` creates or finds deterministic rooms from normalized entity and typology metadata;
- case links and participant joins store references and metadata only;
- room listing is scoped through participant membership;
- safe dossiers include room metadata and public case summaries while omitting planted private note, EDD, audit, and value-hash sentinels;
- invalid room, case, user, relation, role, and dossier inputs fail with stable domain errors;
- canceled contexts fail before repository calls;
- projection contracts include `network_room_summary`, `network_room_case`, and `network_room_dossier` and reject AML-5 private fields.

Run:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/networkroom ./internal/projection ./tests
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
```

W10-T03 did not add network-room HTTP routes or workers. W10-T04 activates only the secure network-room room list/detail/join/dossier routes.

## Wave 10 Secure Network-Room HTTP Coverage

Current W10-T04 HTTP tests verify:

- `GET /api/network/rooms`, `GET /api/network/rooms/{room_id}`, `POST /api/network/rooms/{room_id}/join`, and `GET /api/network/rooms/{room_id}/dossier` require authentication;
- authenticated analysts can join an existing room and then list, detail, and read a references-only dossier for that room;
- non-participants fail closed on room detail/dossier access;
- dossiers may include own and foreign public case shells, `owned_by_requester`, public risk tags, and `private_data_omitted`;
- private note and EDD confidential sentinels from own and foreign cases are absent from join, list, detail, dossier, cross-participant, invalid-path, method-not-allowed, and absent-route responses;
- dossier responses omit raw EDD narrative fields, raw audit diffs, value hashes, credentials, sessions, counterparty fingerprints, trace IDs, checker-private markers, artificial flag fields, raw DB rows, and raw source case blobs;
- broad network roots, raw/private network paths, checker, public attack-data, debug, and admin routes remain absent.

Run:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi ./internal/networkroom ./internal/projection -run "Network|Projection" -count=1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
```

W10-T04 adds the secure network-room HTTP surface. W10-T05 adds the current Wave 10 branch gate and aligns current status authority around the intentional export and network-room expansion.

## Wave 10 Gate Coverage

`scripts/check_wave10_gate.py` validates the Wave 10 current branch state:

- migration ordering through `000009_create_network_rooms.sql`;
- export/dispute tables and network-room tables remain limited to secure baseline storage;
- `internal/exporting` recursive redaction covers root, linked, and nested linked cases;
- export DTOs and presenters omit private notes, EDD confidential comments, raw EDD narrative fields, raw audit diffs, value hashes, credentials, sessions, checker-private markers, artificial flag fields, and raw DB rows;
- network-room repository methods remain participant-scoped and references-only;
- network-room DTOs and dossier presenters expose room metadata, participant metadata, public case shells, `owned_by_requester`, and `private_data_omitted` only;
- secure export routes and secure network-room routes are registered while checker, public attack-data, debug, admin, graph-root, and broad network root routes remain absent;
- projection contracts include `ExportBundleView`, export shell/summary/item views, `NetworkRoomSummaryView`, `NetworkRoomCaseView`, and `NetworkRoomDossierView`;
- Anti-AML-4 and Anti-AML-5 HTTP/source regression tests exist;
- exploit and reference-fix scripts remain absent;
- Wave 10 handoffs, `wave_10_validation_summary.md`, docs tree, and ForcAD config validators pass.

Run the Wave 10 current branch gate:

```sh
python -B scripts/check_wave10_gate.py
make wave10-gate
```

## Wave 11 Checker Coverage

Wave 11 introduced the first real checker behavior while keeping the product
surface unchanged. Checker tests under `tests/test_*checker*.py` verify:

- checker CLI/action parsing for `check`, `put`, and `get`;
- place 1 PFR output shape for PUT;
- private state/public attack data separation;
- public attack data excludes usernames, passwords, tokens, sessions, raw flags,
  checker secrets, and private state;
- private state round trips and rejects tampering;
- place 1 PUT uses the normal HTTP sequence: register, login, customer, account,
  suspicious transaction, alert queue, alert claim, case create, private case
  note create;
- the raw flag appears only in fake-server private note request/response
  fixtures for `POST /api/cases/{case_id}/notes`;
- place 1 GET reads only `GET /api/cases/{case_id}/notes` as the original
  owner, with token use or owner re-authentication;
- wrong flags, tampered state, missing notes, missing owner note view, and auth
  failures map to checker failures;
- dedup, audit, graph, export, network-room, merge-preview, debug, admin,
  public attack-data, and checker-only endpoints are not used as checker
  retrieval paths;
- checker files do not import database drivers or Go/internal repository
  concepts;
- historical place 2 and HAVOC deferral for the Wave 11 branch;
- exploit and reference-fix scripts remain absent.

`scripts/check_wave11_gate.py` is the historical Wave 11 no-bypass gate. It
checks the Wave 11 branch checker source, schema helpers, checker regression
tests, absent exploit/fix scripts, Wave 11 handoffs, Makefile target, and
ForcAD config.

Run:

```sh
python -B -m unittest discover -s tests -p "test_*.py"
python -B scripts/check_wave11_gate.py
python -B scripts/validate_forcad_config.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
make wave11-gate
```

Wave 11 non-goals were: No checker bypass, no public credentials, no public
attack-data route, no direct database checker path, no side-view GET, no place 2
lifecycle, no HAVOC, no vulnerabilities, no exploit scripts, and no reference
fixes. Wave 12 activates place 2; CHECK/HAVOC remains Wave 13. Planned
vulnerability waves remain locked.

## Wave 12 Multi-Place Checker Security Matrix

Wave 12 activates both checker places while keeping CHECK/HAVOC and planned
vulnerability behavior out of scope. Place 1 remains `CaseNote.body` and place
2 is active as `EDDRecord.confidential_comment`.

Place 1 remains `CaseNote.body`. Place 2 is active as `EDDRecord.confidential_comment`. No planned vulnerability behavior is included in Wave 12.

Checker regression tests under `tests/test_*checker*.py` verify:

- place 1 PUT stores the raw flag only through `POST /api/cases/{case_id}/notes`;
- place 1 GET retrieves the raw flag only through `GET /api/cases/{case_id}/notes`;
- place 2 PUT stores the raw flag only as `confidential_comment` through `POST /api/customers/{customer_id}/edd`;
- place 2 GET retrieves the raw flag only through `GET /api/customers/{customer_id}/edd`;
- token reuse and owner re-authentication work for both GET paths;
- place/store validation prevents cross-place private state confusion;
- tampered private state and wrong flag/idempotency mismatches fail before HTTP when possible;
- public attack data for place 1 contains only `service`, `store`, `case_id`, `customer_id`, `dedup_hint`, and `typology_hint`;
- public attack data for place 2 contains only `service`, `store`, `customer_id`, `entity_hint`, and `typology_hint`;
- public attack data excludes usernames, passwords, bearer/session tokens, raw flags, checker secrets, private state, and `confidential_comment`;
- checker GET does not use dedup, audit, graph, export, network-room, merge-preview, debug, admin, public attack-data, or checker-only side views;
- checker source does not import database drivers or Go/internal repository concepts.

`scripts/check_wave12_gate.py` is the current Wave 12 multi-place checker gate.
It validates place 2 activation, place 1 preservation, PFR public/private
separation, cross-place state rejection, owner-view-only GET source paths, no
direct DB/internal imports, no hidden endpoints, no exploit/fix scripts, Wave
12 handoff presence, this testing strategy status, the Makefile target, and
ForcAD config validity.

Run:

```sh
python -B -m unittest discover -s tests -p "test_*checker*.py"
python -B -m unittest discover -s tests -p "test_wave12_gate.py"
python -B scripts/check_wave12_gate.py
python -B scripts/validate_forcad_config.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
make wave12-gate
```

Wave 12 non-goals: CHECK/HAVOC remains Wave 13. No planned vulnerability
behavior, exploit scripts, reference fixes, debug/admin endpoints, public
attack-data routes, product authorization weakening, or direct database checker
access are introduced.

Historical note: `scripts/check_wave11_gate.py` remains the Wave 11 closure gate
and still encodes the pre-Wave-12 expectation that place 2 parsing fails. Use
`scripts/check_wave12_gate.py` for the current multi-place branch.

## Wave 13 CHECK/HAVOC Framework Gate

W13-T01 replaced the shallow health-only CHECK with a named subcheck framework
shared by `check <host>` and `havoc <host>`. W13-T02 added basic, notes, and
dedup business-function checks. W13-T03 added audit timeline and related-graph
safety checks. W13-T04 added export and network-room anti-coarse-fix checks.
W13-T05 adds optional `putnoise`/`getnoise` and a retention smoke guard.
`DEFAULT_CHECK_SUBCHECKS` currently contains `health`, `check_basic`,
`check_case_notes`, `check_dedup`, `check_audit`, `check_graph`,
`check_export`, `check_network_room`, and `check_retention`.

Checker tests in `test_checker_check_workflow.py` verify:

- named subchecks run in dispatcher order;
- unsupported subchecks fail closed with a non-OK checker result;
- subcheck failures are aggregated with independent failure messages;
- `check_basic` uses normal auth, customer, account, transaction, and readback
  routes;
- `check_case_notes` creates an owned case, writes a non-secret private note,
  and reads owner notes without requiring any foreign case body;
- `check_dedup` creates two owned cases with the same `dedup_hint`, verifies
  duplicate candidates, and verifies merge-preview public fields only;
- missing dedup candidates and private fields in merge-preview fail CHECK;
- `check_audit` creates an owned case and non-secret note, verifies the owner
  timeline contains a note event, and fails if the raw note body or raw audit
  diff fields appear;
- missing audit timeline support, missing note events, or unredacted timeline
  changes fail CHECK;
- `check_graph` creates two owned cases for customers sharing the same
  `entity_hint`, verifies the graph entity summary and related-case relation
  count, and rejects non-public graph DTO fields;
- missing graph support or graph private-field leakage fails CHECK;
- `check_export` creates an owned case/export context, verifies export creation
  and retrieval, and rejects bundle shapes that expose private note, EDD,
  audit, credential, session, checker-private, or flag markers;
- disabled export routes or private fields in export bundles fail CHECK;
- `check_network_room` creates deterministic same-entity cases, requires a
  matching materialized participant-visible network room, verifies the
  references-only dossier, and rejects non-public dossier fields;
- disabled network-room routes, missing materialized rooms, or private fields
  in network-room summaries/dossiers fail CHECK;
- `check_retention` scans packaged migrations, product source, and scripts for
  physical delete/truncate/drop paths targeting retention-sensitive
  `case_notes` and `edd_records`;
- `putnoise` creates non-secret customers, transactions, cases, EDD records,
  export context, graph hints, and safe network-room locators where
  materialized;
- `getnoise` verifies MAC-protected private noise state without reading or
  comparing flag values;
- noise public data excludes credentials, tokens, sessions, flags, raw
  `CaseNote.body`, `EDDRecord.confidential_comment`, checker secrets, and
  private state;
- HAVOC uses the same safe framework without changing PUT/GET semantics;
- CHECK must not reveal flags or credentials in stderr or aggregated errors.
- fake checker HTTP services close deterministically under unittest discovery:
  test servers use daemon request threads, non-blocking server close behavior,
  explicit `Connection: close` responses, and joined serving threads so
  `python -B -m unittest discover -s tests -p "test_checker_*.py"` exits after
  the final test.

`scripts/check_wave13_gate.py` validates the W13-T01 framework contract:

- checker source still has no direct DB/internal dependencies;
- checker source still has no hidden checker-only, public attack-data, debug, or
  admin endpoint calls;
- place 1 and place 2 PUT/GET owner retrieval paths are preserved;
- checker PUT/GET workflow tests and CHECK/HAVOC workflow tests are present;
- `check` and `havoc` parse and dispatch through the framework;
- `check_basic`, `check_case_notes`, `check_dedup`, `check_audit`,
  `check_graph`, `check_export`, `check_network_room`, and `check_retention`
  are present in the default subcheck set;
- `putnoise` and `getnoise` parse as explicit optional lifecycle actions;
- redaction removes flag, credential, token, secret, and private-state markers;
- exploit/reference-fix implementation files are still absent before the
  planned exploit and fix waves;
- production checker/product/migration sources contain no current vulnerable
  variant markers;
- `make wave13-gate` is wired to run checker tests, Wave 13 gate tests, Go
  test/vet, docs tree, Wave 13 gate, and ForcAD validation;
- checker workflow tests and framework docs are present;
- ForcAD config remains valid.

Wave 13 framework non-goals: no planned vulnerabilities, no reference exploits,
no reference fixes, no flag recovery through side views, and no PUT/GET semantic
changes.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*workflow.py"
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave13_gate.py"
python -B scripts/check_wave13_gate.py
python -B scripts/validate_forcad_config.py
make wave13-gate
```

## Wave 14 AML-1 Vulnerable Profile Gate

Wave 14 introduces AML-1 only through the `aml1_vulnerable` Go build tag. The
default build remains the secure dedup profile where merge-preview responses
are public-only. The tagged profile changes only
`GET /api/cases/{case_id}/duplicates/{duplicate_case_id}/merge-preview` so the
matched duplicate candidate can include `private_notes[].body`.
`docs/09_vulnerability_matrix.md` remains the source of truth for what AML-1
may expose and what exploit/fix behavior remains locked.

Wave 14 tests verify:

- default secure dedup list and merge-preview responses remain public-only;
- the `aml1_vulnerable` profile exposes the duplicate case private note body
  through merge-preview;
- the duplicate list remains public-only in both profiles;
- AML-1 does not expose `EDDRecord.confidential_comment`, EDD narrative fields,
  audit diffs, credentials, sessions, checker-private state, or unrelated
  internal fields;
- checker PUT/GET and CHECK/HAVOC tests remain part of the regression evidence;
- No reference exploit or reference fix is present in Wave 14.
- `scripts/check_competition_matrix_gate.py` marks the AML-1 vulnerable checker
  gate as concrete while keeping the AML-1 exploit-success, fixed checker,
  exploit-blocked, and anti-coarse-fix cells pending.
- `scripts/check_wave14_gate.py` fails on accidental AML-2 through AML-5
  activation markers in production source/config files.
- fake checker HTTP servers flush close-delimited responses, assert serving
  threads stop during context cleanup, and include a subprocess liveness
  regression that fails if checker unittest discovery prints `OK` but does not
  return control to the caller.
- Wave 14 task handoff evidence is complete:
  `wave_14_W14-T01_handoff.md`, `wave_14_W14-T02_handoff.md`, and
  `wave_14_W14-T03_handoff.md` must exist with standard self-review markers.

Run:

```sh
python -B -m unittest discover -s tests -p "test_wave14_gate.py"
python -B scripts/check_wave14_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_wave13_gate.py
python -B scripts/validate_forcad_config.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml1_vulnerable ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B scripts/check_docs_tree.py
make wave14-gate
```

On hosts without `make`, run the target's component commands in the order shown
above. The target is authoritative for current Wave 14 validation; the Wave 13
gate remains the historical pre-vulnerability CHECK/HAVOC baseline gate.

## Wave 15 AML-2 Vulnerable Profile Gate

Wave 15 introduces AML-2 only through the `aml2_vulnerable` Go build tag. The
default build remains the secure audit profile where sensitive changes are
redacted. Wave 34 makes AML-2 reachable through the product side view
`GET /api/entities/{entity_hint}/activity`: default builds return metadata plus
redacted sensitive values, while the tagged competition profile changes only
the related-entity activity presenter so related `case_note` audit events may
show `case_note.body` and the associated `CaseNote.body` value.
`docs/09_vulnerability_matrix.md` remains the source of truth for what AML-2
may expose and what exploit/fix behavior remains locked.

Wave 15 tests verify:

- default secure audit timeline and related-entity activity responses remain redacted;
- the `aml2_vulnerable` / `audit_detail_view` profile exposes only related
  case-note body values through entity activity change projection;
- cross-owner timeline access still fails closed;
- cross-owner note access still fails closed;
- graph, export, and network-room responses do not expose the AML-2 private
  note value;
- `EDDRecord.confidential_comment`, EDD narrative fields, hashes, credentials,
  sessions, checker-private state, public attack data, and raw database rows
  remain excluded from AML-2 output;
- checker PUT/GET and CHECK/HAVOC tests remain part of the regression evidence;
- No reference exploit or reference fix is present in Wave 15.
- `scripts/check_competition_matrix_gate.py` marks AML-1 and AML-2 vulnerable
  checker gates as concrete while keeping exploit-success, fixed checker,
  exploit-blocked, and anti-coarse-fix cells pending.
- `scripts/check_wave15_gate.py` fails on accidental AML-3 through AML-5
  activation markers in production source/config files.
- fake checker HTTP servers close their listening sockets during teardown
  before waiting on serving threads, bound accepted socket reads, and include a
  Wave 15 subprocess liveness regression that fails if checker unittest
  discovery prints `OK` but does not return control.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave15_gate.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml2_vulnerable ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave15_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/validate_forcad_config.py
make wave15-gate
```

On Windows sandboxed hosts, `GO_OFFLINE_ENV` sets `GOCACHE` and `APPDATA`
inside the workspace so Go test and vet do not depend on user-global telemetry
or build-cache directories. On hosts without `make`, run the target's component
commands in the order shown above and record that final wrapper closure still
requires a make-equipped review host.

## Wave 16 AML-3 Vulnerable Profile Gate

Wave 16 introduces AML-3 only through the `aml3_vulnerable` Go build tag. The
default build remains the secure graph profile where related-entity graph access
returns metadata/count projections only. The tagged profile changes only
`GET /api/graph/entities/{entity_hint}/edd-summaries` so related EDD summary
items may include `confidential_comment` after normal authentication and the
owned-`entity_hint` access check. `docs/09_vulnerability_matrix.md` remains the
source of truth for what AML-3 may expose and what exploit/fix behavior remains
locked.

Wave 16 tests verify:

- default secure graph responses do not expose `CaseNote.body` or
  `EDDRecord.confidential_comment`;
- the `aml3_vulnerable` profile exposes only `EDDRecord.confidential_comment`
  through the graph EDD-summary endpoint;
- cross-owner direct case-note and owner EDD APIs remain fail closed;
- graph entity summaries, related-case summaries, export bundles, network-room
  dossiers, and audit timelines are not broadened by AML-3;
- EDD narrative fields, raw audit diffs, hashes, credentials, sessions,
  checker-private state, public attack data, raw database rows, and
  debug/admin controls remain excluded;
- checker PUT/GET and CHECK/HAVOC tests remain part of the regression evidence;
- no reference exploit or reference fix is present in Wave 16;
- `scripts/check_competition_matrix_gate.py` marks AML-1, AML-2, and AML-3
  vulnerable checker gates as concrete while keeping exploit-success, fixed
  checker, exploit-blocked, and anti-coarse-fix cells pending;
- `scripts/check_wave16_gate.py` fails on accidental AML-4 or AML-5 activation
  markers in production source/config files.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave16_gate.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -tags aml3_vulnerable ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave16_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/validate_forcad_config.py
make wave16-gate
```

On hosts without `make`, run the target's component commands in the order shown
above and record that final wrapper closure still requires a make-equipped
review host. Wave 16 is complete after orchestrator `make wave16-gate`
acceptance. Wave 21, Wave 22, and Wave 23 are accepted, and Wave 24 is
implemented under review for the AML-1 reference fix.

## Wave 17 AML-4 Vulnerable Profile Gate

Wave 17 introduces AML-4 only through the `aml4_vulnerable` Go build tag. The
default build remains the secure export profile where root and linked cases are
recursively public/redacted. The tagged profile changes only
`POST /api/disputes/{dispute_id}/export` so linked duplicate-case private
analyst notes may appear as `linked_private_notes[]` entries containing
`case_id`, `note_id`, and `body`. `docs/09_vulnerability_matrix.md` remains the
source of truth for what AML-4 may expose and what exploit/fix behavior remains
locked.

Wave 17 tests verify:

- default secure dispute exports do not expose root or linked private note
  bodies;
- the `aml4_vulnerable` profile exposes only linked duplicate-case
  `CaseNote.body` values through dispute export bundles;
- ordinary case exports, root object redaction, owner note APIs, and owner EDD
  APIs are not changed;
- `EDDRecord.confidential_comment`, EDD narrative fields, raw audit diffs,
  hashes, credentials, sessions, checker-private state, public attack data, raw
  database rows, graph data, and network-room dossier data remain excluded;
- checker PUT/GET and CHECK/HAVOC tests remain part of the regression evidence;
- no reference exploit or reference fix is present in Wave 17;
- `scripts/check_competition_matrix_gate.py` marks AML-1, AML-2, AML-3, and
  AML-4 vulnerable checker gates as concrete while keeping exploit-success,
  fixed checker, exploit-blocked, and anti-coarse-fix cells pending;
- `scripts/check_wave17_gate.py` fails on accidental AML-5 activation markers
  in production source/config files.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave17_gate.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test -p 1 -tags aml4_vulnerable ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave17_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/validate_forcad_config.py
make wave17-gate
```

The Wave 17 wrapper intentionally serializes the tagged vulnerable-profile
package sweep with `go test -p 1 -tags aml4_vulnerable ./...`. Orchestrator
evidence showed the default package-parallel tagged sweep could fail to
terminate within the 300 second closure wrapper, while the same tagged sweep
with serialized package execution completed. This is a gate determinism policy;
it does not change AML-4 behavior, default secure export redaction, checker
PUT/GET, public attack data, or any exploit/fix sequencing.

On hosts without `make`, run the target's component commands in the order shown
above and record that final wrapper closure still requires a make-equipped
review host. Wave 17 is complete after W17-F01 deterministic wrapper evidence.
Wave 22 is accepted after Wave 21 acceptance and adds only the AML-4 reference
exploit. Wave 23 is accepted and adds only the AML-5 reference exploit. Wave
24 is implemented under review for the AML-1 reference fix.

## Wave 18 AML-5 Vulnerable Profile Gate

Wave 18 introduces AML-5 only through the `aml5_vulnerable` Go build tag. The
default build remains the secure network-room profile where rooms and dossiers
are references-first and public/redacted. The tagged profile changes only
`GET /api/network/rooms/{room_id}/dossier` so a room participant may receive
bounded foreign source-case private data after the normal network-room
clustering/materialization and participant path. `docs/09_vulnerability_matrix.md`
remains the source of truth for what AML-5 may expose and what exploit/fix
behavior remains locked.

Wave 18 tests verify:

- default secure network-room dossiers do not expose own or foreign private
  note bodies or EDD confidential comments;
- the `aml5_vulnerable` profile exposes only bounded foreign private note and
  EDD confidential-comment data through `foreign_private_notes` and
  `foreign_edd_comments`;
- dossier access still requires normal authentication and room participant
  scope;
- owner note APIs, owner EDD APIs, checker PUT/GET, graph, export, audit, and
  public attack data are not broadened;
- credentials, sessions, checker-private state, raw audit diffs, raw rows, EDD
  `source_of_funds`, EDD `risk_rationale`, debug/admin controls, exploit
  behavior, and fix behavior remain excluded;
- no AML-5 reference exploit or reference fix is present at the Wave 18 branch
  point;
- `scripts/check_competition_matrix_gate.py` marks AML-1 through AML-5
  vulnerable checker gates as concrete; after Wave 23 it also marks the AML-1
  through AML-5 exploit-success cells concrete while keeping all fix cells
  pending;
- `scripts/check_wave18_gate.py` validates the `wave18-gate` wrapper, its
  package-by-package AML-5 tagged sweep, release-scoped Go cache environment,
  and archive hygiene validation.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave18_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off python -B scripts/run_aml5_tagged_tests.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
python -B scripts/check_docs_tree.py
python -B scripts/check_wave18_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
make wave18-gate
```

The Wave 18 wrapper uses the deterministic tagged-test strategy established by
W18-F01: `scripts/run_aml5_tagged_tests.py` discovers packages with
`go list -tags aml5_vulnerable ./...` and runs
`go test -tags aml5_vulnerable -count=1 -timeout 60s <package>` per package.
This is a gate determinism policy only; it does not change AML-5 behavior,
default secure network-room redaction, checker PUT/GET, public attack data, or
exploit/fix sequencing. `make wave18-gate` also keeps Wave 18 Go cache and
application-data scratch paths outside the repository and runs
`scripts/check_archive_hygiene.py` before closure.

Wave 18 is complete after W18-F01/F02/F03. Wave 23 is accepted and contains
only `sploits/sentinel_aml/aml_network_room.py`. Wave 24 provides the AML-1
reference fix, Wave 25 provides the AML-2 reference fix, Wave 26 provides the
AML-3 reference fix, Wave 27 provides the AML-4 reference fix, Wave 28 provides
the AML-5 reference fix, and Wave 29 is implemented under review for full
matrix regression.

## Wave 19 AML-1 Reference Exploit Gate

Wave 19 adds exactly one reference exploit:
`sploits/sentinel_aml/aml_dedup_preview.py`. The script targets only the
accepted AML-1 `aml1_vulnerable` merge-preview leak. It accepts host, port, and
public attack-info JSON or a JSON file, creates an attacker-owned source case
with the public victim `dedup_hint`, requests the normal dedup merge-preview
side view, and prints only the extracted flag from
`candidate.private_notes[].body`.

Wave 19 tests verify:

- the exploit exists at exactly `sploits/sentinel_aml/aml_dedup_preview.py`;
- the exploit imports no database drivers, uses no raw SQL, invokes no shell
  process, and does not read checker-private state or public attack-data
  passwords/tokens;
- the exploit expects place 1 `CaseNote.body` attack data with `case_id` and
  `dedup_hint`;
- a fake AML-1 vulnerable service yields stdout containing only the leaked
  flag;
- a secure/default merge-preview response fails safely with non-zero exit;
- Wave 19 rejects AML-2 through AML-5 exploit scripts and all reference fix
  files in its point-in-time gate; the current branch has advanced to Wave 23
  and is governed by `scripts/check_wave23_gate.py`.
- `scripts/check_competition_matrix_gate.py` now marks AML-1 through AML-5
  exploit-success concrete and AML-1 through AML-5 fix cells concrete in the
  Wave 28 gate; final competition readiness remains pending.
- `docs/wave_reports/wave_19_validation_summary.md` records the Wave 19
  evidence. Wave 19 is accepted by orchestrator review, and Wave 20 is now the
  implemented-under-review exploit wave.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave19_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py
python -B scripts/check_wave19_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
make wave19-gate
```

## Wave 20 AML-2 Reference Exploit Gate

Wave 20 adds exactly one new reference exploit on top of the accepted AML-1
exploit: `sploits/sentinel_aml/aml_audit_timeline.py`. The script targets only
the accepted AML-2 `aml2_vulnerable` audit timeline overexposure. It accepts
host, port, and public attack-info JSON or a JSON file, registers/logs in as an
attacker, requests only the normal case timeline side view, and prints only the
extracted flag from exposed `case_note.body` change material or equivalent
audit `diff_json`.

Wave 20 tests verify:

- exactly `aml_dedup_preview.py` and `aml_audit_timeline.py` are present under
  `sploits/sentinel_aml/`;
- the AML-2 exploit imports no database drivers, uses no raw SQL, invokes no
  shell process, and does not read checker-private state or public attack-data
  passwords/tokens;
- the AML-2 exploit expects place 1 `CaseNote.body` attack data with public
  `case_id` and locator metadata;
- fake vulnerable audit timeline responses yield stdout containing only the
  leaked flag from the intended audit side view;
- secure/default redacted timeline responses fail safely with non-zero exit;
- Wave 20 rejected AML-3 through AML-5 exploit scripts and all reference fix
  artifacts at its point-in-time acceptance; the current branch has advanced to
  Wave 23 and is governed by `scripts/check_wave23_gate.py`;
- `scripts/check_competition_matrix_gate.py` now marks AML-1 through AML-5
  exploit-success concrete and AML-1 through AML-5 fix cells concrete in the
  Wave 28 gate while final competition readiness remains pending;
- `docs/wave_reports/wave_20_validation_summary.md` records the accepted Wave
  20 evidence after W20-F01/W20-F02 reconciliation and exit-0
  `timeout 300 make wave20-gate` re-review. Wave 21, Wave 22, and Wave 23 are
  accepted. Wave 24 provides the AML-1 reference fix, Wave 25 provides the
  AML-2 reference fix, Wave 26 provides the AML-3 reference fix, Wave 27
  provides the AML-4 reference fix, Wave 28 provides the AML-5 reference fix,
  and Wave 29 is implemented under review for full matrix regression.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave20_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py
python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py
python -B scripts/check_wave20_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
timeout 300 make wave20-gate
```

## Wave 21 AML-3 Reference Exploit Gate

Wave 21 adds exactly one new reference exploit on top of the accepted AML-1 and
AML-2 exploits: `sploits/sentinel_aml/aml_related_graph.py`. The script targets
only the accepted AML-3 `aml3_vulnerable` related graph EDD-summary exposure.
It accepts host, port, and public attack-info JSON or a JSON file,
registers/logs in as an attacker, creates only attacker-owned graph
participation with the public victim `entity_hint`, requests only
`GET /api/graph/entities/{entity_hint}/edd-summaries`, and prints only the
extracted flag from leaked `summaries[].confidential_comment`.

Wave 21 tests verify:

- exactly `aml_dedup_preview.py`, `aml_audit_timeline.py`, and
  `aml_related_graph.py` are present under `sploits/sentinel_aml/` at Wave 21
  acceptance time;
- AML-4 and AML-5 exploit scripts remained absent at the Wave 21 branch point;
- `fixes/sentinel_aml/` remained README-only at the Wave 21 branch point;
- the AML-3 exploit imports no database drivers, uses no raw SQL, invokes no
  shell process, and does not read checker-private state or public attack-data
  passwords/tokens/sessions;
- the AML-3 exploit expects place 2 `EDDRecord` attack data with public
  `customer_id`, `entity_hint`, and locator metadata;
- fake vulnerable graph EDD-summary responses yield stdout containing only the
  leaked flag from `confidential_comment`;
- secure/default metadata-only graph responses fail safely with non-zero exit;
- `scripts/check_competition_matrix_gate.py` marked AML-1, AML-2, and AML-3
  exploit-success concrete while AML-4/AML-5 exploit-success and all fix cells
  remained pending at Wave 21 acceptance time;
- `docs/wave_reports/wave_21_validation_summary.md` records Wave 21 evidence.
  Wave 21 is complete, Wave 22 and Wave 23 are accepted, Wave 24 provides the
  AML-1 fix, Wave 25 provides the AML-2 fix, Wave 26 provides the AML-3 fix,
  Wave 27 provides the AML-4 fix, Wave 28 provides the AML-5 fix, and Wave 29
  is implemented under review for full matrix regression.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave21_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py
python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py
python -B -m py_compile sploits/sentinel_aml/aml_related_graph.py
python -B scripts/check_wave21_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
timeout 300 make wave21-gate
```

## Wave 22 AML-4 Reference Exploit Gate

Wave 22 adds exactly one new reference exploit on top of the accepted AML-1,
AML-2, and AML-3 exploits:
`sploits/sentinel_aml/aml_export_redaction.py`. The script targets only the
accepted AML-4 `aml4_vulnerable` dispute export redaction gap. It accepts host,
port, and public attack-info JSON or a JSON file, registers/logs in as an
attacker, creates attacker-owned duplicate-linked case and dispute state,
creates a normal dispute export, reads the stored export, and prints only the
extracted flag from leaked `bundle.linked_private_notes[].body`.

Wave 22 tests verify:

- exactly `aml_dedup_preview.py`, `aml_audit_timeline.py`,
  `aml_related_graph.py`, and `aml_export_redaction.py` are present under
  `sploits/sentinel_aml/`;
- AML-5 exploit script remained absent at the Wave 22 branch point;
- `fixes/sentinel_aml/` remained README-only at the Wave 22 branch point;
- the AML-4 exploit imports no database drivers, uses no raw SQL, invokes no
  shell process, and does not read checker-private state or public attack-data
  passwords/tokens/sessions;
- the AML-4 exploit expects place 1 `CaseNote.body` attack data with public
  `case_id`, `dedup_hint`, and locator metadata;
- fake vulnerable export responses yield stdout containing only the leaked
  flag from `linked_private_notes[].body`;
- secure/default redacted export responses fail safely with non-zero exit;
- `scripts/check_competition_matrix_gate.py` marks AML-1 through AML-5
  exploit-success concrete on the current branch while AML-1 through AML-5 fix
  cells are concrete in the Wave 28 gate and final readiness remains pending;
- `docs/wave_reports/wave_22_validation_summary.md` records Wave 22 evidence.
  Wave 22 and Wave 23 are accepted. Wave 24 provides the AML-1 fix, Wave 25
  provides the AML-2 fix, Wave 26 provides the AML-3 fix, Wave 27 provides the
  AML-4 fix, Wave 28 provides the AML-5 fix, and Wave 29 is implemented under
  review for full matrix regression.
- W22-T03 documentation alignment is evidence reconciliation only; it does not
  by itself accept Wave 22 or unlock any reference fix wave.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave22_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py
python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py
python -B -m py_compile sploits/sentinel_aml/aml_related_graph.py
python -B -m py_compile sploits/sentinel_aml/aml_export_redaction.py
python -B scripts/check_wave22_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
timeout 300 make wave22-gate
```

## Wave 23 AML-5 Reference Exploit Gate

Wave 23 adds exactly one new reference exploit on top of the accepted AML-1
through AML-4 exploits:
`sploits/sentinel_aml/aml_network_room.py`. The script targets only the
accepted AML-5 `aml5_vulnerable` network-room dossier collaboration leak. It
accepts host, port, and public attack-info JSON or a JSON file, registers/logs
in as an attacker, creates attacker-owned network-room participation, discovers
and joins a normal network room, reads only
`GET /api/network/rooms/{room_id}/dossier`, and prints only the extracted flag
from `foreign_private_notes[].body` or
`foreign_edd_comments[].confidential_comment`.

Wave 23 tests verify:

- exactly `aml_dedup_preview.py`, `aml_audit_timeline.py`,
  `aml_related_graph.py`, `aml_export_redaction.py`, and
  `aml_network_room.py` are present under `sploits/sentinel_aml/`;
- `fixes/sentinel_aml/` remained README-only at the Wave 23 branch point;
- the AML-5 exploit imports no database drivers, uses no raw SQL, invokes no
  shell process, and does not read checker-private state or public attack-data
  passwords/tokens/sessions;
- the AML-5 exploit expects place 2 `EDDRecord` attack data with public
  `customer_id`, `entity_hint`, and `typology_hint` locator data;
- fake vulnerable network-room dossier responses yield stdout containing only
  the leaked flag from the intended dossier fields;
- secure/default redacted dossier responses fail safely with non-zero exit;
- `scripts/check_competition_matrix_gate.py` marks AML-1 through AML-5
  exploit-success concrete. After Wave 28 gate work it marks AML-1 through
  AML-5 fixed-checker, exploit-blocked, and anti-coarse-fix cells concrete
  while final readiness remains pending;
- `docs/wave_reports/wave_23_validation_summary.md` records Wave 23 evidence.
  Wave 23 is accepted. Wave 24 provides the AML-1 fix, Wave 25 provides the
  AML-2 fix, Wave 26 provides the AML-3 fix, Wave 27 provides the AML-4 fix,
  Wave 28 provides the AML-5 fix, and Wave 29 is implemented under review for
  full matrix regression.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave23_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py
python -B -m py_compile sploits/sentinel_aml/aml_audit_timeline.py
python -B -m py_compile sploits/sentinel_aml/aml_related_graph.py
python -B -m py_compile sploits/sentinel_aml/aml_export_redaction.py
python -B -m py_compile sploits/sentinel_aml/aml_network_room.py
python -B scripts/check_wave23_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off python -B scripts/run_aml5_tagged_tests.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
make wave23-gate
```

## Wave 24 AML-1 Reference Fix Gate

Wave 24 adds exactly one reference fix artifact:
`fixes/sentinel_aml/aml_dedup_preview.patch`. The patch restores the
public-only dedup merge-preview projection for the `aml1_vulnerable` tagged
profile while preserving duplicate candidate discovery, merge-preview
availability, and owner case-note APIs. Wave 24 is complete as the prerequisite
for the current Wave 25 review.

Wave 24 tests verify:

- exactly five reference exploits remain present;
- at the Wave 24 branch point, exactly one AML-1 fix artifact exists and AML-2
  through AML-5 fix artifacts remain absent;
- the AML-1 patch applies cleanly and targets only the AML-1 vulnerable profile
  and tagged proof test;
- the accepted `aml_dedup_preview.py` exploit succeeds against the vulnerable
  fixture and fails safely when fixed merge-preview output omits
  `candidate.private_notes`;
- anti-coarse-fix tests reject merge-preview removal, dedup disablement,
  docs-only patches, and gate-constant-only patches;
- checker tests, competition matrix validation, docs-tree validation, ForcAD
  validation, archive hygiene, all five exploit compiles, and release/offline
  Go test/vet remain part of `wave24-gate`;
- W24-F01 requires the aggregate release/offline Go test step to use unique
  temporary `GOCACHE`/`APPDATA` paths, serial package execution, uncached test
  results, and an explicit Go test timeout.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave24_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B -m py_compile sploits/sentinel_aml/aml_dedup_preview.py sploits/sentinel_aml/aml_audit_timeline.py sploits/sentinel_aml/aml_related_graph.py sploits/sentinel_aml/aml_export_redaction.py sploits/sentinel_aml/aml_network_room.py
python -B scripts/check_wave24_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off GOCACHE=$(mktemp -d "${TMPDIR:-/tmp}/sentinel-aml-gocache.XXXXXXXXXX") APPDATA=$(mktemp -d "${TMPDIR:-/tmp}/sentinel-aml-appdata.XXXXXXXXXX") go test -p 1 -timeout 120s -count=1 ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOTELEMETRY=off go vet ./...
make wave24-gate
```

## Wave 25 AML-2 Reference Fix Gate

Wave 25 adds exactly one new reference fix artifact on top of the AML-1 fix:
`fixes/sentinel_aml/aml_audit_timeline.patch`. The patch restores the redacted
audit timeline projection for the `aml2_vulnerable` tagged profile while
preserving audit event existence, timeline functionality, activity-route
guardrails, and owner case-note APIs. Wave 25 is accepted and opens Wave 26 for
the AML-3 reference fix sequence.

Wave 25 tests verify:

- exactly five reference exploits remain present;
- exactly AML-1 and AML-2 fix artifacts exist, with AML-3 through AML-5 fix
  artifacts absent;
- the AML-1 and AML-2 patches apply cleanly;
- the AML-2 patch targets only the AML-2 vulnerable profile and tagged proof
  test;
- `aml_audit_timeline.py` succeeds against vulnerable audit timeline output and
  fails safely against fixed redacted timeline output;
- fixed output preserves `case_note.body` field identity, `[redacted]` values,
  `redacted: true`, audit event existence, and owner note access;
- anti-coarse-fix tests reject `/timeline` removal, `/activity` removal, audit
  disablement, docs-only patches, gate-constant-only patches, and raw-body
  reintroduction;
- checker tests, competition matrix validation, docs-tree validation, ForcAD
  validation, archive hygiene, all five exploit compiles, and release/offline
  Go test/vet remain part of `wave25-gate`.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave25_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B scripts/check_wave25_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
make wave25-gate
```

## Wave 26 AML-3 Reference Fix Gate

Wave 26 adds exactly one new reference fix artifact on top of the AML-1 and
AML-2 fixes: `fixes/sentinel_aml/aml_related_graph.patch`. The patch restores
the public graph EDD-summary projection for the `aml3_vulnerable` tagged
profile while preserving graph entity summaries, related-case summaries,
EDD-summary side views, owner EDD APIs, and unrelated export/network-room
boundedness assertions. Wave 26 is accepted; AML-3 fix cells are concrete and
accepted after orchestrator review, Wave 27 is accepted for AML-4, Wave 28 is
accepted for AML-5, and Wave 29 is implemented under review for full matrix
regression.

Wave 26 tests verify:

- exactly five reference exploits remain present;
- exactly AML-1, AML-2, and AML-3 fix artifacts existed at Wave 26 review time,
  with AML-4 and AML-5 fix artifacts absent;
- the AML-1, AML-2, and AML-3 patches apply cleanly;
- the AML-3 patch targets only the AML-3 vulnerable graph profile, repository
  expansion, and tagged proof test;
- `aml_related_graph.py` succeeds against vulnerable graph EDD-summary output
  and fails safely against fixed public graph output;
- fixed graph output omits `summaries[].confidential_comment` and sensitive
  `CaseNote.body` values while retaining public EDD summary fields and owner
  EDD access;
- anti-coarse-fix tests reject graph endpoint removal, graph disablement,
  docs-only patches, gate-constant-only patches, outside-scope patch targets,
  raw private-field reintroduction, debug/admin paths, direct DB shortcuts, and
  shell helpers;
- checker tests, competition matrix validation, docs-tree validation, ForcAD
  validation, archive hygiene, all five exploit compiles, the package-by-package
  release/offline Go test runner, and release/offline Go vet remain part of
  `wave26-gate`.

Wave 26 documentation recorded implementation under review only until
orchestrator acceptance. Wave 26 is now accepted and unlocked only Wave 27;
Wave 27 is accepted and unlocked only Wave 28; Wave 28 is accepted and unlocked
only Wave 29; Wave 29 remains under review and Wave 30 remains locked.

W26-F01 replaces the prior opaque aggregate Go test line in `wave26-gate` with
`scripts/run_go_release_tests.py`. The helper enumerates `go list ./...`
deterministically, prints each package name before execution, runs each package
with `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, `GOTELEMETRY=off`, and isolated
temporary `GOCACHE`/`APPDATA`, and applies an outer per-package timeout so a
future stall reports the exact package.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave26_gate.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B scripts/check_wave26_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
python -B scripts/run_go_release_tests.py --go go --package-timeout 120
make wave26-gate
```

## Wave 27 AML-4 Reference Fix Gate

Wave 27 adds exactly one new reference fix artifact on top of the AML-1 through
AML-3 fixes: `fixes/sentinel_aml/aml_export_redaction.patch`. The patch turns
the AML-4 tagged export profile into fixed behavior by removing the linked-case
private-note side-view injection and preserving recursive public export
redaction, dispute export creation, stored export readback, linked public case
shells, redaction metadata, and owner-only private note/EDD APIs. Wave 27 is
implemented under review; AML-4 fix cells become accepted only after
orchestrator review, and AML-5 fix work remains locked.

Wave 27 tests verify:

- exactly five reference exploits remain present;
- exactly AML-1 through AML-4 fix artifacts exist, with AML-5 fix artifacts
  absent;
- the AML-1, AML-2, AML-3, and AML-4 patches apply cleanly;
- the AML-4 patch targets only the AML-4 vulnerable export HTTP profile,
  exporting profile, and tagged proof test;
- `aml_export_redaction.py` succeeds against vulnerable export output with
  `bundle.linked_private_notes[].body` and fails safely against fixed public
  export output;
- fixed export output keeps `linked_cases`, public root/linked case summaries,
  `redaction_policy`, and `sensitive_field` evidence while omitting linked
  foreign `CaseNote.body`, EDD confidential comments, internal comments, raw
  audit diffs, hashes, credentials, sessions, debug/admin data, and raw DB rows;
- anti-coarse-fix tests reject export/dispute endpoint removal, export
  disablement, docs-only patches, gate-constant-only patches, outside-scope
  patch targets, raw private-field reintroduction, sensitive-field renames,
  direct DB shortcuts, and shell helpers;
- checker tests, Wave 27 gate tests, runner liveness tests, competition matrix
  validation, docs-tree validation, ForcAD validation, archive hygiene, all
  five exploit compiles, the package-by-package release/offline Go test runner,
  and release/offline Go vet remain part of `wave27-gate`.

Wave 27 documentation records implementation under review only. It does not
claim competition readiness or unlock AML-5 until exact aggregate-gate
acceptance evidence is present from orchestrator review.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave27_gate.py"
python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B scripts/check_wave27_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
python -B scripts/run_go_release_tests.py --go go --package-timeout 120
make wave27-gate
```

## Wave 28 AML-5 Reference Fix Gate

Wave 28 adds the fifth and final individual reference fix artifact:
`fixes/sentinel_aml/aml_network_room.patch`. The patch restores network-room
dossier reference/public projection semantics for the AML-5 tagged profile while
preserving room discovery, joins, public summaries, participant-scoped dossiers,
and checker owner PUT/GET flows. Wave 28 makes AML-5 fixed-checker,
exploit-blocked, and anti-coarse-fix evidence concrete in validation, but it
does not claim competition readiness; the full regression matrix and packaging
validation remain a later wave.

Wave 28 tests verify:

- exactly five reference exploits remain present;
- exactly AML-1 through AML-5 reference fix patches exist, with no nonstandard
  extra fix files;
- all five patches apply cleanly with `git apply --check --whitespace=error`;
- the AML-5 patch targets only tagged network-room profile/repository/proof
  files;
- `aml_network_room.py` still succeeds against vulnerable dossier output and
  fails safely against fixed public/reference-only dossier output;
- fixed network-room dossiers keep room/case public summaries,
  `owned_by_requester`, `private_data_omitted`, `references_only`, and `omitted`
  policy evidence while omitting foreign notes, EDD confidential comments, raw
  audit diffs, hashes, credentials, sessions, checker-private state, debug/admin
  output, and raw DB rows;
- anti-coarse-fix tests reject network-room endpoint removal, join/dossier
  disablement, worker removal, docs-only patches, gate-constant-only patches,
  outside-scope patch targets, sensitive-field renames, direct DB shortcuts, and
  shell helpers;
- checker tests, Wave 28 gate tests, runner liveness tests, competition matrix
  validation, docs-tree validation, ForcAD validation, archive hygiene, all five
  exploit compiles, the package-by-package release/offline Go test runner, and
  release/offline Go vet remain part of `wave28-gate`.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_wave28_gate.py"
python -B -m unittest discover -s tests -p "test_run_go_release_tests.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B scripts/check_wave28_gate.py
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_docs_tree.py
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
python -B scripts/run_go_release_tests.py --go go --package-timeout 120
make wave28-gate
```

## Wave 29 Full Competition Matrix Gate

Wave 29 adds the single full competition matrix gate after the individual
reference exploit and reference fix waves. It validates the whole A/D matrix
together and does not mark final release readiness; final packaging and release
review remain later work.

W29-T03 records Wave 29 as implemented under review after W29-T01 and W29-T02
evidence. Wave 30 remains the only next step, and it is limited to final
packaging, release validation, source-of-truth freeze, and reproducibility
checks after Wave 29 orchestrator acceptance.

Wave 29 tests verify:

- all checker unittest discovery terminates and passes;
- the current competition matrix has concrete vulnerable-checker,
  exploit-success, fixed-checker, exploit-blocked, and anti-coarse-fix cells for
  AML-1 through AML-5;
- exactly five reference sploits compile without repository-local bytecode;
- all five reference fix patches apply cleanly;
- focused vulnerable-profile package tests run under bounded release/offline
  tagged Go commands for AML-1 through AML-5:
  `./internal/httpapi` for AML-1 and AML-2,
  `./internal/httpapi ./internal/graph` for AML-3,
  `./internal/httpapi ./internal/exporting` for AML-4, and
  `./internal/httpapi ./internal/networkroom` for AML-5;
- all five reference fix patches retain exploit-blocked and feature-preserved
  evidence;
- anti-coarse-fix checks reject endpoint removal, feature disabling,
  docs-only patches, gate-only patches, sensitive-field renames, debug/admin
  shortcuts, and direct DB shortcuts;
- checker PFR still uses place 1 `CaseNote.body` and place 2
  `EDDRecord.confidential_comment`, with public attack data remaining
  credential-free.

Run:

```sh
python -B -m unittest discover -s tests -p "test_checker_*.py"
python -B -m unittest discover -s tests -p "test_competition_matrix_gate.py"
python -B -m unittest discover -s tests -p "test_wave29_gate.py"
python -B scripts/check_competition_matrix_gate.py
python -B scripts/check_wave29_gate.py
make wave29-gate
```

W29-F01 originally removed duplicate full tagged `go test ./...` sweeps, but
W30-F01 further stabilizes the final aggregate target after orchestrator review
reproduced a 300-second timeout at the AML-2 tagged test. `wave29-gate` now
runs `scripts/run_vulnerable_profile_tests.py` for the five focused vulnerable
profile checks with one shared out-of-repository Go cache/appdata pair for the
aggregate invocation. `scripts/run_go_release_tests.py` likewise reuses one
out-of-repository Go cache/appdata pair across the untagged package-by-package
release/offline runner while preserving per-package timeout handling and
diagnostic package names. The gate still keeps all sploit compile checks, all
patch apply checks, checker tests, matrix tests, docs-tree, ForcAD, archive
hygiene, and the Wave 29 regression runner. W30-F01 recorded the final
settled-tree exact GNU-style `timeout 300 make wave29-gate` command exiting 0
in 3m39.837s on the WSL review path.

## Wave 29 End-to-End Regression Evidence

W29-T02 adds `scripts/check_wave29_regression.py` as the reproducible
end-to-end evidence runner for combinations across the finished matrix. It
keeps temporary patch/build/test artifacts outside the repository, applies the
five reference fix patches in sequence in a clean temporary checkout, and
validates each matching fixed tagged proof plus checker regression on the
cumulative fixed checkout before deleting the temporary tree.

W29-F01 also makes the regression runner emit progress and elapsed seconds for
each section. In mixed WSL/Linux-Python plus Windows `go.exe` environments, the
temporary patched checkout is created on the `/mnt/c` project drive instead of
WSL `/tmp`, avoiding Windows Go `go.mod` locking failures on
`\\wsl.localhost` paths.

The regression runner verifies:

- checker PUT/GET and CHECK/HAVOC regression tests still pass;
- current competition-matrix and Wave 29 full-gate Python evidence still pass;
- all five accepted reference sploits compile with repository bytecode disabled;
- AML-1 through AML-5 vulnerable build tags pass independently before any patch
  application;
- each AML-1 through AML-5 reference fix patch applies in the clean temporary
  copy and its focused fixed-profile proof passes;
- checker regression remains green as the cumulative fixed service evolves.

Run:

```sh
python -B -m unittest discover -s tests -p "test_wave29_regression.py"
python -B scripts/check_wave29_regression.py
python -B scripts/check_archive_hygiene.py
python -B scripts/validate_forcad_config.py
```

## Wave 30 Final Validation Evidence

Wave 30 records final release-review evidence without changing implementation
contracts or claiming competition readiness before orchestrator acceptance. The
final validation pass is owned by one single final acceptance command:
`timeout 300 make wave30-gate`. The target delegates to the accepted Wave 29
aggregate matrix/regression gate, then runs the competition matrix gate, Wave 30
static target validation, ForcAD config validation, archive hygiene, and the
release archive builder introduced by W30-T02.

Final validation evidence recorded in
`docs/wave_reports/wave_30_final_validation_summary.md` covers:

- checker PUT/GET and CHECK/HAVOC for both active places;
- AML-1 through AML-5 vulnerable-profile and exploit-success evidence;
- AML-1 through AML-5 fixed-checker, exploit-blocked, and anti-coarse-fix
  evidence;
- all five accepted sploit compile checks and all five reference patch apply
  checks;
- ForcAD `pfr` config shape and archive hygiene;
- release archive generation with required checker, sploit, fix, config,
  source, migration, test, vendor, and documentation inventory.

W30-F01 supersedes the earlier local Wave 30 aggregate timing evidence after
orchestrator review reproduced a timeout. It stabilizes the delegated
matrix/regression command, `timeout 300 make wave29-gate`; the liveness fix
changes only release-gate caching and helper structure, not product behavior or
evidence coverage.

W30-F02 adds `wave30-gate` as the release-readiness owner. It does not replace
or remove Wave 29 evidence; it wraps the stabilized `wave29-gate` and adds
Wave 30 target validation plus final release archive generation. Wave 30 is
accepted only after exact `timeout 300 make wave30-gate` success under
orchestrator review. It does not claim final competition readiness. No future
feature wave is unlocked by Wave 30 acceptance; only final release-candidate
handoff/package promotion remains.

W31-F01 hardens the final aggregate gate after orchestrator review observed
`/usr/bin/timeout 300 make wave30-gate` stalling in
`scripts/run_vulnerable_profile_tests.py`. The vulnerable-profile runner now
uses the same process-tree-aware command runner as release/offline Go package
tests, keeps one out-of-repository GOCACHE/APPDATA pair for the five focused
AML-1 through AML-5 tagged scenarios, and caps each child command with an outer
timeout of `min(package_timeout + 30, 45)` seconds. The Go test command still
uses the existing `-timeout 120s` profile argument from `wave29-gate`; the
additional outer cap exists only to terminate stuck child processes with
diagnostics before the 300-second final gate is exhausted.

Agent validation on 2026-09-05 ran `/usr/bin/timeout 300 make wave30-gate`
successfully in 3m49.270s on the WSL GNU-timeout/make path. This evidence
stabilizes the final aggregate gate for orchestrator review, but it does not
issue the final release candidate or claim final competition readiness.

Run:

```sh
timeout 300 make wave30-gate
make competition-matrix-gate
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
make release-archive
```

## Archive-Free Stability Gate

`make ad-stability-gate` is the reproducible service stability gate. It proves
the checker, competition matrix, accepted reference sploits, reference fixes,
vulnerable profiles, release-profile Go tests, Go vet/build, documentation
tree, and ForcAD configuration without producing package artifacts.

The aggregate runner owns liveness as part of the evidence. It runs every phase
through the process-tree-aware command helper, prints per-phase timing and
remaining aggregate budget, reuses one out-of-repository Go cache/appdata pair
for the Go-heavy phases, and fails before the outer 300-second review wrapper is
exhausted.

The stability gate is intentionally archive-free: it does not build release
archives, player bundles, final manifests, or checksums. It also avoids the
archive hygiene/package evidence path so service behavior and liveness failures
are separated from release packaging concerns.

Release/package gates remain responsible for archive generation, player
bundles, final manifests, and checksums. `wave30-gate` stays the historical
final aggregate gate that delegates to earlier behavior evidence and then runs
release archive creation; `ad-stability-gate` is the narrower stability command
to use when the question is whether service/checker/sploit/fix behavior is
green independent of final packaging.

Run:

```sh
timeout 300 make ad-stability-gate
```

## Wave 33 Productization Gate

`make wave33-gate` is the archive-free Wave 33 regression gate for the
player/admin candidate split. It validates candidate tree generation, player
hygiene scans, participant-doc hygiene, checker tests, competition matrix
validation, all five sploit syntax checks, all five fix patch checks,
vulnerable-profile tests, release-profile Go tests, Go vet/build, docs-tree,
and ForcAD configuration. It does not build final release archives, player
release archives, final manifests, or checksums.

The Wave 33 runner uses the same bounded aggregate model as
`ad-stability-gate`: a single process-tree-aware Python runner, shared
out-of-repository Go cache/appdata for Go-heavy phases, a gate-local compatibility
shim for POSIX hosts that expose `python3` but not `python`, and explicit
per-phase elapsed/remaining timing output. W33-F04 hardens the shared process
runner so descendants cannot keep stdout/stderr pipes open after their parent
process has exited; this keeps the aggregate bounded even when a child prints
successful unittest output and an inherited handle would otherwise keep the
wrapper waiting.

On 2026-09-10 the exact WSL review command exited `0` after W33-F05 with host
elapsed `139.731s` and runner elapsed `139.245s`. The gate remained
archive-free and ran strict repository-submission hygiene, player/admin
candidate generation, local-staging repository hygiene, player hygiene, checker
tests, competition matrix validation, all five sploit syntax checks, all five
fix patch checks, vulnerable-profile tests, release-profile Go tests, Go
vet/build, docs-tree, ForcAD validation, and generated-candidate cleanup.

Run:

```sh
/usr/bin/timeout 300 make wave33-gate
```

Wave 33 distinguishes five artifact classes:

- Organizer repository: the full internal working tree with checker, sploits,
  fixes, vulnerable-profile evidence, tests, scripts, docs, and reports.
- Review submission archive: a snapshot submitted for orchestrator review; it
  must not contain repo-local generated candidates, bytecode caches, Go caches,
  appdata caches, or other scratch output.
- Generated candidate directory: ignored local `tmp/*candidate*` output created
  during Wave 33 gates for inspection and hygiene scanning only.
- Player artifact: a future promoted package or image for teams; Wave 33 does
  not issue one.
- Admin/checker artifact: a future operator package for checker execution;
  Wave 33 only stages a candidate tree.

Repository-submission hygiene is checked separately from player-bundle hygiene:

```sh
python -B scripts/check_repository_submission_hygiene.py
python -B scripts/check_repository_submission_hygiene.py --allow-wave33-local-candidates
```

The strict form is for submitted repository archives or extracted submission
trees and fails on `__pycache__/`, `.pyc`, `.gocache*`, `.appdata*`, and
generated `tmp/*candidate*` entries. The explicit local-staging form permits the
known ignored Wave 33 candidate directories and allowlist sidecars while a gate
is running; it still rejects bytecode and cache artifacts.

`wave33-gate` exercises both forms deterministically. It runs the strict
repository-submission hygiene check before local candidate generation, builds
the player/admin candidate trees under ignored `tmp/` paths, then runs the
local-staging check with `--allow-wave33-local-candidates` before player-bundle
hygiene. The final phase removes only the known Wave 33 generated candidate
paths so a completed gate leaves the repository ready for the strict submission
check again. The local-staging mode is not valid for submitted archives.

Player source runtime readiness remains blocked in Wave 33. Current player
package metadata is neutral and operational, while future packaging must pass
the stricter runtime guard by proving either offline source build/start with
required dependencies and deployment files, or binary/image delivery with no
source leakage:

```sh
python -B scripts/check_player_bundle_hygiene.py tmp/wave33-player-service-candidate --allowlist tmp/wave33-player-service-candidate.hygiene-allowlist.json --require-runtime-ready
```

That command is expected to fail until a later packaging wave records
successful runtime proof.

## Wave 34 Product-Facing Source Hardening

Wave 34 keeps the Wave 33 artifact boundary, tightens generated player source
vocabulary, and proves the source-delivery runtime path. `scripts/build_player_bundle.py`
now stages product-neutral policy filenames and helper identifiers in the player
candidate instead of exposing internal build-profile names. It also removes the
previous Go CLI `flag` exception from generated source, so the hygiene allowlist
generated for the player candidate is empty.

The player hygiene scanner fails a candidate when source files expose the known
internal build-profile path or identifier patterns. This scanner still runs on
candidate trees or archives, not the organizer repository, so checker, sploit,
fix, vulnerable-profile, and wave evidence remain preserved internally.

Wave 34 defined the competition runtime build profile explicitly. W33-AF4
reconciles that profile guard with the safer binary/OCI player-delivery
strategy. The default organizer `make build` target remains the secure/default
baseline. The internal competition runtime uses `COMPETITION_TAGS`:

```sh
case_match_preview audit_detail_view entity_review_summary linked_case_export_detail network_room_detail
```

The canonical competition runtime build command is:

```sh
make competition-runtime-build
```

This target builds `./cmd/aml-api`, `./cmd/aml-worker`, and `./scripts/migrate`
with `-tags "$(COMPETITION_TAGS)"` using vendored dependencies and
out-of-repository Go cache/appdata directories. The binary player artifact is
built from the same internal competition runtime profile, but the player
archive itself does not expose CTF labels or source-level policy names.

The runtime-profile guard defaults to binary mode:

```sh
python -B scripts/check_competition_runtime_profile.py --mode binary \
  --player-manifest out/manifests/player_manifest.json \
  --player-artifact out/artifacts/sentinel-aml-player-service.tar.gz
```

The guard fails if any neutral competition policy tag is missing from the
internal runtime build, if legacy `aml*_vulnerable` aliases become the
canonical build vocabulary, if the player manifest does not identify
`binary-image` or OCI delivery, if built `aml-api`, `aml-worker`, or
`aml-migrate` runtime members are missing, if player bytes include Go source,
if exact-artifact runtime proof policy is absent, or if the manifest says CTF
labels are exposed in the player artifact. Historical package proof reports are
context only for this guard; newly generated player bytes are proven either by
runtime evidence that names the current player artifact SHA-256 or by the
artifact-local proof contract that requires
`out/artifact-first-validation-summary.json` to stamp the player/admin SHA-256s
and live/external runtime statuses.

Source player mode exists only as an explicit opt-in:

```sh
python -B scripts/check_competition_runtime_profile.py --mode source \
  --player-manifest path/to/player_manifest.json \
  --player-artifact path/to/source-player.tar.gz
```

In source mode the flattened source artifact must contain only the selected
competition behavior, must not carry dual default/detail policy source pairs,
must include runtime evidence, and its Dockerfile/build command must not
silently compile the secure/default baseline.

Run the focused W34 checks:

```sh
python -B scripts/build_artifacts.py --output-root out
python -B scripts/check_competition_runtime_profile.py --mode binary --player-manifest out/manifests/player_manifest.json --player-artifact out/artifacts/sentinel-aml-player-service.tar.gz
python -B -m unittest discover -s tests -p "test_competition_runtime_profile.py"
```

## Final Split-Package Gate

`make final-split-package-gate` validates the final split-package boundary
without creating final archives. The gate keeps three artifact statuses
separate:

- `player-service`: runtime-proven source candidate plus final player hygiene
  with `--require-runtime-ready`;
- `admin/checker`: exact operator candidate inventory, copied ForcAD config,
  checker requirements, and no reference attack/fix or sample-secret material;
- `organizer-internal`: archive-free A/D stability gate, archive hygiene,
  repository-submission hygiene, docs tree, and root ForcAD config.

The gate stages temporary candidates only under ignored `tmp/` paths and cleans
them before archive hygiene. It does not create final archives, release
archives, manifests, checksums, or image pushes.

On 2026-09-08 the exact WSL review command exited `0` with host elapsed
`147.199s` and runner elapsed `146.706s`. In the mixed WSL/Windows toolchain
environment, `make` resolved to `python3`, `go.exe`, and `docker.exe`; the
player runtime proof delegated that one package-smoke phase to Windows
PowerShell so Docker, Go, and API loopback health checks ran on the same host.
The final output reported `player-service`, `admin-checker`, and
`organizer-internal` statuses as `pass` and `final_archives_created: false`.

Run:

```sh
/usr/bin/timeout 300 make final-split-package-gate
```

## Artifact-First Build Outputs

`make artifacts` builds exact transfer artifacts under `out/` instead of
mixing package proof with `tmp/` staging directories. The target cleans
`out/artifacts/`, `out/manifests/`, and `out/checksums/`, stages inputs in an
external temporary directory, then writes stable audience-labelled archives:

- `out/artifacts/sentinel-aml-player-service.tar.gz`;
- `out/artifacts/sentinel-aml-admin-organizer.tar.gz`;
- `out/manifests/player_manifest.json`;
- `out/manifests/admin_manifest.json`;
- `out/checksums/SHA256SUMS`.

The player artifact is derived from the sanitized player-service builder. The
admin/organizer artifact preserves internal checker, sploit, fix, test, docs,
gate, and CHECK/HAVOC evidence while excluding generated scratch/output such as
`tmp/`, `temp/`, `out/`, caches, archives, frontend build output, and local
dependency installs.

The focused gate is:

```sh
python -B scripts/check_artifacts.py --run
python -B scripts/build_artifacts.py --output-root out
python -B scripts/build_artifacts.py --output-root out --verify-only
```

The check script proves clean output handling, manifest/archive inventory
matching, checksum-byte matching, stale generated file cleanup, and missing
artifact detection without depending on repo-local `tmp/` leftovers. These
outputs are packaging artifacts for review; they do not by themselves claim
final competition readiness or replace orchestrator acceptance.

## Artifact-Byte Hygiene Gate

`scripts/check_artifact_hygiene.py` scans the exact transfer archive bytes, not
only source directories or stale staging paths. The runner accepts explicit
artifact paths:

```sh
python -B scripts/check_artifact_hygiene.py \
  --player-artifact out/artifacts/sentinel-aml-player-service.tar.gz \
  --admin-artifact out/artifacts/sentinel-aml-admin-organizer.tar.gz
```

The player side strips the stable transfer root before scanning archive
members, then rejects checker/sploit/fix/test/script/doc paths, source maps,
CTF/vulnerability-map vocabulary, internal build-profile source vocabulary,
dual-policy source names, path traversal, and local/generated/cache artifacts
such as `node_modules/`, `__pycache__/`, `.tsbuildinfo`, `tmp/`, and
`.gocache*`.

The admin side has separate rules for the narrow admin/checker candidate and
the full admin/organizer transfer artifact. The full transfer artifact must
preserve checker, sploit, fix, test, wave-evidence, and CHECK/HAVOC material,
but it still rejects accidental local/generated/cache artifacts. The synthetic
coverage lives in `tests/test_artifact_hygiene.py`.

Current W33-AF2 local scan result: the player artifact passes, and the
admin/organizer artifact must pass after `make clean-generated` and artifact
rebuild excludes frontend TypeScript build info files. That generated-cache
class remains forbidden and is not allowlisted.

## Aggregate Artifact-First Gate

`make artifact-first-gate` is the Wave 33 aggregate gate for transfer-artifact
review. It uses the same canonical player artifact contract as
`make artifact-gate`: `player-service-with-ui.v1`, a single player artifact
containing backend binaries plus participant UI runtime files. The intended
bounded command is:

```sh
/usr/bin/timeout 300 make artifact-first-gate
```

The gate runs generated-output cleanup while preserving the prebuilt frontend
UI dist needed for transfer packaging, builds the player-service and
admin/organizer transfer artifacts under `out/`, verifies manifests/checksums,
scans the exact player and admin archive bytes, optionally scans
`REPOSITORY_SUBMISSION` when a submitted repository archive is supplied, and writes
`out/artifact-first-validation-summary.json`.

The aggregate runner creates both transfer artifacts in one
`build_artifacts.py` build phase and then runs one `--verify-only` inventory
phase. This keeps the build-then-test-transfer-bytes ordering without repeating
the same expensive manifest/checksum verification work.

The player UI check is mandatory. `artifact-gate` and `artifact-first-gate`
both run `npm --prefix frontend run security:scan:source` and
`npm --prefix frontend run security:scan:dist` before building transfer
artifacts. A gate cannot pass with `ui not applicable`: the player archive,
`player_manifest.json`, and `PACKAGING_STATUS.json` must agree that
`participant-ui` is required and included, and the archive must contain
`ui/index.html` and `ui/runtime-config.js`. The manifest lists the exact UI
bytes delivered under `sentinel-aml-player-service/ui/`, and checksum evidence
covers the resulting player tarball and manifest. Live runtime smoke and
checker/sploit/fix matrix execution against a deployed player runtime are
recorded in the summary as `external-required` when they are not run in the
bounded local byte-validation pass. The summary also stamps the player artifact
SHA-256, admin artifact SHA-256, runtime smoke status, checker CHECK/HAVOC
status, five-sploit status, five-fix workflow status, and matrix status.
`PACKAGING_STATUS.json` stays player-facing by recording operational package
contents and runtime requirements; exact-artifact runtime proof remains in the
external validation summary when live validation is not run locally. This gate
validates transfer artifacts and known live obligations; it does not make final
release acceptance claims.

The repository-submission handoff archive is built separately from player/admin
transfer artifacts:

```sh
python -B scripts/build_repository_submission.py --output out/repository-submission/sentinel-aml-repository-submission.zip .
python -B scripts/check_repository_submission_hygiene.py out/repository-submission/sentinel-aml-repository-submission.zip
```

The builder is allowlist-first for reviewed source/evidence paths, excludes
generated transfer archives and local cache/build output, and validates the
exact zip bytes it writes. A dirty local working tree can contain generated
`out/`, `tmp/`, `validation/`, frontend build/install output, or bytecode
caches without those files being confused with repository-submission readiness.

## Exact-Artifact Live Acceptance

FH-05 adds an opt-in live acceptance runner for the transfer artifacts produced
under `out/artifacts/`. It deploys the extracted
`sentinel-aml-player-service.tar.gz` player package, runs CHECK/HAVOC and
PUT/GET through the checker extracted from
`sentinel-aml-admin-organizer.tar.gz`, runs all five extracted reference
sploits, and applies each extracted reference fix in an isolated admin-artifact
source copy to prove the sploit is blocked while CHECK still passes.
The fixed-service live deployment applies production hunks from the extracted
patches and excludes `*_test.go` hunks so review-era test edits do not become a
substitute for runtime proof.

```sh
make exact-artifact-live-acceptance
```

The machine-readable result is
`out/exact-artifact-live-acceptance-summary.json`. The summary binds every
pass/fail verdict to the exact player/admin archive SHA-256 values and records
`historical_candidate_tree_substitute: false` for the live matrix result.

## Wave 09 Gate Coverage

`scripts/check_wave09_gate.py` validates the historical Wave 09 branch state:

- migration ordering through `000007_create_entity_graph.sql`;
- graph tables remain limited to safe entity metadata and relation edges;
- `internal/graph` repository summaries and query methods avoid private note, EDD narrative, audit, auth/session, checker-private, trace, owner, and raw-row fields;
- retained owner workflow routes plus only the secure graph routes `GET /api/graph/entities/{entity_hint}`, `GET /api/graph/entities/{entity_hint}/related-cases`, and `GET /api/graph/entities/{entity_hint}/edd-summaries`;
- `GraphEntityView`, `GraphRelatedCaseView`, and `EDDGraphSummaryView` DTOs match the projection allowlists;
- Anti-AML-3 HTTP, projection, and source guard tests exist;
- exploit and reference-fix scripts remain absent;
- checker, public attack-data, export, network, `/api/entities`, graph-root, debug, and admin route expansion remains absent;
- Wave 09 handoffs, `wave_09_validation_summary.md`, docs tree, and ForcAD config validators pass.

Run the Wave 09 current branch gate:

```sh
python -B scripts/check_wave09_gate.py
make wave09-gate
```

## Live Integration Gate

The default unit test path remains DB-free unless `SENTINEL_AML_INTEGRATION_DATABASE_URL` is set.

Start the local integration database:

```sh
docker compose up -d postgres
```

Run the live gate:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresMigrationAuthIntegration -count=1
```

Run the Wave 03 live owner API gate:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresWave03OwnerAPIIntegration -count=1
```

Run the Wave 03 live domain persistence gate:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./tests -run TestWave03LivePostgresDomainRepositories -count=1
```

Run the Wave 04 live investigation persistence gate:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./tests -run TestWave04LivePostgresInvestigationRepositories -count=1
```

Run the Wave 04 live risk/alert generation gate:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./tests -run TestWave04LivePostgresRiskAlertGeneration -count=1
```

Run the Wave 04 live owner investigation API gate:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresWave04InvestigationAPIIntegration -count=1
```

Run the Wave 05 live EDD API gate:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresWave05EDDAPIIntegration -count=1 -v
```

Or run the grouped Wave 04 live target after starting PostgreSQL:

```sh
make postgres-up
make live-wave04-integration
```

Or run the grouped Wave 05 live target after starting PostgreSQL:

```sh
make postgres-up
make live-wave05-integration
```

If `SENTINEL_AML_INTEGRATION_DATABASE_URL` is unset, the live test skips with a clear message. When set, it resets only the target database schema named by that URL.

The Wave 02 and Wave 03 live tests both reset the same configured schema. Run the named live gates separately, or serialize package execution with `go test -p 1 ./...` when enabling `SENTINEL_AML_INTEGRATION_DATABASE_URL` for a full package sweep.

## Maintenance Test Direction

Later work should keep the existing backend stability, checker, sploit/fix,
packaging, and frontend UI gates separated by ownership. UI-only waves should
run the frontend clean gate and document backend changes as none. Backend,
checker, exploit, fix, packaging, or competition-runtime changes must run their
nearest source-of-truth gate before broader aggregate validation.
