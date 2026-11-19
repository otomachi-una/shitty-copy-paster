# Sentinel AML — Deployment

Wave 02 defines local developer commands and the first PostgreSQL migration hook, but not a full production deployment package.

## Go Toolchain

The supported local/offline Go baseline is Go 1.22+. `go.mod` pins the language version to `go 1.22.0` and does not include a `toolchain` directive, so review and competition test runs must not download a newer Go toolchain.

Go dependencies are source-controlled under `vendor/`. Review and competition commands must use vendor mode instead of downloading modules or relying on a pre-populated module cache.

Offline review commands:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go vet ./...
```

On Windows hosts where the default Go build cache is not writable, set `GOCACHE` to a writable temporary directory while keeping `GOTOOLCHAIN=local`.

For clean dependency verification, the same commands can be run with a fresh `GOMODCACHE` and `GOPROXY=off`; vendor mode should not attempt network module downloads.

## Archive Hygiene

Competition and review archives must contain source, tests, docs, vendored Go
dependencies, migrations, checker files, and sploit/fix placeholder structure
only. They must not include local cache, telemetry, IDE, bytecode, or OS
metadata artifacts.

Forbidden archive artifacts include:

- `.gocache*/`
- `.gotelemetry/`
- `.appdata*/`
- `.idea/`
- `.vscode/`
- `__pycache__/`
- `.pytest_cache/`, `.mypy_cache/`, and `.ruff_cache/`
- `*.pyc` and `*.pyo`
- `coverage.out`, `.coverage*`, and `*.coverprofile`
- temporary archives such as `*.zip`, `*.tar`, `*.tar.gz`, and `*.tgz`
- `.DS_Store` and `Thumbs.db`

Run the archive hygiene gate before creating or submitting a bundle:

```sh
python -B scripts/check_archive_hygiene.py
```

The gate scans the repository snapshot while ignoring `.git/` internals. A
clean archive must preserve the required CTF layout, including
`checkers/sentinel_aml/`, `sploits/sentinel_aml/`, and `config.yml`, without
shipping machine-local caches or editor state.

## Release Archive Packaging

Wave 30 adds a deterministic release archive builder. The builder writes the
archive outside the repository by default, normalizes tar metadata, excludes
local cache/editor/bytecode/archive scratch paths, excludes archived foreign
material under `docs/archive/`, and validates the generated artifact before
returning success.

Build the release archive:

```sh
make release-archive
```

Equivalent direct command:

```sh
python -B scripts/build_release_archive.py --output-dir "${TMPDIR:-/tmp}/sentinel-aml-release"
```

Validate the generated archive, not only the working tree:

```sh
python -B scripts/check_archive_hygiene.py "${TMPDIR:-/tmp}/sentinel-aml-release/sentinel_aml_release.tar.gz"
```

The release archive must contain the required A/D review artifacts:

- `checkers/sentinel_aml/checker.py`
- `checkers/sentinel_aml/checker_lib.py`
- `checkers/sentinel_aml/requirements.txt`
- all five `sploits/sentinel_aml/*.py` reference sploits
- all five `fixes/sentinel_aml/*.patch` reference fixes
- `config.yml`
- `docker-compose.yml`
- Go source, migrations, tests, vendor tree, and canonical docs required for
  review.

Current release wave gates that run Go commands must keep Go build cache and
application-data scratch paths outside the deliverable tree or remove them
before archive validation. `make wave18-gate` uses release-scoped cache
locations outside the repository and then runs `scripts/check_archive_hygiene.py`
as part of the closure gate.

## Current Commands

```sh
make build
make test
make vet
make toolchain-gate
make wave03-gate
make release-archive
make postgres-up
make live-auth-integration
make live-wave03-integration
make run-api
make run-worker
python -B scripts/validate_forcad_config.py
python -B scripts/check_archive_hygiene.py
python -B scripts/check_wave03_gate.py
make wave18-gate
go run ./scripts/migrate
python -B scripts/runtime_smoke.py
```

## Database Configuration

`DATABASE_URL` is the runtime PostgreSQL connection string used by `internal/config.DatabaseFromEnv` and `internal/db.Open`.

The current migration command is:

```sh
DATABASE_URL=postgres://user:pass@host:5432/sentinel_aml?sslmode=disable go run ./scripts/migrate
```

The migration runner uses the `pgx` standard-library driver. SQL shape and repository behavior are validated deterministically in tests, and a live PostgreSQL path is available for integration review.

## Local PostgreSQL Integration Gate

Start the dedicated local PostgreSQL service:

```sh
docker compose up -d postgres
```

Run the live migration/auth integration test:

```sh
SENTINEL_AML_INTEGRATION_DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./internal/httpapi -run TestLivePostgresMigrationAuthIntegration -count=1
```

PowerShell form:

```powershell
$env:SENTINEL_AML_INTEGRATION_DATABASE_URL = "postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable"
$env:GOTOOLCHAIN = "local"
$env:GOFLAGS = "-mod=vendor"
go test ./internal/httpapi -run TestLivePostgresMigrationAuthIntegration -count=1
```

The test skips with a clear message when `SENTINEL_AML_INTEGRATION_DATABASE_URL` is unset. When set, it resets the target database schema, applies repository migrations from `migrations/`, registers an analyst through `POST /api/auth/register`, logs in through `POST /api/auth/login`, calls `GET /api/auth/me` with a bearer token, confirms unauthenticated `/api/auth/me` fails closed, and verifies sensitive hash fields are not serialized.

## Runtime Smoke

Wave 32 provides an archive-free runtime smoke command:

```sh
python -B scripts/runtime_smoke.py
```

The command uses these defaults:

```text
DATABASE_URL=postgres://sentinel:sentinel@localhost:54329/sentinel_aml_test?sslmode=disable
SENTINEL_AML_RUNTIME_SMOKE_URL=http://127.0.0.1:18080
```

It runs `docker compose up -d postgres`, waits for PostgreSQL health, applies
migrations with `go run ./scripts/migrate`, starts the API with `go run
./cmd/aml-api -addr 127.0.0.1:18080`, runs `go run ./cmd/aml-worker` twice,
checks `/healthz`, and executes normal authenticated customer, account,
transaction, alert, case-note, EDD, timeline, graph, and network-room-list
HTTP flows. It uses normal analyst credentials created during the smoke and
does not use checker-private credentials, direct DB writes, debug routes, or
hidden admin helpers.

The PostgreSQL host port is configurable through the database URL. When the
default host port is unavailable, set both the URL port and compose port to the
same value:

```powershell
$env:DATABASE_URL = "postgres://sentinel:sentinel@localhost:55432/sentinel_aml_test?sslmode=disable"
$env:SENTINEL_AML_POSTGRES_PORT = "55432"
python -B scripts/runtime_smoke.py
```

If Docker is unavailable, the command fails clearly. For local dependency
probing only, a non-acceptance skip mode is available:

```sh
python -B scripts/runtime_smoke.py --skip-if-docker-unavailable
```

Exit code `77` means Docker/PostgreSQL was unavailable and does not satisfy
full runtime-smoke acceptance. Full acceptance requires exit code `0` from the
primary command in the target environment or an explicit orchestrator waiver.

## Current ForcAD Layout

- `config.yml`
- `checkers/sentinel_aml/`
- `sploits/sentinel_aml/`

## Open Items

Production container layout, production environment variables, retention configuration, checker runtime packaging, and production hardening remain future work.
