# W34-P04 Source-Based Docker Compose Runtime

## Summary

W34-P04 makes the canonical player source artifact self-contained for Docker Compose runtime validation. The generated package now provides a root `docker-compose.yml`, a multi-stage source-building `Dockerfile`, participant-safe Make targets, and runtime docs that describe how to run and rebuild without requiring organizer-only files.

Artifact checked:

```text
out/artifacts/sentinel-aml-player-source.tar.gz
```

SHA-256:

```text
c2c64d50075977bff48032d25c843e54172fdc97e7bc7468959426d031348f5c
```

## Runtime Implementation

The generated Compose stack includes:

- `postgres`
- `aml-migrate`
- `aml-api`
- `aml-worker`
- `aml-ui`

`aml-migrate`, `aml-api`, and `aml-worker` build from the `runtime` Dockerfile target. `aml-ui` builds from the `ui` target, which copies frontend build output from the Docker build stage into an nginx image and proxies API/health requests to `aml-api`. This avoids any host dependency on `frontend/dist`.

The generated Makefile exposes participant-safe commands:

```bash
make up
make down
make logs
make rebuild
make smoke
```

## Runtime Checker

Added:

```bash
python -B scripts/check_player_source_runtime.py out/artifacts/sentinel-aml-player-source.tar.gz
```

The checker:

- unpacks the exact tarball into a clean temporary directory;
- validates required services, source build targets, Make targets, docs, and absence of organizer-only runtime references;
- runs `docker compose config`, `docker compose build`, and `docker compose up -d` when Docker is available;
- smokes API and UI endpoints;
- always attempts `docker compose down --remove-orphans -v` cleanup after live startup;
- returns explicit `external-required` when Docker CLI, Compose, or daemon access is unavailable.

## Live Evidence

Docker was available in the elevated runtime check.

Command:

```bash
python -B scripts/check_player_source_runtime.py out/artifacts/sentinel-aml-player-source.tar.gz --json-report out/artifacts/player-source-runtime-report.json
```

Result:

```json
{
  "status": "pass",
  "docker_available": true,
  "docker-compose-config": "pass",
  "docker-compose-build": "pass",
  "docker-compose-build_elapsed_seconds": 24.407,
  "docker-compose-up": "pass",
  "docker-compose-up_elapsed_seconds": 8.234,
  "cleanup": "pass"
}
```

Endpoints tested:

- API health: `/healthz`
- API readiness: `/readyz`
- UI index: `/`
- UI proxied health: `/healthz`

Cleanup completed with `docker compose down --remove-orphans -v` and removed the stack containers, network, and PostgreSQL volume.

## CTF Invariants

The change is limited to generated player-source packaging/runtime material and validation scripts. It does not change product logic, checker logic, sploits, fixes, migrations, authorization behavior, or the intended runtime behavior delivered in the source package.

## Security Invariants

The compose-local PostgreSQL service is not exposed on a host port. Packaged credentials are local runtime defaults only and are documented as unsuitable for non-isolated use. No debug or admin endpoint was added, and the runtime files do not call organizer-only checker/sploit/fix material.
