# Sentinel AML Player Source

Sentinel AML is a compact anti-money-laundering investigation service for analyst teams. It provides user accounts, customer and account records, transaction intake, alert review, case work, due-diligence records, relationship review, shared review rooms, and case exports.

This package contains backend service source, database migrations, vendored Go modules, a prebuilt static frontend bundle, Docker Compose runtime, and local commands needed to inspect, change, rebuild, and run the application.

## Requirements

- Docker with Compose support.
- Ports `8080` and `8081` available on your workstation, or custom ports set in `.env`.
- A shell with `make` for the helper commands.
- Go 1.22 only when running backend builds outside Docker.

## Start

From the package root:

```sh
docker compose up --build
```

The frontend is available at `http://127.0.0.1:8081`.

The API is available at `http://127.0.0.1:8080`.

Health endpoints:

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

The same startup flow is available through:

```sh
make up
```

## Rebuild After Changes

After changing Go or migration files, rebuild the containers:

```sh
make rebuild
make up
```

For a one-command fresh container build:

```sh
docker compose up --build
```

## Logs

Follow recent service logs:

```sh
make logs
```

Useful focused views:

```sh
docker compose logs aml-api
docker compose logs aml-worker
docker compose logs aml-ui
docker compose logs postgres
```

## Reset Local Data

To stop the stack and remove the local database volume:

```sh
make down
```

Then start again:

```sh
make up
```

This removes local records created in the Compose database. Keep a separate backup if you need to preserve investigation data.

## Environment

Copy the example environment file when you want custom host ports:

```sh
cp deploy/player.env.example .env
```

Common values:

- `SENTINEL_AML_API_PORT`: host port for the API, default `8080`.
- `SENTINEL_AML_HTTP_PORT`: host port for the frontend, default `8081`.
- `DATABASE_URL`: database connection used inside the Compose network.

The packaged defaults are for local event operation. Review network exposure and storage policy before using the service in any broader environment.

## Local Checks

Run the public smoke probe against a running stack:

```sh
make smoke
```

The smoke probe checks API liveness, API readiness, and frontend load using ordinary HTTP requests and non-sensitive content checks.

## Basic Troubleshooting

If startup fails, check that Docker is running and that ports `8080` and `8081` are free.

If readiness fails, inspect PostgreSQL logs and confirm migrations completed.

If the frontend loads but API calls fail, confirm the API container is healthy and the frontend gateway can reach it through Compose.

The UI is shipped as built static assets under `web/dist`; participant patches are expected to target the backend source and migrations in this package.

If backend changes are not visible, rebuild containers with `make rebuild` and start again.
