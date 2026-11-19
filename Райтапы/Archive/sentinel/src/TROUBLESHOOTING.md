# Sentinel AML Troubleshooting

Use this guide when the local stack does not start, health probes fail, or normal AML workflows do not persist data.

## Docker Is Not Ready

Confirm Docker is running:

```sh
docker compose version
docker info
```

Then verify the Compose file:

```sh
docker compose config
```

Run all commands from the package root so Docker can use the local source tree as its build context.

## Ports Are Busy

The default host ports are:

- frontend: `8081`
- API: `8080`

Choose alternate ports in `.env`:

```sh
SENTINEL_AML_HTTP_PORT=18081
SENTINEL_AML_API_PORT=18080
```

Restart the stack after changing port values.

## API Health Fails

Check the API container:

```sh
docker compose ps
docker compose logs aml-api
```

The liveness endpoint is:

```sh
curl http://127.0.0.1:8080/healthz
```

If the API process exits, rebuild and review the startup log.

## Readiness Fails

The readiness endpoint depends on the database:

```sh
curl http://127.0.0.1:8080/readyz
```

Inspect database and migration services:

```sh
docker compose logs postgres
docker compose logs aml-migrate
```

A fresh local reset usually clears partial setup state:

```sh
make down
make up
```

## Frontend Does Not Load

Check the frontend container and gateway:

```sh
docker compose logs aml-ui
curl http://127.0.0.1:8081/
curl http://127.0.0.1:8081/healthz
```

If the page is stale after backend changes, rebuild the image:

```sh
make rebuild
make up
```

## Data Disappears

`make down` removes the local database volume. Use plain Docker Compose stop commands when you want to preserve local records between restarts.

## Builds Are Slow

The first build downloads container images and compiles the Go services from vendored modules. The UI is already included as static files, so player builds do not install frontend packages.

## Public Smoke Probe

With the stack running:

```sh
make smoke
```

The probe checks only public liveness/readiness and frontend loading. It does not create or modify business records.
