# VoltaX Exchange

VoltaX Exchange is a small Ruby HTTP service that models exchange accounts,
wallets, order-book trades, RFQs, partner reports, conditional orders, and a
public market feed.

## Run

Create an environment file from the example values, then start the service:

```sh
cp .env.example .env
docker compose up -d postgres
docker compose run --rm exchange-api ruby bin/migrate
docker compose up -d
```

The API listens on `http://localhost:9292`.

Useful checks:

```sh
curl -fsS http://localhost:9292/health
curl -fsS http://localhost:9292/ready
```

The matching and market workers run as deterministic background services by
default. For a single maintenance tick, use:

```sh
docker compose run --rm matching-engine matching-engine once
docker compose run --rm market-simulator market-simulator once
```

PostgreSQL is only reachable inside the Compose network by default.
