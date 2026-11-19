GO ?= go
COMPOSE ?= docker compose
PYTHON ?= python

.PHONY: test build up down logs rebuild smoke

test:
	GOTOOLCHAIN=local $(GO) test -mod=vendor ./...

build:
	GOTOOLCHAIN=local $(GO) build -mod=vendor ./cmd/aml-api ./cmd/aml-worker ./cmd/aml-migrate

up:
	$(COMPOSE) up --build

down:
	$(COMPOSE) down --remove-orphans -v

logs:
	$(COMPOSE) logs --tail=200 -f

rebuild:
	$(COMPOSE) build --no-cache

smoke:
	$(PYTHON) tests/public_smoke/public_smoke.py --api-url http://127.0.0.1:$${SENTINEL_AML_API_PORT:-8080} --ui-url http://127.0.0.1:$${SENTINEL_AML_HTTP_PORT:-8081}
