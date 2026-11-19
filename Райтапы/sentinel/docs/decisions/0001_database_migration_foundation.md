# ADR 0001: Database Migration Foundation

## Status

Accepted for Wave 02.

## Context

Wave 02 needs PostgreSQL migration and auth persistence foundations without introducing AML domain schema or checker behavior. The source requires session token hashes but does not prescribe the column name or migration library.

## Decision

Use a small standard-library migration runner in `internal/db` for the initial foundation and name the session credential column `token_hash`.

Migrations live under `migrations/` as ordered SQL files. Applied versions are recorded in `schema_migrations`.

## Consequences

- No external migration dependency is needed for Wave 02.
- The SQL remains PostgreSQL-specific and must not be treated as SQLite-compatible product behavior.
- Future waves may replace or extend the runner only with an ADR-backed migration plan.
- Session records store token hashes only; raw session tokens must never be stored.
