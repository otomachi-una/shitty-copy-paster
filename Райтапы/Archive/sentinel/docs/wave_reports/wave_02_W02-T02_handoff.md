# Wave 02 W02-T02 Handoff — Auth and Session API

## 1. Summary

Implemented normal analyst registration, login, bearer-session authentication, and `/api/auth/me` on top of the Wave 02 auth repository foundation. The API uses explicit DTOs and keeps password hashes, stored token hashes, internal rows, and checker-private markers out of responses.

## 2. Implementation Details

- Added an auth service that hashes passwords with `golang.org/x/crypto/bcrypt`.
- Added secure session token generation with `crypto/rand`.
- Stored only SHA-256 session token hashes through the existing repository contract.
- Defaulted self-registration to the normal `analyst` role.
- Added bearer-token current-user loading and an `internal/authz` principal boundary.
- Added HTTP handlers for `POST /api/auth/register`, `POST /api/auth/login`, and `GET /api/auth/me`.
- Kept `/healthz` and `/readyz` operational-only.
- Wired `cmd/aml-api` to open PostgreSQL, create the auth repository/service, and serve the API routes.

## 3. Files Changed

- `cmd/aml-api/main.go`
- `go.mod`
- `go.sum`
- `internal/auth/service.go`
- `internal/auth/service_test.go`
- `internal/authz/doc.go`
- `internal/authz/principal.go`
- `internal/httpapi/doc.go`
- `internal/httpapi/server.go`
- `internal/httpapi/server_test.go`
- `docs/03_api_contract.md`
- `docs/05_authentication_authorization.md`
- `docs/06_visibility_and_projections.md`
- `docs/12_testing_strategy.md`
- `docs/wave_reports/wave_02_W02-T02_handoff.md`
- `docs/14_agent_execution_log.md`

## 4. Tests Added

- Auth service tests for analyst default role, bcrypt password verification, token-hash storage, wrong-password rejection, and unknown-token fail-closed behavior.
- Auth HTTP tests for successful register, duplicate username rejection, successful login, wrong password rejection, unauthenticated `/api/auth/me`, authenticated `/api/auth/me`, sensitive response exclusion, and absence of debug/admin endpoints.

## 5. Tests Run

- `go get golang.org/x/crypto/bcrypt` initially failed under restricted network access, then succeeded with approved escalation.
- `go mod tidy` initially failed because the default Windows Go build cache returned access denied errors; rerun with `GOCACHE` pointed at the temp directory and completed successfully.
- `go test ./...` initially exposed a production constructor mismatch for `auth.NewRepository(*sql.DB)`; fixed with a SQL adapter and reran successfully.
- `go test ./...` completed successfully.
- `go vet ./...` completed successfully.
- `python3 -B -m unittest discover -s tests -p "test_*.py"` was attempted but the Windows `python3` alias only printed `Python` and exited with code 1.
- `python -B -m unittest discover -s tests -p "test_*.py"` completed successfully with 15 tests.
- `python -B scripts/check_wave01_scope.py` completed successfully and reported overall status `pass`.
- `python -B scripts/check_docs_tree.py` completed successfully and reported overall status `pass`.

## 6. Documentation Updated

- Updated API contract with auth request/response DTOs and stable error semantics.
- Updated authentication/authorization docs with bearer-token middleware behavior, bcrypt hashing, token hashing, session expiry, and default role.
- Updated visibility/projection docs with explicit auth response field boundaries.
- Updated testing strategy with auth service and HTTP API gates.

## 7. CTF Invariants Checked

- Future checker traffic uses the same normal auth endpoints.
- No checker-only auth path was added.
- No public attack data was introduced.
- No private flag identifier format was introduced.
- No flag stores were introduced.
- No planned vulnerabilities or reference exploits were implemented.

## 8. Security Invariants Checked

- Password hashes and stored token hashes are not serialized in response DTOs.
- Raw session tokens are returned only when a session is created by register or login.
- Auth middleware fails closed for missing, malformed, unknown, expired, or revoked bearer tokens.
- Protected unauthenticated calls return stable error responses.
- Database models are converted into explicit DTOs before serialization.

## 9. Self-Review

The implementation keeps auth behavior narrow and product-normal. The HTTP tests use a fake auth store because no live PostgreSQL service is available in this environment. The bearer-token and bcrypt decisions are documented in the allowed auth docs; a standalone ADR was intentionally not created because W02-T02 file scope did not include `docs/decisions/`.

## 10. Risks / Open Questions

- Live PostgreSQL auth API integration remains a follow-up for W02-T03 or a later environment with a running database.
- Password policy is intentionally minimal in Wave 02 and may need product hardening later.
- Session revocation endpoint is not exposed yet.

## 11. Ready for Orchestrator Review

Yes.
